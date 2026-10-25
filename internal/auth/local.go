package auth

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// HashCost is the bcrypt cost of paindash hash-password (about 250 ms).
const HashCost = 12

// HashPassword returns the bcrypt hash of a password, for the accounts file.
func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("use a password of 12 characters or more, e.g. a passphrase")
	}
	if len(password) > 72 {
		return "", errors.New("bcrypt reads 72 bytes at most: use a shorter password")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), HashCost)
	return string(h), err
}

type account struct {
	name   string
	hash   []byte
	groups []string
}

// localLogin checks passwords against the accounts file: one account per line,
// name:bcrypt-hash[:group,group...], the format of htpasswd -B. The file is
// read again when it changes (a mounted Secret is updated in place), so
// accounts are added, removed or changed without a restart.
type localLogin struct {
	path    string
	limiter *limiter
	sem     chan struct{} // bcrypt is slow on purpose: bounds the CPU spent on attempts

	mu       sync.Mutex
	accounts map[string]account // by lowercase name
	modTime  time.Time
	checked  time.Time
	now      func() time.Time
	warn     func(msg string, args ...any)
}

// NewLocal returns sessions opened by a password check against the accounts
// file. It fails on an unreadable file or a malformed line.
func NewLocal(usersFile string, sc SessionConfig) (*Sessions, error) {
	if usersFile == "" {
		return nil, errors.New("PAINDASH_USERS_FILE is required: the accounts file (name:bcrypt-hash[:groups] lines)")
	}
	a, err := newSessions(sc)
	if err != nil {
		return nil, err
	}
	l := &localLogin{path: usersFile, limiter: newLimiter(), sem: make(chan struct{}, 4), now: time.Now, warn: a.log.Warn}
	if err := l.reload(); err != nil {
		return nil, err
	}
	a.kind, a.local = "local", l
	go dummy() // so that the first unknown account is not slower than the others
	return a, nil
}

// loginPost answers the sign-in form.
func (a *Sessions) loginPost(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		a.render(w, http.StatusForbidden, page{Title: "Sign-in refused", Message: "The request did not come from paindash.", Link: "/auth/login", LinkText: "Sign in"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		a.render(w, http.StatusBadRequest, page{Title: "Sign in", Form: true, RD: "/", Error: "The form could not be read."})
		return
	}
	name, rd := strings.TrimSpace(r.PostForm.Get("email")), localPath(r.PostForm.Get("rd"))
	form := page{Title: "Sign in", Form: true, RD: rd, Email: name}
	if wait := a.local.limiter.wait(name); wait > 0 {
		form.Error = fmt.Sprintf("Too many failed attempts. Try again in %d minute(s).", int(math.Ceil(wait.Minutes())))
		a.render(w, http.StatusTooManyRequests, form)
		return
	}
	acc, found, ok := a.local.check(name, r.PostForm.Get("password"))
	if !ok {
		a.local.limiter.fail(name)
		if found {
			a.log.Warn("sign-in failed: wrong password", "user", acc.name)
		} else {
			// Not logged: often a password typed in the wrong field.
			a.log.Warn("sign-in failed: unknown account")
		}
		form.Error = "Wrong email or password."
		a.render(w, http.StatusUnauthorized, form)
		return
	}
	a.local.limiter.reset(name)
	a.signIn(w, r, session{Email: acc.name, Groups: acc.groups, Check: fingerprint(acc.hash), Method: methodPassword}, rd)
}

// dummy is compared when the account does not exist, so that the answer takes
// as long as for a wrong password and does not reveal which accounts exist.
var dummy = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("paindash: no such account"), HashCost)
	return h
})

func (l *localLogin) check(name, password string) (acc account, found, ok bool) {
	acc, found = l.account(name)
	hash := acc.hash
	if !found {
		hash = dummy()
	}
	l.sem <- struct{}{}
	err := bcrypt.CompareHashAndPassword(hash, []byte(password))
	<-l.sem
	return acc, found, found && err == nil
}

// account looks a name up, after reading the file again if it changed (at
// most every 10 s).
func (l *localLogin) account(name string) (account, bool) {
	l.mu.Lock()
	if l.now().Sub(l.checked) >= 10*time.Second {
		l.checked = l.now()
		if st, err := os.Stat(l.path); err == nil && !st.ModTime().Equal(l.modTime) {
			if err := l.reloadLocked(); err != nil {
				l.warn("accounts file not reloaded, previous accounts kept", "file", l.path, "err", err)
			}
		}
	}
	acc, ok := l.accounts[strings.ToLower(name)]
	l.mu.Unlock()
	return acc, ok
}

func (l *localLogin) reload() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.checked = l.now()
	return l.reloadLocked()
}

func (l *localLogin) reloadLocked() error {
	st, err := os.Stat(l.path)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(l.path)
	if err != nil {
		return err
	}
	accounts, err := parseAccounts(b)
	if err != nil {
		return fmt.Errorf("%s: %w", l.path, err)
	}
	for _, a := range accounts {
		if c, _ := bcrypt.Cost(a.hash); c < 10 {
			l.warn("weak password hash: bcrypt cost below 10, hash it again with paindash hash-password", "user", a.name, "cost", c)
		}
	}
	l.accounts, l.modTime = accounts, st.ModTime()
	return nil
}

func parseAccounts(b []byte) (map[string]account, error) {
	out := map[string]account{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 || parts[0] == "" {
			return nil, fmt.Errorf("line %d: want name:bcrypt-hash[:group,...]", n)
		}
		hash := []byte(parts[1])
		if _, err := bcrypt.Cost(hash); err != nil {
			return nil, fmt.Errorf("line %d: not a bcrypt hash (paindash hash-password, or htpasswd -nB)", n)
		}
		acc := account{name: parts[0], hash: hash}
		if len(parts) == 3 {
			for _, g := range strings.Split(parts[2], ",") {
				if g = strings.TrimSpace(g); g != "" {
					acc.groups = append(acc.groups, g)
				}
			}
		}
		key := strings.ToLower(acc.name)
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("line %d: %s is listed twice", n, acc.name)
		}
		out[key] = acc
	}
	return out, sc.Err()
}

// fingerprint ties a session to the password hash it was opened with: a new
// password signs the account out everywhere.
func fingerprint(hash []byte) string {
	sum := sha256.Sum256(hash)
	return hex.EncodeToString(sum[:8])
}

// limiter slows password guessing: after 5 failures within 15 minutes, an
// account is refused until the oldest failure is 15 minutes old; after 30
// failures within a minute, across all accounts (password spraying), every
// account is refused for that minute. Kept in memory: one replica.
type limiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
	all   []time.Time
	now   func() time.Time
}

const (
	accountFails  = 5
	accountWindow = 15 * time.Minute
	globalFails   = 30
	globalWindow  = time.Minute
)

func newLimiter() *limiter {
	return &limiter{fails: map[string][]time.Time{}, now: time.Now}
}

// wait returns how long sign-ins of name are refused, 0 if they are not.
func (l *limiter) wait(name string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.all = recent(l.all, now, globalWindow)
	if len(l.all) >= globalFails {
		return l.all[0].Add(globalWindow).Sub(now)
	}
	key := strings.ToLower(name)
	f := recent(l.fails[key], now, accountWindow)
	if len(f) >= accountFails {
		return f[0].Add(accountWindow).Sub(now)
	}
	return 0
}

func (l *limiter) fail(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := strings.ToLower(name)
	l.fails[key] = append(recent(l.fails[key], now, accountWindow), now)
	l.all = append(l.all, now)
	// Names are chosen by whoever tries: drop the ones without recent
	// failures (the global limit caps how many can be recent).
	if len(l.fails) > 1000 {
		for k, f := range l.fails {
			if len(recent(f, now, accountWindow)) == 0 {
				delete(l.fails, k)
			}
		}
	}
}

func (l *limiter) reset(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, strings.ToLower(name))
}

// recent keeps the times of ts within window before now (ts is sorted).
func recent(ts []time.Time, now time.Time, window time.Duration) []time.Time {
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= window {
		i++
	}
	return ts[i:]
}
