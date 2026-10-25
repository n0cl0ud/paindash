package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// hash is a fast (cost 4) bcrypt hash, for tests only.
func hash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func writeAccounts(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "users")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// edit rewrites the accounts file, with a modification time the next check
// sees as new.
func edit(t *testing.T, path string, clk *clock, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(11 * time.Second) // the file is checked every 10 s
	if err := os.Chtimes(path, clk.t, clk.t); err != nil {
		t.Fatal(err)
	}
}

const site = "https://paindash.example.com"

// localSite serves the echo app behind local accounts, with a settable clock.
func localSite(t *testing.T, accounts string, policy Policy) (*Sessions, *clock, string) {
	t.Helper()
	path := writeAccounts(t, accounts)
	a, err := NewLocal(path, SessionConfig{Key: testKey(), PublicURL: site, Policy: policy, Log: testLog})
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{time.Now()}
	a.now, a.local.now, a.local.limiter.now = c.now, c.now, c.now
	a.local.checked = c.t
	return a, c, path
}

func signIn(b *browser, name, password, rd string) *http.Response {
	return b.do(http.MethodPost, "/auth/login", url.Values{"email": {name}, "password": {password}, "rd": {rd}})
}

func TestLocalSignIn(t *testing.T) {
	accounts := "# comment\n\nalice@example.com:" + hash(t, "correct horse battery") + ":sec,dev\n" +
		"Bob:" + hash(t, "staple battery horse") + "\n"
	a, clk, _ := localSite(t, accounts, Policy{Editors: []string{"sec"}})
	b := newBrowser(a.Middleware(echo), site)

	res := signIn(b, "alice@example.com", "wrong password", "/vulns")
	if s := body(res); res.StatusCode != http.StatusUnauthorized || !strings.Contains(s, "Wrong email or password") || !strings.Contains(s, `value="alice@example.com"`) {
		t.Errorf("wrong password: %d", res.StatusCode)
	}
	for _, password := range []string{"correct horse battery", dummyPassword} {
		if res := signIn(b, "nobody@example.com", password, "/"); res.StatusCode != http.StatusUnauthorized {
			t.Errorf("unknown account, %q: %d", password, res.StatusCode)
		}
	}
	if b.user(t) != nil {
		t.Fatal("signed in after failures")
	}

	res = signIn(b, "alice@example.com", "correct horse battery", "/vulns?env=prod")
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/vulns?env=prod" {
		t.Fatalf("sign-in: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	c := b.cookies["__Host-paindash_session"]
	if c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("session cookie: %+v", c)
	}
	u := b.user(t)
	if u == nil || u.Email != "alice@example.com" || !u.CanEdit || strings.Join(u.Groups, ",") != "sec,dev" {
		t.Errorf("alice: %+v", u)
	}
	if s := opened(t, a, b); s.Method != methodPassword || s.SignedIn != clk.t.Unix() || s.Expires != clk.t.Add(12*time.Hour).Unix() {
		t.Errorf("session: %+v", s)
	}

	// Names are case-insensitive; Bob has no editor group: read-only.
	bob := newBrowser(a.Middleware(echo), site)
	signIn(bob, "bob", "staple battery horse", "/")
	if u := bob.user(t); u == nil || u.Email != "Bob" || u.CanEdit {
		t.Errorf("bob: %+v", u)
	}
}

func TestLocalRedirectStaysOnSite(t *testing.T) {
	a, _, _ := localSite(t, "alice:"+hash(t, "correct horse battery")+"\n", Policy{})
	b := newBrowser(a.Middleware(echo), site)
	for _, rd := range []string{"//evil.example", "https://evil.example", "/\\evil.example"} {
		delete(b.cookies, "__Host-paindash_session")
		if res := signIn(b, "alice", "correct horse battery", rd); res.Header.Get("Location") != "/" {
			t.Errorf("rd %q: went to %q", rd, res.Header.Get("Location"))
		}
	}
}

func TestLocalCrossSite(t *testing.T) {
	a, _, _ := localSite(t, "alice:"+hash(t, "correct horse battery")+"\n", Policy{})
	h := a.Middleware(echo)
	for _, hdr := range []map[string]string{
		{"Origin": "https://evil.example"},
		{"Sec-Fetch-Site": "cross-site"},
		{"Origin": "http://paindash.example.com"}, // not the public origin
	} {
		for _, path := range []string{"/auth/login", "/auth/logout"} {
			b := newBrowser(h, "")
			res := b.post(path, url.Values{"email": {"alice"}, "password": {"correct horse battery"}, "rd": {"/"}}, hdr)
			if res.StatusCode != http.StatusForbidden || len(b.cookies) > 0 {
				t.Errorf("%s with %v: %d, cookies %v", path, hdr, res.StatusCode, b.cookies)
			}
		}
	}
}

func TestLocalLimiter(t *testing.T) {
	accounts := "alice:" + hash(t, "correct horse battery") + "\n"
	for i := range globalFails {
		accounts += fmt.Sprintf("user%d:%s\n", i, hash(t, "unguessable passphrase"))
	}
	a, clk, _ := localSite(t, accounts, Policy{})
	b := newBrowser(a.Middleware(echo), site)
	for i := range accountFails {
		if res := signIn(b, "alice", fmt.Sprint("guess ", i), "/"); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, res.StatusCode)
		}
	}
	// Blocked, even with the right password, until the first failure is 15 minutes old.
	res := signIn(b, "ALICE", "correct horse battery", "/")
	if s := body(res); res.StatusCode != http.StatusTooManyRequests || !strings.Contains(s, "Try again in 15 minute") {
		t.Fatalf("blocked: %d", res.StatusCode)
	}
	clk.t = clk.t.Add(accountWindow)
	if res := signIn(b, "alice", "correct horse battery", "/"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("after the window: %d", res.StatusCode)
	}

	// Password spraying: failures across accounts block everyone for a minute.
	for i := range globalFails {
		signIn(newBrowser(a.Middleware(echo), site), fmt.Sprint("user", i), "guess", "/")
	}
	if res := signIn(newBrowser(a.Middleware(echo), site), "alice", "correct horse battery", "/"); res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("global limit: %d", res.StatusCode)
	}
	clk.t = clk.t.Add(globalWindow)
	if res := signIn(newBrowser(a.Middleware(echo), site), "alice", "correct horse battery", "/"); res.StatusCode != http.StatusSeeOther {
		t.Errorf("after the global window: %d", res.StatusCode)
	}
}

// The accounts file is read again when it changes: a new password or a
// removed account ends the sessions at once.
func TestLocalReload(t *testing.T) {
	alice, bob := "alice:"+hash(t, "correct horse battery")+":sec\n", "bob:"+hash(t, "staple battery horse")+"\n"
	a, clk, path := localSite(t, alice+bob, Policy{})
	ba, bb := newBrowser(a.Middleware(echo), site), newBrowser(a.Middleware(echo), site)
	signIn(ba, "alice", "correct horse battery", "/")
	signIn(bb, "bob", "staple battery horse", "/")
	if ba.user(t) == nil || bb.user(t) == nil {
		t.Fatal("not signed in")
	}

	// Alice gets a new password, Bob is removed, Carol is added.
	carol := "carol:" + hash(t, "a new passphrase here") + "\n"
	edit(t, path, clk, "alice:"+hash(t, "another long password")+":sec\n"+carol)
	if ba.user(t) != nil || bb.user(t) != nil {
		t.Error("sessions survived a new password and a removed account")
	}
	if res := signIn(ba, "alice", "another long password", "/"); res.StatusCode != http.StatusSeeOther {
		t.Errorf("new password: %d", res.StatusCode)
	}
	if res := signIn(newBrowser(a.Middleware(echo), site), "carol", "a new passphrase here", "/"); res.StatusCode != http.StatusSeeOther {
		t.Errorf("new account: %d", res.StatusCode)
	}

	// A broken file keeps the previous accounts.
	edit(t, path, clk, "garbage\n")
	if ba.user(t) == nil {
		t.Error("a broken file signed alice out")
	}
}

// A * in front of a hash, or in place of it, locks an account: its sessions
// end and its sign-ins fail as a wrong password does, in as much time, until
// the * is removed.
func TestLocalLock(t *testing.T) {
	alice := "alice:" + hash(t, "correct horse battery") + ":sec\n"
	a, clk, path := localSite(t, alice+"carol:*\n", Policy{})
	b := newBrowser(a.Middleware(echo), site)
	signIn(b, "alice", "correct horse battery", "/")
	if b.user(t) == nil {
		t.Fatal("not signed in")
	}

	var warned []string
	a.local.warn = func(msg string, _ ...any) { warned = append(warned, msg) }
	compared, orig := 0, dummy
	dummy = func() []byte { compared++; return orig() }
	t.Cleanup(func() { dummy = orig })

	edit(t, path, clk, strings.Replace(alice, ":", ":*", 1)+"carol:*\n")
	if b.user(t) != nil {
		t.Error("a locked account kept its session")
	}
	if len(warned) > 0 {
		t.Errorf("warnings on locked accounts: %v", warned)
	}
	for _, name := range []string{"alice", "carol"} {
		for _, password := range []string{"correct horse battery", dummyPassword} {
			res := signIn(b, name, password, "/")
			if s := body(res); res.StatusCode != http.StatusUnauthorized || !strings.Contains(s, "Wrong email or password") {
				t.Errorf("%s, locked, %q: %d", name, password, res.StatusCode)
			}
		}
	}
	if compared != 4 {
		t.Errorf("locked accounts compared against the dummy hash %d times, want 4", compared)
	}

	edit(t, path, clk, alice+"carol:*\n")
	if res := signIn(b, "alice", "correct horse battery", "/"); res.StatusCode != http.StatusSeeOther || b.user(t) == nil {
		t.Errorf("unlocked: %d", res.StatusCode)
	}
}

func TestLocalPolicyAndExpiry(t *testing.T) {
	accounts := "alice:" + hash(t, "correct horse battery") + ":viewers\n" + "mallory:" + hash(t, "staple battery horse") + ":other\n"
	a, clk, _ := localSite(t, accounts, Policy{Allowed: []string{"viewers"}})
	b := newBrowser(a.Middleware(echo), site)
	if res := signIn(b, "mallory", "staple battery horse", "/"); res.StatusCode != http.StatusForbidden || len(b.cookies) > 0 {
		t.Errorf("not in an allowed group: %d, cookies %v", res.StatusCode, b.cookies)
	}
	signIn(b, "alice", "correct horse battery", "/")
	if b.user(t) == nil {
		t.Fatal("alice not signed in")
	}
	clk.t = clk.t.Add(12*time.Hour - time.Second)
	if b.user(t) == nil {
		t.Error("session ended before its 12 h")
	}
	clk.t = clk.t.Add(time.Second)
	if b.user(t) != nil {
		t.Error("session outlived its 12 h")
	}
}

func TestSignOut(t *testing.T) {
	a, _, _ := localSite(t, "alice:"+hash(t, "correct horse battery")+"\n", Policy{})
	b := newBrowser(a.Middleware(echo), site)
	signIn(b, "alice", "correct horse battery", "/")
	stolen := *b.cookies["__Host-paindash_session"]
	res := b.do(http.MethodPost, "/auth/logout", url.Values{})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/auth/signed-out" || b.user(t) != nil {
		t.Errorf("sign-out: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if s := body(b.do(http.MethodGet, "/auth/signed-out", nil)); !strings.Contains(s, "signed out") {
		t.Error("signed-out page")
	}
	// Sessions are not stored server-side: a copied cookie stays valid until
	// its expiry (documented). Pinned here so that a change of design shows up.
	b.cookies["__Host-paindash_session"] = &stolen
	if b.user(t) == nil {
		t.Error("a copied cookie stopped working after sign-out: update docs/architecture.md")
	}
}

// A session opened in one mode is worthless in the other, with the same key:
// switching modes signs everyone out.
func TestSessionModes(t *testing.T) {
	a, _, _ := localSite(t, "alice:"+hash(t, "correct horse battery")+"\n", Policy{})
	b := newBrowser(a.Middleware(echo), site)
	signIn(b, "alice", "correct horse battery", "/")
	if b.user(t) == nil {
		t.Fatal("not signed in")
	}
	o, err := NewOIDC(context.Background(), OIDCConfig{Issuer: "http://127.0.0.1:1", ClientID: "paindash"},
		SessionConfig{Key: testKey(), PublicURL: site, Log: testLog})
	if err != nil {
		t.Fatal(err)
	}
	b.h = o.Middleware(echo)
	if u := b.user(t); u != nil {
		t.Errorf("a local session works in oidc mode: %+v", u)
	}
}

func TestParseAccounts(t *testing.T) {
	h := hash(t, "correct horse battery")
	for _, bad := range []string{
		"alice\n",
		":" + h + "\n",
		"alice:\n",
		"alice:not-a-hash\n",
		"alice:" + h + "\nALICE:" + h + "\n",
	} {
		if _, err := parseAccounts([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	accs, err := parseAccounts([]byte("alice:" + h + ": sec , ,dev\n"))
	if err != nil || strings.Join(accs["alice"].groups, ",") != "sec,dev" || accs["alice"].locked() {
		t.Errorf("groups: %v %v", accs, err)
	}
	// * in place of the hash, or in front of it: a locked account.
	accs, err = parseAccounts([]byte("alice:*\nbob:*" + h + ":sec\n"))
	if err != nil || !accs["alice"].locked() || !accs["bob"].locked() || strings.Join(accs["bob"].groups, ",") != "sec" {
		t.Errorf("locked accounts: %v %v", accs, err)
	}
	// htpasswd -nbB writes $2y$ hashes.
	y := "$2y$" + strings.TrimPrefix(h, "$2a$")
	accs, err = parseAccounts([]byte("alice:" + y + "\n"))
	if err != nil || bcrypt.CompareHashAndPassword(accs["alice"].hash, []byte("correct horse battery")) != nil {
		t.Errorf("$2y$ hash: %v", err)
	}
}

func TestHashPassword(t *testing.T) {
	if _, err := HashPassword("too short"); err == nil {
		t.Error("short password accepted")
	}
	if _, err := HashPassword(strings.Repeat("x", 73)); err == nil {
		t.Error("password beyond 72 bytes accepted")
	}
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := bcrypt.Cost([]byte(h)); c != HashCost || bcrypt.CompareHashAndPassword([]byte(h), []byte("correct horse battery")) != nil {
		t.Errorf("hash %s", h)
	}
}
