package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
)

// Cookie names, prefixed with __Host- over HTTPS (host-only, Secure, Path=/).
const (
	sessionCookie = "paindash_session"
	loginCookie   = "paindash_login" // OpenID Connect state, nonce and PKCE verifier, for 10 minutes
)

// SessionConfig is shared by the oidc and local modes.
type SessionConfig struct {
	// Key seals the cookies (AES-256-GCM, 32 bytes): store.Secret keeps it
	// across restarts, so that a restart signs nobody out.
	Key []byte
	// PublicURL is the URL browsers use, e.g. https://paindash.example.com:
	// the OpenID Connect redirect URI, the origin form posts must come from,
	// and Secure cookies when it is https.
	PublicURL string
	TTL       time.Duration // session lifetime, from sign-in (default 12h)
	Policy    Policy
	Log       *slog.Logger
}

// Sessions signs users in and keeps them in an encrypted cookie: no
// server-side store, nothing to clean up. A session ends at its expiry or on
// sign-out; local accounts are checked again on every request.
type Sessions struct {
	ttl    time.Duration
	policy Policy
	log    *slog.Logger
	aead   cipher.AEAD
	origin string // scheme://host[:port] of PublicURL
	secure bool
	public string // PublicURL without trailing slash
	kind   string // "oidc" or "local": a session of one mode is worthless in the other
	oidc   *oidcLogin
	local  *localLogin
	now    func() time.Time
}

type session struct {
	Email   string   `json:"e"`
	Groups  []string `json:"g,omitempty"`
	Expires int64    `json:"x"`
	Check   string   `json:"c,omitempty"` // local: fingerprint of the account's hash field
	// How and when the user signed in, for actions that will want a recent
	// sign-in, such as enrolling a passkey (ROADMAP).
	Method   string `json:"m,omitempty"`
	SignedIn int64  `json:"t,omitempty"`
}

// Sign-in methods recorded in sessions.
const (
	methodPassword = "password"
	methodOIDC     = "oidc"
)

func newSessions(c SessionConfig) (*Sessions, error) {
	if len(c.Key) != 32 {
		return nil, errors.New("session key: want 32 bytes")
	}
	u, err := url.Parse(strings.TrimRight(c.PublicURL, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != "" {
		return nil, fmt.Errorf("PAINDASH_PUBLIC_URL %q: want the URL browsers use, e.g. https://paindash.example.com", c.PublicURL)
	}
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if c.TTL <= 0 {
		c.TTL = 12 * time.Hour
	}
	if u.Scheme == "http" && !loopback(u.Hostname()) && c.Log != nil {
		c.Log.Warn("PAINDASH_PUBLIC_URL is plain http: passwords and session cookies travel unencrypted; use https outside a local test", "url", u.String())
	}
	return &Sessions{
		ttl: c.TTL, policy: c.Policy, log: c.Log, aead: aead,
		origin: u.Scheme + "://" + u.Host, secure: u.Scheme == "https", public: u.String(),
		now: time.Now,
	}, nil
}

// Middleware serves the /auth/ pages and lets the rest through to signed-in
// users only. Pages send others to the sign-in; API calls get a 401, which
// the UI answers with a reload.
func (a *Sessions) Middleware(next http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", a.login)
	mux.HandleFunc("POST /auth/logout", a.logout)
	mux.HandleFunc("GET /auth/signed-out", a.signedOut)
	if a.oidc != nil {
		mux.HandleFunc("GET /auth/callback", a.callback)
	}
	if a.local != nil {
		mux.HandleFunc("POST /auth/login", a.loginPost)
	}
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := a.current(r); u != nil {
			next.ServeHTTP(w, r.WithContext(withUser(r.Context(), u)))
			return
		}
		if r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/api/") {
			http.Redirect(w, r, "/auth/login?rd="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"sign-in required"}` + "\n"))
	}))
	return mux
}

// current returns the user of a valid session cookie, nil otherwise.
func (a *Sessions) current(r *http.Request) *model.User {
	c, err := r.Cookie(a.cookieName(sessionCookie))
	if err != nil {
		return nil
	}
	var s session
	if !a.open(c.Value, a.sessionPurpose(), &s) || a.now().Unix() >= s.Expires {
		return nil
	}
	groups := s.Groups
	if a.local != nil {
		// Removed, or its password changed: signed out.
		acc, ok := a.local.account(s.Email)
		if !ok || fingerprint(acc.hash) != s.Check {
			return nil
		}
		groups = acc.groups
	}
	if !a.policy.allows(groups) {
		return nil
	}
	return a.policy.user(s.Email, groups)
}

// signIn opens the session of an authenticated user and goes back to rd.
func (a *Sessions) signIn(w http.ResponseWriter, r *http.Request, s session, rd string) {
	if !a.policy.allows(s.Groups) {
		a.log.Warn("sign-in refused: in none of the allowed groups", "user", s.Email)
		a.render(w, http.StatusForbidden, page{Title: "Access denied", Message: "Your account is not allowed in paindash. Ask an administrator to add you to an allowed group."})
		return
	}
	if a.local != nil {
		s.Groups = nil // read from the accounts file on every request
	}
	now := a.now()
	s.Groups, s.SignedIn, s.Expires = a.policy.relevant(s.Groups), now.Unix(), now.Add(a.ttl).Unix()
	v, err := a.seal(s, a.sessionPurpose())
	if err != nil {
		a.fail(w, err)
		return
	}
	a.setCookie(w, sessionCookie, v, a.ttl)
	a.log.Info("signed in", "user", s.Email)
	http.Redirect(w, r, rd, http.StatusSeeOther)
}

// login answers GET /auth/login: the form of local accounts, or the identity
// provider of OpenID Connect.
func (a *Sessions) login(w http.ResponseWriter, r *http.Request) {
	rd := localPath(r.URL.Query().Get("rd"))
	if a.current(r) != nil {
		http.Redirect(w, r, rd, http.StatusSeeOther)
		return
	}
	if a.oidc != nil {
		a.startOIDC(w, r, rd)
		return
	}
	a.render(w, http.StatusOK, page{Title: "Sign in", Form: true, RD: rd})
}

func (a *Sessions) logout(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		a.render(w, http.StatusForbidden, page{Title: "Sign-out refused", Message: "The request did not come from paindash."})
		return
	}
	if c, err := r.Cookie(a.cookieName(sessionCookie)); err == nil {
		var s session
		if a.open(c.Value, a.sessionPurpose(), &s) {
			a.log.Info("signed out", "user", s.Email)
		}
	}
	a.setCookie(w, sessionCookie, "", -1)
	http.Redirect(w, r, "/auth/signed-out", http.StatusSeeOther)
}

func (a *Sessions) signedOut(w http.ResponseWriter, r *http.Request) {
	msg := "You are signed out of paindash."
	if a.oidc != nil {
		msg += " Your identity provider may still have you signed in: signing in again can be immediate."
	}
	a.render(w, http.StatusOK, page{Title: "Signed out", Message: msg, Link: "/auth/login", LinkText: "Sign in again"})
}

// sameOrigin refuses form posts from other sites (login CSRF, forced
// sign-out): browsers send Origin and Sec-Fetch-Site with every form post.
func (a *Sessions) sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	o := r.Header.Get("Origin")
	return o == "" || o == a.origin
}

// localPath keeps a post-login redirect on this site: a path such as
// /vulns?env=prod, never //host, /\host or a URL, which browsers would follow
// elsewhere.
func localPath(rd string) string {
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(rd, "/") ||
		strings.HasPrefix(rd, "//") || strings.HasPrefix(rd, "/auth/") || strings.ContainsFunc(rd, func(c rune) bool { return c == '\\' || c <= ' ' || c == 0x7f }) {
		return "/"
	}
	return rd
}

// loopback: hosts browsers treat as a secure context over plain http.
func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || ip != nil && ip.IsLoopback()
}

func (a *Sessions) sessionPurpose() string { return sessionCookie + "/" + a.kind }

func (a *Sessions) cookieName(base string) string {
	if a.secure {
		return "__Host-" + base
	}
	return base
}

// setCookie sets a cookie for maxAge, or deletes it when maxAge < 0.
func (a *Sessions) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	c := &http.Cookie{
		Name: a.cookieName(name), Value: value, Path: "/",
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	}
	if maxAge < 0 {
		c.MaxAge = -1
	} else {
		c.MaxAge = int(maxAge.Seconds())
	}
	http.SetCookie(w, c)
}

// seal encrypts and authenticates v for the cookie called purpose: a cookie
// cannot be read, forged, or used as another one.
func (a *Sessions) seal(v any, purpose string) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, a.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(a.aead.Seal(nonce, nonce, plain, []byte(purpose))), nil
}

func (a *Sessions) open(sealed, purpose string, v any) bool {
	b, err := base64.RawURLEncoding.DecodeString(sealed)
	n := a.aead.NonceSize()
	if err != nil || len(b) < n {
		return false
	}
	plain, err := a.aead.Open(nil, b[:n], b[n:], []byte(purpose))
	return err == nil && json.Unmarshal(plain, v) == nil
}

func (a *Sessions) fail(w http.ResponseWriter, err error) {
	a.log.Error("auth", "err", err)
	a.render(w, http.StatusInternalServerError, page{Title: "Sign-in failed", Message: "An internal error occurred. Try again in a moment.", Link: "/auth/login", LinkText: "Try again"})
}
