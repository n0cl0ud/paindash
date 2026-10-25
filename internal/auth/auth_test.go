package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
)

var testLog = slog.New(slog.NewTextHandler(io.Discard, nil))

func testKey() []byte { return bytes.Repeat([]byte{7}, 32) }

// echo stands for the UI and the API: it answers with the user it was given.
var echo = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(UserFrom(r.Context()))
})

// clock is a settable time for sessions, accounts and the limiter.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// browser keeps cookies across requests and posts forms the way a browser
// does from a page of origin.
type browser struct {
	h       http.Handler
	origin  string
	cookies map[string]*http.Cookie
}

func newBrowser(h http.Handler, origin string) *browser {
	return &browser{h: h, origin: origin, cookies: map[string]*http.Cookie{}}
}

func newRequest(method, target, form string, hdr map[string]string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(form))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return req
}

func (b *browser) do(method, target string, form url.Values) *http.Response {
	hdr := map[string]string{}
	if method == http.MethodPost {
		hdr["Origin"], hdr["Sec-Fetch-Site"] = b.origin, "same-origin"
	}
	return b.send(newRequest(method, target, form.Encode(), hdr))
}

// post sends a form with exactly the given headers, as from another site.
func (b *browser) post(path string, form url.Values, hdr map[string]string) *http.Response {
	return b.send(newRequest(http.MethodPost, path, form.Encode(), hdr))
}

func (b *browser) send(req *http.Request) *http.Response {
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	res := rec.Result()
	for _, c := range res.Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return res
}

// user returns who the app sees, nil if the request did not reach it.
func (b *browser) user(t *testing.T) *model.User {
	t.Helper()
	res := b.do(http.MethodGet, "/api/meta", nil)
	if res.StatusCode != http.StatusOK {
		return nil
	}
	var u *model.User
	if err := json.NewDecoder(res.Body).Decode(&u); err != nil {
		t.Fatal(err)
	}
	return u
}

func body(res *http.Response) string {
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

func TestPolicy(t *testing.T) {
	p := Policy{Allowed: []string{"sec", "dev"}, Editors: []string{"sec"}}
	for _, tc := range []struct {
		groups          []string
		allowed, editor bool
		relevant        []string
	}{
		{[]string{"sec", "hr"}, true, true, []string{"sec"}},
		{[]string{"dev"}, true, false, []string{"dev"}},
		{[]string{"hr"}, false, false, nil},
		{nil, false, false, nil},
	} {
		if got := p.allows(tc.groups); got != tc.allowed {
			t.Errorf("%v: allows = %v", tc.groups, got)
		}
		if got := p.user("a", tc.groups).CanEdit; got != tc.editor {
			t.Errorf("%v: CanEdit = %v", tc.groups, got)
		}
		if got := p.relevant(tc.groups); !slices.Equal(got, tc.relevant) {
			t.Errorf("%v: relevant = %v", tc.groups, got)
		}
	}
	// No groups configured: everyone is allowed in and may edit.
	if open := (Policy{}); !open.allows(nil) || !open.user("a", nil).CanEdit {
		t.Error("empty policy should let anyone in, as an editor")
	}
}

func TestSeal(t *testing.T) {
	a, err := newSessions(SessionConfig{Key: testKey(), PublicURL: "https://paindash.example.com", Log: testLog})
	if err != nil {
		t.Fatal(err)
	}
	in := session{Email: "alice@example.com", Expires: 42}
	v, err := a.seal(in, sessionCookie)
	if err != nil {
		t.Fatal(err)
	}
	var out session
	if !a.open(v, sessionCookie, &out) || out.Email != in.Email || out.Expires != 42 {
		t.Fatalf("round trip: %+v", out)
	}
	if a.open(v, loginCookie, &out) {
		t.Error("a session cookie must not open as a login cookie")
	}
	b := []byte(v)
	b[len(b)/2] ^= 1
	if a.open(string(b), sessionCookie, &out) {
		t.Error("a tampered cookie must not open")
	}
	other, _ := newSessions(SessionConfig{Key: bytes.Repeat([]byte{8}, 32), PublicURL: "https://paindash.example.com", Log: testLog})
	if other.open(v, sessionCookie, &out) {
		t.Error("another key must not open the cookie")
	}
	for _, bad := range []string{"", "!!", "AAAA"} {
		if a.open(bad, sessionCookie, &out) {
			t.Errorf("%q opened", bad)
		}
	}
}

func TestNewSessionsConfig(t *testing.T) {
	for _, u := range []string{"", "paindash.example.com", "ftp://x", "https://x/sub", "https://"} {
		if _, err := newSessions(SessionConfig{Key: testKey(), PublicURL: u, Log: testLog}); err == nil {
			t.Errorf("PublicURL %q accepted", u)
		}
	}
	if _, err := newSessions(SessionConfig{Key: []byte("short"), PublicURL: "https://x", Log: testLog}); err == nil {
		t.Error("short key accepted")
	}
	a, err := newSessions(SessionConfig{Key: testKey(), PublicURL: "http://localhost:8080/", Log: testLog})
	if err != nil || a.secure || a.origin != "http://localhost:8080" || a.cookieName(sessionCookie) != "paindash_session" {
		t.Fatalf("http: %v %+v", err, a)
	}
	a, _ = newSessions(SessionConfig{Key: testKey(), PublicURL: "https://paindash.example.com", Log: testLog})
	if !a.secure || a.cookieName(sessionCookie) != "__Host-paindash_session" {
		t.Errorf("https: secure %v, cookie %s", a.secure, a.cookieName(sessionCookie))
	}
	// Plain http is for a local test only: elsewhere, a warning at start.
	for u, warned := range map[string]bool{
		"http://paindash.example.com":    true,
		"http://10.0.0.5:8080":           true,
		"https://paindash.example.com":   false,
		"http://localhost:8080":          false,
		"http://127.0.0.1:8080":          false,
		"http://[::1]:8080":              false,
		"http://paindash.localhost:8088": false,
	} {
		var log bytes.Buffer
		if _, err := newSessions(SessionConfig{Key: testKey(), PublicURL: u, Log: slog.New(slog.NewTextHandler(&log, nil))}); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(log.String(), "plain http"); got != warned {
			t.Errorf("%s: warned %v, want %v", u, got, warned)
		}
	}
}

func TestLocalPath(t *testing.T) {
	for in, want := range map[string]string{
		"/vulns?env=prod":       "/vulns?env=prod",
		"/workloads/c/ns/k/n":   "/workloads/c/ns/k/n",
		"/":                     "/",
		"":                      "/",
		"//evil.example":        "/",
		"/\\evil.example":       "/",
		"/\t/evil.example":      "/",
		"https://evil.example/": "/",
		"javascript:alert(1)":   "/",
		"vulns":                 "/",
		"/auth/login?rd=/":      "/",
		"/%2F%2Fevil.example":   "/%2F%2Fevil.example", // a path on this site
	} {
		if got := localPath(in); got != want {
			t.Errorf("localPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// Without a session, pages go to the sign-in and the API answers 401 in
// JSON, which the UI turns into a reload.
func TestRequireSession(t *testing.T) {
	l := writeAccounts(t, "alice@example.com:"+hash(t, "correct horse battery")+"\n")
	a, err := NewLocal(l, SessionConfig{Key: testKey(), PublicURL: "https://paindash.example.com", Log: testLog})
	if err != nil {
		t.Fatal(err)
	}
	b := newBrowser(a.Middleware(echo), "https://paindash.example.com")
	res := b.do(http.MethodGet, "/vulns?env=prod&ns=a,b", nil)
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/auth/login?rd=%2Fvulns%3Fenv%3Dprod%26ns%3Da%2Cb" {
		t.Errorf("page: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	for _, r := range []struct{ method, path string }{{"GET", "/api/meta"}, {"GET", "/api/stream?env=prod"}, {"POST", "/api/exceptions"}} {
		res := b.do(r.method, r.path, nil)
		if res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get("Content-Type"), "json") {
			t.Errorf("%s %s: %d %s", r.method, r.path, res.StatusCode, res.Header.Get("Content-Type"))
		}
	}
	res = b.do(http.MethodGet, "/auth/login?rd=%2Fvulns", nil)
	if s := body(res); res.StatusCode != http.StatusOK || !strings.Contains(s, `action="/auth/login"`) || !strings.Contains(s, `value="/vulns"`) {
		t.Errorf("sign-in form: %d", res.StatusCode)
	}
}
