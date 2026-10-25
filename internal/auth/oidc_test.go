package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeIdP is an OpenID Connect provider: discovery, JWKS, and a token
// endpoint that checks the client secret, the redirect URI and the PKCE
// verifier, and signs ID tokens (RS256) with claims set by the test.
type fakeIdP struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	down atomic.Bool // discovery answers 503

	mu     sync.Mutex
	claims map[string]any // added to the next ID tokens
	codes  map[string]grant
}

type grant struct{ challenge, nonce, redirect string }

const clientID, clientSecret = "paindash", "s3cret"

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, codes: map[string]grant{}, claims: map[string]any{}}
	b64 := base64.RawURLEncoding.EncodeToString
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if f.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /token", f.token)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// authorize plays the browser at the provider: it reads the request paindash
// redirected to and returns a code for it.
func (f *fakeIdP) authorize(t *testing.T, location string) (code, state string) {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil || !strings.HasPrefix(location, f.srv.URL+"/authorize?") {
		t.Fatalf("not sent to the provider: %s", location)
	}
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != clientID || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || q.Get("nonce") == "" || !slices.Contains(strings.Fields(q.Get("scope")), "openid") {
		t.Fatalf("authorization request: %v", q)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	code = random()
	f.codes[code] = grant{q.Get("code_challenge"), q.Get("nonce"), q.Get("redirect_uri")}
	return code, q.Get("state")
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	f.mu.Lock()
	g, found := f.codes[r.PostForm.Get("code")]
	delete(f.codes, r.PostForm.Get("code")) // a code is used once
	claims := map[string]any{"iss": f.srv.URL, "aud": clientID, "sub": "u-1", "nonce": g.nonce,
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()}
	for k, v := range f.claims {
		claims[k] = v
	}
	f.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	switch {
	case id != clientID || secret != clientSecret:
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
	case !found || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge || r.PostForm.Get("redirect_uri") != g.redirect:
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": f.sign(claims)})
	}
}

func (f *fakeIdP) sign(claims map[string]any) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signed := enc(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signed))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (f *fakeIdP) set(claims map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims = claims
}

func oidcSite(t *testing.T, f *fakeIdP, policy Policy, claim string) (*Sessions, *browser) {
	t.Helper()
	a, err := NewOIDC(context.Background(), OIDCConfig{Issuer: f.srv.URL, ClientID: clientID, ClientSecret: clientSecret, GroupsClaim: claim},
		SessionConfig{Key: testKey(), PublicURL: site, Policy: policy, Log: testLog})
	if err != nil {
		t.Fatal(err)
	}
	return a, newBrowser(a.Middleware(echo), site)
}

// login goes from a page to the provider and back, as a browser would.
func (f *fakeIdP) login(t *testing.T, b *browser, page string) *http.Response {
	t.Helper()
	res := b.do(http.MethodGet, page, nil)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("%s: %d", page, res.StatusCode)
	}
	res = b.do(http.MethodGet, res.Header.Get("Location"), nil)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("/auth/login: %d %s", res.StatusCode, body(res))
	}
	code, state := f.authorize(t, res.Header.Get("Location"))
	return b.do(http.MethodGet, "/auth/callback?"+url.Values{"code": {code}, "state": {state}}.Encode(), nil)
}

func TestOIDCSignIn(t *testing.T) {
	f := newFakeIdP(t)
	_, b := oidcSite(t, f, Policy{Editors: []string{"sec"}}, "")
	f.set(map[string]any{"email": "alice@example.com", "email_verified": true, "groups": []string{"dev", "sec"}})
	res := f.login(t, b, "/vulns?env=prod")
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/vulns?env=prod" {
		t.Fatalf("callback: %d %s %s", res.StatusCode, res.Header.Get("Location"), body(res))
	}
	if _, ok := b.cookies["__Host-paindash_login"]; ok {
		t.Error("login cookie kept after the callback")
	}
	u := b.user(t)
	if u == nil || u.Email != "alice@example.com" || !u.CanEdit || strings.Join(u.Groups, ",") != "sec" {
		t.Errorf("user: %+v", u)
	}
	// Signed in: /auth/login goes straight back.
	if res := b.do(http.MethodGet, "/auth/login?rd=%2Fworkloads", nil); res.Header.Get("Location") != "/workloads" {
		t.Errorf("signed in, /auth/login: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestOIDCGroupsAndIdentity(t *testing.T) {
	f := newFakeIdP(t)
	_, b := oidcSite(t, f, Policy{Allowed: []string{"paindash"}, Editors: []string{"paindash-admin"}}, "realm_access.roles")
	// Unverified email: the username names the user.
	f.set(map[string]any{"email": "boss@example.com", "email_verified": "false", "preferred_username": "mallory",
		"realm_access": map[string]any{"roles": []string{"paindash"}}})
	f.login(t, b, "/")
	if u := b.user(t); u == nil || u.Email != "mallory" || u.CanEdit || strings.Join(u.Groups, ",") != "paindash" {
		t.Errorf("user: %+v", u)
	}

	// In none of the allowed groups: refused, no session.
	_, b = oidcSite(t, f, Policy{Allowed: []string{"paindash"}}, "realm_access.roles")
	f.set(map[string]any{"email": "eve@example.com", "realm_access": map[string]any{"roles": "other"}})
	if res := f.login(t, b, "/"); res.StatusCode != http.StatusForbidden || b.user(t) != nil {
		t.Errorf("not allowed: %d", res.StatusCode)
	}
}

func TestOIDCCallbackChecks(t *testing.T) {
	f := newFakeIdP(t)
	a, b := oidcSite(t, f, Policy{}, "")
	f.set(map[string]any{"email": "alice@example.com"})
	start := func() (code, state string) {
		res := b.do(http.MethodGet, "/auth/login", nil)
		return f.authorize(t, res.Header.Get("Location"))
	}
	callback := func(q url.Values) *http.Response { return b.do(http.MethodGet, "/auth/callback?"+q.Encode(), nil) }

	code, _ := start()
	if res := callback(url.Values{"code": {code}, "state": {"forged"}}); res.StatusCode != http.StatusBadRequest {
		t.Errorf("wrong state: %d", res.StatusCode)
	}
	if b.user(t) != nil {
		t.Fatal("signed in")
	}

	// The provider refused (the user cancelled).
	_, state := start()
	if res := callback(url.Values{"error": {"access_denied"}, "state": {state}}); res.StatusCode != http.StatusForbidden || !strings.Contains(body(res), "access_denied") {
		t.Errorf("provider error: %d", res.StatusCode)
	}

	// A code replayed, or one that does not match the PKCE verifier.
	code, state = start()
	f.mu.Lock()
	g := f.codes[code]
	g.challenge = "not-the-challenge"
	f.codes[code] = g
	f.mu.Unlock()
	if res := callback(url.Values{"code": {code}, "state": {state}}); res.StatusCode != http.StatusBadGateway {
		t.Errorf("PKCE mismatch: %d", res.StatusCode)
	}

	// An ID token for another sign-in (nonce).
	code, state = start()
	f.mu.Lock()
	g = f.codes[code]
	g.nonce = "another"
	f.codes[code] = g
	f.mu.Unlock()
	if res := callback(url.Values{"code": {code}, "state": {state}}); res.StatusCode != http.StatusBadGateway {
		t.Errorf("nonce mismatch: %d", res.StatusCode)
	}

	// The login cookie expires after 10 minutes.
	clk := &clock{time.Now()}
	a.now = clk.now
	code, state = start()
	clk.t = clk.t.Add(10 * time.Minute)
	if res := callback(url.Values{"code": {code}, "state": {state}}); res.StatusCode != http.StatusBadRequest {
		t.Errorf("expired login: %d", res.StatusCode)
	}
	if b.user(t) != nil {
		t.Error("signed in after failed callbacks")
	}
}

// An unreachable provider does not stop paindash: sign-in says so, and works
// once the provider answers.
func TestOIDCProviderDown(t *testing.T) {
	f := newFakeIdP(t)
	f.down.Store(true)
	_, b := oidcSite(t, f, Policy{}, "")
	if res := b.do(http.MethodGet, "/auth/login", nil); res.StatusCode != http.StatusBadGateway {
		t.Errorf("provider down: %d", res.StatusCode)
	}
	f.down.Store(false)
	f.set(map[string]any{"email": "alice@example.com"})
	if res := f.login(t, b, "/"); res.StatusCode != http.StatusSeeOther || b.user(t) == nil {
		t.Errorf("provider back: %d", res.StatusCode)
	}
}

func TestStringsAt(t *testing.T) {
	claims := map[string]any{"groups": []any{"a", 1, "b"}, "one": "x", "realm_access": map[string]any{"roles": []any{"r"}}}
	for path, want := range map[string]string{"groups": "a,b", "one": "x", "realm_access.roles": "r", "missing": "", "one.deeper": ""} {
		if got := strings.Join(stringsAt(claims, path), ","); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
}
