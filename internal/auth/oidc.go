package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig signs users in with an OpenID Connect provider (Keycloak, Dex,
// Entra ID, Okta, Google...), authorization code flow with PKCE.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string   // empty for a public client (PKCE only)
	Scopes       []string // default openid, email, profile
	// GroupsClaim names the ID token claim holding the groups (default
	// "groups"); a dotted path reaches into objects, e.g. realm_access.roles.
	GroupsClaim string
}

type oidcLogin struct {
	cfg      OIDCConfig
	redirect string
	client   *http.Client

	mu    sync.Mutex
	oauth *oauth2.Config
	ver   *oidc.IDTokenVerifier
}

// loginState travels in the login cookie between the redirect to the identity
// provider and its callback.
type loginState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	RD       string `json:"r"`
	Expires  int64  `json:"x"`
}

// NewOIDC returns sessions opened by an OpenID Connect sign-in. The provider
// is discovered at the first sign-in (and retried until it answers), so that
// paindash starts and serves signed-in users while it is unreachable.
func NewOIDC(ctx context.Context, cfg OIDCConfig, sc SessionConfig) (*Sessions, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" {
		return nil, errors.New("PAINDASH_OIDC_ISSUER and PAINDASH_OIDC_CLIENT_ID are required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	a, err := newSessions(sc)
	if err != nil {
		return nil, err
	}
	a.kind = "oidc"
	a.oidc = &oidcLogin{cfg: cfg, redirect: a.public + "/auth/callback", client: &http.Client{Timeout: 15 * time.Second}}
	// Discovered now in the background, to log a wrong issuer early without
	// delaying the start.
	go func() {
		if _, _, err := a.oidc.provider(ctx); err != nil {
			a.log.Warn("OpenID Connect provider unreachable, retried at the next sign-in", "issuer", cfg.Issuer, "err", err)
		}
	}()
	return a, nil
}

func (o *oidcLogin) ctx(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, o.client)
}

func (o *oidcLogin) provider(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.oauth == nil {
		p, err := oidc.NewProvider(o.ctx(ctx), o.cfg.Issuer)
		if err != nil {
			return nil, nil, err
		}
		o.oauth = &oauth2.Config{
			ClientID: o.cfg.ClientID, ClientSecret: o.cfg.ClientSecret,
			Endpoint: p.Endpoint(), RedirectURL: o.redirect, Scopes: o.cfg.Scopes,
		}
		o.ver = p.Verifier(&oidc.Config{ClientID: o.cfg.ClientID})
	}
	return o.oauth, o.ver, nil
}

// startOIDC sends the browser to the identity provider.
func (a *Sessions) startOIDC(w http.ResponseWriter, r *http.Request, rd string) {
	conf, _, err := a.oidc.provider(r.Context())
	if err != nil {
		a.log.Error("OpenID Connect provider unreachable", "issuer", a.oidc.cfg.Issuer, "err", err)
		a.render(w, http.StatusBadGateway, page{Title: "Sign-in unavailable", Message: "The identity provider cannot be reached. Try again in a moment.", Link: "/auth/login?rd=" + url.QueryEscape(rd), LinkText: "Try again"})
		return
	}
	ls := loginState{State: random(), Nonce: random(), Verifier: oauth2.GenerateVerifier(), RD: rd, Expires: a.now().Add(10 * time.Minute).Unix()}
	v, err := a.seal(ls, loginCookie)
	if err != nil {
		a.fail(w, err)
		return
	}
	a.setCookie(w, loginCookie, v, 10*time.Minute)
	http.Redirect(w, r, conf.AuthCodeURL(ls.State, oidc.Nonce(ls.Nonce), oauth2.S256ChallengeOption(ls.Verifier)), http.StatusFound)
}

// callback answers GET /auth/callback, where the identity provider sends the
// browser back with an authorization code.
func (a *Sessions) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var ls loginState
	c, err := r.Cookie(a.cookieName(loginCookie))
	if err != nil || !a.open(c.Value, loginCookie, &ls) || a.now().Unix() >= ls.Expires ||
		subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(ls.State)) != 1 {
		// Expired, replayed, or started in another tab since.
		a.render(w, http.StatusBadRequest, page{Title: "Sign-in expired", Message: "This sign-in took too long or was replaced by another one.", Link: "/auth/login?rd=" + url.QueryEscape(localPath(ls.RD)), LinkText: "Sign in again"})
		return
	}
	a.setCookie(w, loginCookie, "", -1)
	retry := "/auth/login?rd=" + url.QueryEscape(ls.RD)
	if e := q.Get("error"); e != "" {
		a.log.Warn("sign-in refused by the identity provider", "error", e, "description", q.Get("error_description"))
		why := strings.TrimSpace(e + " " + q.Get("error_description"))
		if r := []rune(why); len(r) > 200 {
			why = string(r[:200]) + "…"
		}
		a.render(w, http.StatusForbidden, page{Title: "Sign-in refused", Message: "The identity provider refused the sign-in: " + why, Link: retry, LinkText: "Try again"})
		return
	}
	conf, ver, err := a.oidc.provider(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	ctx := a.oidc.ctx(r.Context())
	tok, err := conf.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(ls.Verifier))
	if err != nil {
		a.log.Warn("OpenID Connect code exchange failed", "err", err)
		a.render(w, http.StatusBadGateway, page{Title: "Sign-in failed", Message: "The identity provider did not confirm the sign-in.", Link: retry, LinkText: "Try again"})
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := ver.Verify(ctx, raw)
	if err != nil || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(ls.Nonce)) != 1 {
		a.log.Warn("invalid ID token", "err", err)
		a.render(w, http.StatusBadGateway, page{Title: "Sign-in failed", Message: "The identity provider sent an invalid ID token.", Link: retry, LinkText: "Try again"})
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		a.fail(w, err)
		return
	}
	a.signIn(w, r, identity(claims), stringsAt(claims, a.oidc.cfg.GroupsClaim), "", ls.RD)
}

// identity names the user: the email, unless the provider says it is not
// verified, else the username, else the subject.
func identity(claims map[string]any) string {
	verified := true
	switch v := claims["email_verified"].(type) {
	case bool:
		verified = v
	case string:
		verified = v == "true"
	}
	keys := []string{"preferred_username", "sub"}
	if verified {
		keys = append([]string{"email"}, keys...)
	}
	for _, k := range keys {
		if s, _ := claims[k].(string); s != "" {
			return s
		}
	}
	return ""
}

// stringsAt reads a list of strings (or a single string) at a dotted path.
func stringsAt(claims map[string]any, path string) []string {
	var v any = claims
	for _, k := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	switch v := v.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
