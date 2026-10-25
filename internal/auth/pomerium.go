package auth

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
)

const header = "X-Pomerium-Jwt-Assertion"

// Pomerium enforces the access policy; paindash still verifies the signed
// X-Pomerium-Jwt-Assertion header so that a request reaching the pod without
// going through Pomerium (port-forward, another pod) is rejected.
type Pomerium struct {
	verifier *oidc.IDTokenVerifier
	policy   Policy
	log      *slog.Logger
}

// NewPomerium verifies tokens against the JWKS of Pomerium (served at
// https://<route or authenticate host>/.well-known/pomerium/jwks.json).
// audience is the route host, e.g. "paindash.example.com". issuer may be
// empty to skip the issuer check. policy.Allowed, when set, is an extra
// app-side check on the "groups" claim.
func NewPomerium(ctx context.Context, jwksURL, audience, issuer string, policy Policy, log *slog.Logger) *Pomerium {
	keys := oidc.NewRemoteKeySet(ctx, jwksURL)
	v := oidc.NewVerifier(issuer, keys, &oidc.Config{
		ClientID:             audience,
		SkipIssuerCheck:      issuer == "",
		SupportedSigningAlgs: []string{oidc.ES256, oidc.RS256},
	})
	return &Pomerium{verifier: v, policy: policy, log: log}
}

func (p *Pomerium) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get(header)
		if raw == "" {
			http.Error(w, "missing Pomerium identity", http.StatusUnauthorized)
			return
		}
		tok, err := p.verifier.Verify(r.Context(), raw)
		if err != nil {
			p.log.Warn("rejected Pomerium assertion", "err", err)
			http.Error(w, "invalid Pomerium identity", http.StatusUnauthorized)
			return
		}
		var claims struct {
			Email  string   `json:"email"`
			Groups []string `json:"groups"`
		}
		if err := tok.Claims(&claims); err != nil {
			http.Error(w, "invalid claims", http.StatusUnauthorized)
			return
		}
		if !p.policy.allows(claims.Groups) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), p.policy.user(claims.Email, claims.Groups))))
	})
}
