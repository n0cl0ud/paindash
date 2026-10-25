// Package auth establishes who is calling: from the signed assertion of
// Pomerium, or from a session cookie paindash issues itself after an OpenID
// Connect login (oidc) or a password check against local accounts (local).
package auth

import (
	"context"
	"slices"

	"github.com/n0cl0ud/paindash/internal/model"
)

type ctxKey struct{}

// Policy decides from groups who gets in and who may record exceptions.
type Policy struct {
	Allowed []string // groups allowed in; empty: any authenticated user
	Editors []string // groups that may record and revoke exceptions; empty: anyone allowed in
}

func (p Policy) allows(groups []string) bool {
	return len(p.Allowed) == 0 || intersects(groups, p.Allowed)
}

// relevant keeps the groups the policy looks at: a session cookie stays small
// whatever the number of groups the identity provider returns.
func (p Policy) relevant(groups []string) []string {
	var out []string
	for _, g := range groups {
		if slices.Contains(p.Allowed, g) || slices.Contains(p.Editors, g) {
			out = append(out, g)
		}
	}
	return out
}

func (p Policy) user(email string, groups []string) *model.User {
	if groups == nil {
		groups = []string{}
	}
	return &model.User{Email: email, Groups: groups, CanEdit: len(p.Editors) == 0 || intersects(groups, p.Editors)}
}

func intersects(a, b []string) bool {
	return slices.ContainsFunc(a, func(g string) bool { return slices.Contains(b, g) })
}

func withUser(ctx context.Context, u *model.User) context.Context {
	return context.WithValue(ctx, ctxKey{}, u)
}

// UserFrom returns the authenticated user, or nil when auth is disabled.
func UserFrom(ctx context.Context) *model.User {
	u, _ := ctx.Value(ctxKey{}).(*model.User)
	return u
}
