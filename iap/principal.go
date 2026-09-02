package iap

import "context"

type Principal struct {
	Subject     string   `json:"sub"`
	Issuer      string   `json:"iss"`
	Audience    []string `json:"aud"`
	Email       string   `json:"email,omitempty"`
	Name        string   `json:"name,omitempty"`
	Picture     string   `json:"picture,omitempty"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

func (p Principal) HasRole(role string) bool             { return contains(p.Roles, role) }
func (p Principal) HasAnyRole(roles ...string) bool      { return containsAny(p.Roles, roles) }
func (p Principal) HasPermission(permission string) bool { return contains(p.Permissions, permission) }
func (p Principal) HasAnyPermission(permissions ...string) bool {
	return containsAny(p.Permissions, permissions)
}

func contains(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}
func containsAny(items, wanted []string) bool {
	for _, candidate := range wanted {
		if contains(items, candidate) {
			return true
		}
	}
	return false
}

type principalContextKey struct{}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}
