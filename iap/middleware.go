package iap

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (v *Verifier) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, token, ok := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
			writeAuthError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		principal, err := v.Verify(r.Context(), strings.TrimSpace(token))
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
	})
}

func RequireAnyRole(roles ...string) func(http.Handler) http.Handler {
	return require(func(p Principal) bool { return p.HasAnyRole(roles...) })
}
func RequireAnyPermission(permissions ...string) func(http.Handler) http.Handler {
	return require(func(p Principal) bool { return p.HasAnyPermission(permissions...) })
}

func require(allowed func(Principal) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := PrincipalFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "unauthenticated")
				return
			}
			if !allowed(principal) {
				writeAuthError(w, http.StatusForbidden, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeAuthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
