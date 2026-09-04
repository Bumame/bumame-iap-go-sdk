package iap

import "github.com/gofiber/fiber/v2"

// FiberAuth is an immutable Fiber authentication runtime. Construct it once at
// process startup and inject its middleware into protected route groups.
// It intentionally contains no application database or global mutable state.
type FiberAuth struct {
	verifier *Verifier
}

// NewFiberAuth validates the IAP configuration and constructs the token
// verifier used by Fiber middleware.
func NewFiberAuth(cfg Config) (*FiberAuth, error) {
	verifier, err := NewVerifier(cfg)
	if err != nil {
		return nil, err
	}
	return &FiberAuth{verifier: verifier}, nil
}

// Authenticate verifies the IAP bearer token, normalizes its claims, and
// stores a typed Principal in Fiber Locals and the request context.
func (a *FiberAuth) Authenticate() fiber.Handler {
	return a.verifier.Authenticate()
}
