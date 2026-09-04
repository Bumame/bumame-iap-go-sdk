package iap

import (
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
)

const PrincipalLocalKey = "iap_principal"

// Authenticate validates the IAP bearer token and makes the principal available
// to both Fiber handlers and downstream context.Context-aware services.
func (v *Verifier) Authenticate() fiber.Handler {
	return func(c *fiber.Ctx) error {
		scheme, token, ok := strings.Cut(strings.TrimSpace(c.Get(fiber.HeaderAuthorization)), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
			return writeAuthError(c, fiber.StatusUnauthorized, "unauthenticated")
		}
		principal, err := v.Verify(c.UserContext(), strings.TrimSpace(token))
		if err != nil {
			return writeAuthError(c, fiber.StatusUnauthorized, "invalid_token")
		}

		c.Locals(PrincipalLocalKey, principal)
		c.SetUserContext(WithPrincipal(c.UserContext(), principal))
		return c.Next()
	}
}

func PrincipalFromFiber(c *fiber.Ctx) (Principal, bool) {
	principal, ok := c.Locals(PrincipalLocalKey).(Principal)
	return principal, ok
}

func RequireAnyRole(roles ...string) fiber.Handler {
	return require(func(p Principal) bool { return p.HasAnyRole(roles...) })
}
func RequireAnyPermission(permissions ...string) fiber.Handler {
	return require(func(p Principal) bool { return p.HasAnyPermission(permissions...) })
}

// RequireResource allows a route only when the authenticated principal has
// access to the supplied resource ID. It is useful when a route has a fixed
// resource, while dynamic resource IDs should use RequireResourceFromParam or
// RequireResourceFromHeader.
func RequireResource(resourceType, resourceID string) fiber.Handler {
	return require(func(p Principal) bool {
		return p.HasResource(resourceType, strings.TrimSpace(resourceID))
	})
}

// RequireResourceFromParam validates a Fiber route parameter against a
// resource scope claim. Example: RequireResourceFromParam("cis.clinics", "clinicID").
func RequireResourceFromParam(resourceType, param string) fiber.Handler {
	return requireResourceValue(resourceType, func(c *fiber.Ctx) string {
		return c.Params(param)
	})
}

// RequireResourceFromHeader validates a request header against a resource
// scope claim. Example: RequireResourceFromHeader("cis.clinics", "X-Clinic-ID").
func RequireResourceFromHeader(resourceType, header string) fiber.Handler {
	return requireResourceValue(resourceType, func(c *fiber.Ctx) string {
		return c.Get(header)
	})
}

// RequireInt64ResourceFromHeader is a convenience guard for resource IDs that
// are numeric in the application database. It rejects malformed IDs before
// scope evaluation, keeping application handlers free of auth parsing.
func RequireInt64ResourceFromHeader(resourceType, header string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		value := strings.TrimSpace(c.Get(header))
		if value == "" {
			return writeAuthError(c, fiber.StatusBadRequest, "resource_context_required")
		}
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			return writeAuthError(c, fiber.StatusBadRequest, "invalid_resource_context")
		}
		principal, ok := PrincipalFromFiber(c)
		if !ok {
			return writeAuthError(c, fiber.StatusUnauthorized, "unauthenticated")
		}
		if !principal.HasResource(resourceType, value) {
			return writeAuthError(c, fiber.StatusForbidden, "resource_forbidden")
		}
		return c.Next()
	}
}

func require(allowed func(Principal) bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		principal, ok := PrincipalFromFiber(c)
		if !ok {
			return writeAuthError(c, fiber.StatusUnauthorized, "unauthenticated")
		}
		if !allowed(principal) {
			return writeAuthError(c, fiber.StatusForbidden, "forbidden")
		}
		return c.Next()
	}
}

func requireResourceValue(resourceType string, value func(*fiber.Ctx) string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		resourceID := strings.TrimSpace(value(c))
		if resourceID == "" {
			return writeAuthError(c, fiber.StatusBadRequest, "resource_context_required")
		}
		principal, ok := PrincipalFromFiber(c)
		if !ok {
			return writeAuthError(c, fiber.StatusUnauthorized, "unauthenticated")
		}
		if !principal.HasResource(resourceType, resourceID) {
			return writeAuthError(c, fiber.StatusForbidden, "resource_forbidden")
		}
		return c.Next()
	}
}

func writeAuthError(c *fiber.Ctx, status int, code string) error {
	return c.Status(status).JSON(fiber.Map{
		"error": fiber.Map{"code": code},
	})
}
