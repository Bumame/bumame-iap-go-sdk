package iap

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestRequireAnyPermissionAllowsMatchingPrincipal(t *testing.T) {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(PrincipalLocalKey, Principal{Permissions: []string{"cis.encounter.read"}})
		return c.Next()
	})
	app.Get("/encounters", RequireAnyPermission("cis.encounter.read"), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusNoContent)
	})

	response, err := app.Test(httptest.NewRequest("GET", "/encounters", nil))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != fiber.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.StatusCode, fiber.StatusNoContent)
	}
}

func TestIAPIDFromFiber(t *testing.T) {
	app := fiber.New()
	app.Get("/me", func(c *fiber.Ctx) error {
		c.Locals(PrincipalLocalKey, Principal{Subject: "5a40f2f5-1d63-45e8-8799-d31977c09f91"})
		id, ok := IAPIDFromFiber(c)
		if !ok || id != "5a40f2f5-1d63-45e8-8799-d31977c09f91" {
			return c.SendStatus(fiber.StatusInternalServerError)
		}
		return c.SendStatus(fiber.StatusNoContent)
	})
	response, err := app.Test(httptest.NewRequest(http.MethodGet, "/me", nil))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != fiber.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.StatusCode, fiber.StatusNoContent)
	}
}

func TestRequireAnyRoleRejectsNonMatchingPrincipal(t *testing.T) {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(PrincipalLocalKey, Principal{Roles: []string{"cis.front-office"}})
		return c.Next()
	})
	app.Get("/reports", RequireAnyRole("cis.superuser"), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusNoContent)
	})

	response, err := app.Test(httptest.NewRequest("GET", "/reports", nil))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != fiber.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.StatusCode, fiber.StatusForbidden)
	}
}

func TestRequireInt64ResourceFromHeader(t *testing.T) {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(PrincipalLocalKey, Principal{ResourceScopes: map[string]ResourceScope{
			"cis.clinics": {Mode: "selected", IDs: []string{"7"}},
		}})
		return c.Next()
	})
	app.Get("/encounters", RequireInt64ResourceFromHeader("cis.clinics", "X-Clinic-ID"), func(c *fiber.Ctx) error {
		id, ok := Int64ResourceFromFiber(c, "cis.clinics")
		if !ok || id != 7 {
			return c.SendStatus(fiber.StatusInternalServerError)
		}
		return c.SendStatus(fiber.StatusNoContent)
	})

	allowedRequest := httptest.NewRequest(http.MethodGet, "/encounters", nil)
	allowedRequest.Header.Set("X-Clinic-ID", "7")
	allowed, err := app.Test(allowedRequest)
	if err != nil {
		t.Fatal(err)
	}
	if allowed.StatusCode != fiber.StatusNoContent {
		t.Fatalf("allowed status = %d, want %d", allowed.StatusCode, fiber.StatusNoContent)
	}

	deniedRequest := httptest.NewRequest(http.MethodGet, "/encounters", nil)
	deniedRequest.Header.Set("X-Clinic-ID", "8")
	denied, err := app.Test(deniedRequest)
	if err != nil {
		t.Fatal(err)
	}
	if denied.StatusCode != fiber.StatusForbidden {
		t.Fatalf("denied status = %d, want %d", denied.StatusCode, fiber.StatusForbidden)
	}
}
