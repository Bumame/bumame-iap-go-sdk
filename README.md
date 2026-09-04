# Bumame IAP Go SDK

Shared authentication and authorization helpers for Bumame Go backends.

## Install

```bash
go get github.com/Bumame/bumame-iap-go-sdk@v0.1.0-alpha.3
```

The package repository is public; applications should still pin a released tag.

## Usage

```go
verifier, err := iap.NewVerifier(iap.Config{
    Issuer:   "https://auth.bumame.com",
    Audience: "urn:bumame:cis",
})
if err != nil { log.Fatal(err) }

router.With(
    verifier.Authenticate,
    iap.RequireAnyPermission("cis.patient.read"),
).Get("/patients/{id}", getPatient)
```

Use `RequireAnyRole` only while migrating legacy role checks. New endpoints should use permissions and must still enforce resource ownership in the application backend.

The SDK validates RS256 signature, `iss`, `aud`, `sub`, `exp`, and `nbf`, discovers JWKS from the issuer, refreshes keys after rotation, and normalizes profile claims (`name`, `email`, `picture`) plus Hydra access-token claims from `ext.roles` and `ext.permissions`.
