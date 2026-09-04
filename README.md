# Bumame IAP Go SDK

Shared authentication and authorization helpers for Bumame Go backends.

## Install

```bash
go get github.com/Bumame/bumame-iap-go-sdk@v1.2.0
```

The package repository is public; applications should still pin a released tag.

## Usage

```go
auth, err := iap.NewFiberAuth(iap.Config{
    Issuer:   "https://auth.bumame.com",
    Audience: "urn:bumame:cis",
})
if err != nil { log.Fatal(err) }

app.Get("/patients/:id",
    auth.Authenticate(),
    iap.RequireAnyPermission("cis.patient.read"),
    getPatient,
)
```

`NewFiberAuth` is created once during startup and passed directly to normal
Fiber route groups. It has no application database, global mutable runtime, or
legacy-user adapter. In handlers, read the authenticated identity with
`PrincipalFromFiber`, `IAPIDFromFiber`, `RolesFromFiber`, or
`PermissionsFromFiber`. Persist `IAPIDFromFiber` in UUID columns named
`iap_id` or `*_iap_id`.

Use `RequireAnyRole` only while migrating legacy role checks. New endpoints should use permissions and must still enforce resource ownership in the application backend.

The SDK validates RS256 signature, `iss`, `aud`, `sub`, `exp`, and `nbf`, discovers JWKS from the issuer, refreshes keys after rotation, and normalizes profile claims (`name`, `email`, `picture`) plus Hydra access-token claims from `ext.roles` and `ext.permissions`.
