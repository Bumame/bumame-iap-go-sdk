package iap

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyAccessTokenAndPermissions(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "jwks_uri": issuer + "/jwks"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "test", "n": base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()), "e": "AQAB"}}})
	}))
	defer server.Close()
	issuer = server.URL
	verifier, err := NewVerifier(Config{Issuer: issuer, Audience: "urn:bumame:cis"})
	if err != nil {
		t.Fatal(err)
	}
	token := signedToken(t, privateKey, map[string]any{"iss": issuer, "sub": "user-1", "aud": []string{"urn:bumame:cis"}, "exp": time.Now().Add(time.Minute).Unix(), "picture": "https://example.com/avatar.jpg", "ext": map[string]any{"roles": []string{"cis.doctor"}, "permissions": []string{"cis.patient.read"}}})
	principal, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if principal.Subject != "user-1" || principal.Picture != "https://example.com/avatar.jpg" || !principal.HasRole("cis.doctor") || !principal.HasPermission("cis.patient.read") {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}

func TestRejectsWrongAudience(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuer := "https://issuer.example"
	verifier, _ := NewVerifier(Config{Issuer: issuer, Audience: "expected"})
	token := signedToken(t, privateKey, map[string]any{"iss": issuer, "sub": "user-1", "aud": "other", "exp": time.Now().Add(time.Minute).Unix()})
	var header, payload map[string]any
	_ = header
	_ = payload
	if _, err := verifier.Verify(context.Background(), token); err == nil {
		t.Fatal("expected verification failure")
	}
}

func signedToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		raw, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	unsigned := encode(map[string]string{"alg": "RS256", "kid": "test", "typ": "JWT"}) + "." + encode(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s.%s", unsigned, base64.RawURLEncoding.EncodeToString(signature))
}
