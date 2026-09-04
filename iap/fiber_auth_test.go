package iap

import "testing"

func TestNewFiberAuthValidatesConfiguration(t *testing.T) {
	if _, err := NewFiberAuth(Config{}); err == nil {
		t.Fatal("expected invalid configuration error")
	}
	auth, err := NewFiberAuth(Config{
		Issuer:   "https://auth.example.com",
		Audience: "urn:example:app",
	})
	if err != nil {
		t.Fatalf("NewFiberAuth() error = %v", err)
	}
	if auth == nil || auth.verifier == nil {
		t.Fatal("expected initialized immutable Fiber auth runtime")
	}
}
