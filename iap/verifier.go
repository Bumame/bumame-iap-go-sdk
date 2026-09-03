package iap

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidToken = errors.New("iap: invalid access token")
	ErrExpiredToken = errors.New("iap: access token expired")
)

type discoveryDocument struct{ Issuer, JWKSURI string }

func (d *discoveryDocument) UnmarshalJSON(data []byte) error {
	var value struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	d.Issuer, d.JWKSURI = value.Issuer, value.JWKSURI
	return nil
}

type Verifier struct {
	cfg        Config
	http       *http.Client
	mu         sync.RWMutex
	jwksURI    string
	keys       map[string]*rsa.PublicKey
	keysExpire time.Time
}

func NewVerifier(cfg Config) (*Verifier, error) {
	normalized, err := cfg.normalized()
	if err != nil {
		return nil, err
	}
	return &Verifier{cfg: normalized, http: &http.Client{Timeout: normalized.HTTPTimeout}}, nil
}

func (v *Verifier) Verify(ctx context.Context, raw string) (Principal, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Principal{}, ErrInvalidToken
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	if err := decodePart(parts[0], &header); err != nil || header.Algorithm != "RS256" || header.KeyID == "" {
		return Principal{}, ErrInvalidToken
	}
	key, err := v.key(ctx, header.KeyID, false)
	if err != nil {
		key, err = v.key(ctx, header.KeyID, true)
		if err != nil {
			return Principal{}, fmt.Errorf("%w: signing key: %v", ErrInvalidToken, err)
		}
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return Principal{}, ErrInvalidToken
	}

	var claims struct {
		Issuer    string          `json:"iss"`
		Subject   string          `json:"sub"`
		Audience  json.RawMessage `json:"aud"`
		Expires   int64           `json:"exp"`
		NotBefore int64           `json:"nbf"`
		Email     string          `json:"email"`
		Name      string          `json:"name"`
		Picture   string          `json:"picture"`
		Ext       struct {
			Roles          []string                 `json:"roles"`
			Permissions    []string                 `json:"permissions"`
			ResourceScopes map[string]ResourceScope `json:"resource_scopes"`
			Email          string                   `json:"email"`
			Name           string                   `json:"name"`
			Picture        string                   `json:"picture"`
		} `json:"ext"`
	}
	if err := decodePart(parts[1], &claims); err != nil {
		return Principal{}, ErrInvalidToken
	}
	audiences, err := decodeAudience(claims.Audience)
	if err != nil || claims.Issuer != v.cfg.Issuer || claims.Subject == "" || !contains(audiences, v.cfg.Audience) {
		return Principal{}, ErrInvalidToken
	}
	now := time.Now()
	if claims.Expires == 0 || now.After(time.Unix(claims.Expires, 0).Add(v.cfg.ClockSkew)) {
		return Principal{}, ErrExpiredToken
	}
	if claims.NotBefore != 0 && now.Add(v.cfg.ClockSkew).Before(time.Unix(claims.NotBefore, 0)) {
		return Principal{}, ErrInvalidToken
	}
	email, name, picture := claims.Email, claims.Name, claims.Picture
	if email == "" {
		email = claims.Ext.Email
	}
	if name == "" {
		name = claims.Ext.Name
	}
	if picture == "" {
		picture = claims.Ext.Picture
	}
	return Principal{Subject: claims.Subject, Issuer: claims.Issuer, Audience: audiences, Email: email, Name: name, Picture: picture, Roles: claims.Ext.Roles, Permissions: claims.Ext.Permissions, ResourceScopes: claims.Ext.ResourceScopes}, nil
}

func (v *Verifier) key(ctx context.Context, kid string, force bool) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, exists := v.keys[kid]
	fresh := time.Now().Before(v.keysExpire)
	v.mu.RUnlock()
	if exists && fresh && !force {
		return key, nil
	}
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	key, exists = v.keys[kid]
	if !exists {
		return nil, errors.New("unknown kid")
	}
	return key, nil
}

func (v *Verifier) refresh(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	uri := v.jwksURI
	if uri == "" {
		var discovery struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := v.getJSON(ctx, v.cfg.Issuer+"/.well-known/openid-configuration", &discovery); err != nil {
			return err
		}
		if strings.TrimRight(discovery.Issuer, "/") != v.cfg.Issuer || discovery.JWKSURI == "" {
			return errors.New("issuer discovery mismatch")
		}
		uri = discovery.JWKSURI
		v.jwksURI = uri
	}
	var raw struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := v.getJSON(ctx, uri, &raw); err != nil {
		return err
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, item := range raw.Keys {
		kid, _ := item["kid"].(string)
		kty, _ := item["kty"].(string)
		n, _ := item["n"].(string)
		e, _ := item["e"].(string)
		if kid == "" || kty != "RSA" {
			continue
		}
		key, err := rsaKey(n, e, item)
		if err == nil {
			keys[kid] = key
		}
	}
	if len(keys) == 0 {
		return errors.New("JWKS contains no usable RSA keys")
	}
	v.keys, v.keysExpire = keys, time.Now().Add(v.cfg.JWKSCacheTTL)
	return nil
}

func rsaKey(n, e string, item map[string]any) (*rsa.PublicKey, error) {
	if n != "" && e != "" {
		nBytes, err := base64.RawURLEncoding.DecodeString(n)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(e)
		if err != nil {
			return nil, err
		}
		exponent := 0
		for _, b := range eBytes {
			exponent = exponent<<8 + int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: exponent}, nil
	}
	if chain, ok := item["x5c"].([]any); ok && len(chain) > 0 {
		encoded, _ := chain[0].(string)
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("not RSA")
		}
		return key, nil
	}
	return nil, errors.New("missing RSA material")
}

func (v *Verifier) getJSON(ctx context.Context, url string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	res, err := v.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return fmt.Errorf("GET %s: %s", url, res.Status)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(target)
}

func decodePart(part string, target any) error {
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}
func decodeAudience(raw json.RawMessage) ([]string, error) {
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []string{one}, nil
}
