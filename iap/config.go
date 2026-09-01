package iap

import (
	"errors"
	"strings"
	"time"
)

type Config struct {
	Issuer       string
	Audience     string
	HTTPTimeout  time.Duration
	JWKSCacheTTL time.Duration
	ClockSkew    time.Duration
}

func (c Config) normalized() (Config, error) {
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	c.Audience = strings.TrimSpace(c.Audience)
	if c.Issuer == "" || c.Audience == "" {
		return Config{}, errors.New("iap: issuer and audience are required")
	}
	if c.HTTPTimeout == 0 {
		c.HTTPTimeout = 5 * time.Second
	}
	if c.JWKSCacheTTL == 0 {
		c.JWKSCacheTTL = 15 * time.Minute
	}
	if c.ClockSkew == 0 {
		c.ClockSkew = 30 * time.Second
	}
	return c, nil
}
