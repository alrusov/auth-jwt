package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/alrusov/auth"
	"github.com/alrusov/config"
	"github.com/alrusov/misc"
)

//----------------------------------------------------------------------------------------------------------------------------//

type anyUserProvider struct{}

func (p *anyUserProvider) Init(aCfg *config.Auth) error { return nil }
func (p *anyUserProvider) GetIdentity(u string) (*auth.Identity, error) {
	return &auth.Identity{User: u}, nil
}
func (p *anyUserProvider) Check(u string, pwd string, hashed bool) (*auth.Identity, bool, error) {
	return nil, false, nil
}

func TestCheckTokenAlgAndExp(t *testing.T) {
	if err := auth.AddStdIdentityProvider(&anyUserProvider{}, &config.Auth{}); err != nil {
		t.Fatal(err)
	}

	secret := "test-secret"
	now := misc.NowUTC()

	sign := func(m jwt.SigningMethod, c jwt.MapClaims) string {
		s, err := jwt.NewWithClaims(m, c).SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	good, err := CreateToken("u1", secret, "access", now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		token string
		ok    bool
	}{
		{"HS256 with exp", good, true},
		{"HS512, same secret", sign(jwt.SigningMethodHS512, jwt.MapClaims{"username": "u1", "type": "access", "exp": now.Add(time.Hour).Unix()}), false},
		{"no exp", sign(jwt.SigningMethodHS256, jwt.MapClaims{"username": "u1", "type": "access"}), false},
		{"expired", sign(jwt.SigningMethodHS256, jwt.MapClaims{"username": "u1", "type": "access", "exp": now.Add(-time.Hour).Unix()}), false},
		{"wrong secret", func() string {
			s, _ := CreateToken("u1", "other", "access", now, now.Add(time.Hour))
			return s
		}(), false},
	}

	for _, c := range cases {
		identity, err := CheckToken(c.token, "access", secret)
		if c.ok && (err != nil || identity == nil || identity.User != "u1") {
			t.Errorf(`%s: expected success, got %v %v`, c.name, identity, err)
		}
		if !c.ok && err == nil {
			t.Errorf(`%s: expected error`, c.name)
		}
	}

	if _, status, err := ExtractToken(cases[2].token, secret); status || err == nil {
		t.Errorf(`ExtractToken without exp: expected error, got %v %v`, status, err)
	}

	// /tools/jwt/verify: просроченный - не ошибка, status = false; действующий - status = true; HS512 - ошибка
	if tp, status, err := ExtractToken(cases[3].token, secret); status || err != nil || tp != "access" {
		t.Errorf(`ExtractToken expired: %q %v %v`, tp, status, err)
	}
	if tp, status, err := ExtractToken(good, secret); !status || err != nil || tp != "access" {
		t.Errorf(`ExtractToken good: %q %v %v`, tp, status, err)
	}
	if _, _, err := ExtractToken(cases[1].token, secret); err == nil {
		t.Errorf(`ExtractToken HS512: expected error`)
	}
}

//----------------------------------------------------------------------------------------------------------------------------//

// Токен содержит прежние ключи (username, type, exp - целое число секунд) и iat
func TestCreateTokenClaims(t *testing.T) {
	now := time.Unix(1764000000, 0).UTC()
	s, err := CreateToken("u1", "test-secret", "refresh", now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	c := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(s, c); err != nil {
		t.Fatal(err)
	}

	if c["username"] != "u1" || c["type"] != "refresh" || c["exp"] != float64(now.Add(time.Hour).Unix()) || c["iat"] != float64(now.Unix()) {
		t.Errorf(`claims: %v`, c)
	}
}

//----------------------------------------------------------------------------------------------------------------------------//
