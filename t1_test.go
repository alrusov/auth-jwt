package jwt

import (
	"fmt"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/alrusov/auth"
	"github.com/alrusov/config"
	"github.com/alrusov/misc"
)

//----------------------------------------------------------------------------------------------------------------------------//

func Test1(t *testing.T) {
	user := "TestUser"

	secret := "tOpSeCrEt-123"
	lifetime := 3 * time.Hour
	score := 10

	cfg := &config.Listener{
		Auth: config.Auth{
			Users: map[string]config.User{
				user: {
					Password: "***",
				},
			},
			Methods: map[string]*config.AuthMethod{
				module: {
					Enabled: true,
					Score:   score,
					Options: &methodOptions{
						Secret:          secret,
						LifetimeAccess:  config.Duration(lifetime),
						LifetimeRefresh: config.Duration(lifetime),
					},
				},
			},
		},
	}

	auth.AddStdIdentityProvider(&auth.LocalIdentityProvider{}, &cfg.Auth)

	ah := &AuthHandler{}

	err := ah.Init(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if !ah.Enabled() {
		t.Fatalf("method disabled")
	}

	mScore := ah.Score()
	if mScore != score {
		t.Fatalf("got score %d, expected %d", mScore, score)
	}

	mAuthHeader, mWithRealm := ah.WWWAuthHeader()
	if mAuthHeader != method {
		t.Fatalf(`got header "%s", expected "%s"`, mAuthHeader, method)
	}
	if mWithRealm {
		t.Fatalf(`got withRealm "%v", expected "%v"`, mWithRealm, false)
	}

	token, _, exp, err := MakeTokens(user, secret, lifetime, lifetime)
	if err != nil {
		t.Fatal(err)
	}

	exp0 := misc.NowUnix() + int64(lifetime.Seconds())
	if math.Abs(float64(exp-exp0)) > 2 {
		t.Fatalf("exp got %d, expected about %d", exp, exp0)
	}

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	r.Header.Set(auth.Header, fmt.Sprintf("Bearer %s", token))

	identity, _, err := ah.Check(0, "", "/", nil, r)

	if err != nil {
		t.Fatal(err)
	}

	if identity == nil {
		t.Fatalf("authorization failed")
	}

	if identity.User != user {
		t.Fatalf(`got user "%s", expected "%s"`, identity.User, user)
	}

	fmt.Println(token)
}

//----------------------------------------------------------------------------------------------------------------------------//
