package jwt

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go/v4"

	"github.com/alrusov/auth"
	"github.com/alrusov/config"
	"github.com/alrusov/jsonw"
	"github.com/alrusov/log"
	"github.com/alrusov/misc"
)

//----------------------------------------------------------------------------------------------------------------------------//

//
func (ah *AuthHandler) Handler(id uint64, prefix string, path string, w http.ResponseWriter, r *http.Request) (processed bool) {

	switch path {
	case "/tools/jwt-login":
		processed = true
		GetToken(ah.http.Config(), id, path, w, r)
		return
	}

	return
}

//----------------------------------------------------------------------------------------------------------------------------//

// GetToken --
func GetToken(cfg *config.Listener, id uint64, path string, w http.ResponseWriter, r *http.Request) bool {
	queryParams := r.URL.Query()

	code, msg := func() (code int, msg string) {
		code = http.StatusForbidden
		msg = ""

		methodCfg, exists := cfg.Auth.Methods[module]
		if !exists || !methodCfg.Enabled || methodCfg.Options == nil {
			msg = `JWT auth is disabled`
			return
		}

		options, ok := methodCfg.Options.(*methodOptions)
		if !ok || options.Secret == "" {
			msg = fmt.Sprintf(`Method "%s" is misconfigured`, module)
			return
		}

		u := queryParams.Get("u")
		if u == "" {
			msg = `Empty username`
			return
		}
		p := queryParams.Get("p")

		userDef, exists := cfg.Auth.Users[u]
		if !exists || userDef.Password != string(auth.Hash([]byte(p), []byte(u))) {
			msg = fmt.Sprintf(`Illegal login or password for "%s"`, u)
			return
		}

		msg, _, err := MakeToken(u, options.Secret, options.Lifetime)
		if err != nil {
			msg = err.Error()
			return
		}

		code = http.StatusOK
		return
	}()

	tp := ""
	if code != http.StatusOK {
		tp = " error"
	}

	auth.Log.Message(log.DEBUG, `[%d] JWT token%s: %s`, id, tp, msg)

	_, exists := queryParams["json"]
	if exists {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		var v interface{}

		if code != http.StatusOK {
			v = struct {
				Error string `json:"error"`
			}{
				Error: msg,
			}
		} else {
			v = struct {
				Token string `json:"token"`
			}{
				Token: msg,
			}
		}

		data, _ := jsonw.Marshal(v)
		w.Write(data)
		return false
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(code)
	w.Write([]byte(msg))

	return false
}

//----------------------------------------------------------------------------------------------------------------------------//

func MakeToken(user string, secret string, lifetime time.Duration) (token string, exp int64, err error) {
	now := misc.NowUTC()
	expT := now.Add(lifetime)
	exp = expT.Unix()

	claims := claims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: jwt.At(expT),
			IssuedAt:  jwt.At(now),
		},
		User: user,
		Exp:  exp,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err = t.SignedString([]byte(secret))
	if err != nil {
		return
	}

	return
}

//----------------------------------------------------------------------------------------------------------------------------//
