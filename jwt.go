package jwt

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go/v4"

	"github.com/alrusov/auth"
	"github.com/alrusov/config"
	"github.com/alrusov/jsonw"
	"github.com/alrusov/log"
	"github.com/alrusov/misc"
	"github.com/alrusov/stdhttp"
)

//----------------------------------------------------------------------------------------------------------------------------//

type (
	// AuthHandler --
	AuthHandler struct {
		http    *stdhttp.HTTP
		authCfg *config.Auth
		cfg     *config.AuthMethod
		options *methodOptions
	}

	methodOptions struct {
		Secret    string        `toml:"secret"`
		LifetimeS string        `toml:"lifetime"`
		Lifetime  time.Duration `toml:"-"`
	}
)

const (
	module = "jwt"
	method = "Bearer"
)

//----------------------------------------------------------------------------------------------------------------------------//

func init() {
	config.AddAuthMethod(module, &methodOptions{}, checkConfig)
}

func checkConfig(m *config.AuthMethod) (err error) {
	msgs := misc.NewMessages()

	options, ok := m.Options.(*methodOptions)
	if !ok {
		msgs.Add(`%s.checkConfig: Options is "%T", expected "%T"`, module, m.Options, options)
	}

	if !m.Enabled {
		return
	}

	if options.Secret == "" {
		msgs.Add(`%s.checkConfig: secret parameter isn't defined"`, module)
	}

	if options.Secret == "" {
		msgs.Add(`%s.checkConfig: secret parameter isn't defined"`, module)
	}

	err = msgs.Error()
	return
}

//----------------------------------------------------------------------------------------------------------------------------//

// Init --
func (ah *AuthHandler) Init(cfg *config.Listener) (err error) {
	ah.authCfg = nil
	ah.cfg = nil
	ah.options = nil

	if ah.http != nil {
		ah.http.AddHandler(ah, false)
		ah.http.AddEndpointsInfo(
			misc.StringMap{
				"/tools/jwt-login": "Get jwt token. Parameters: u=<username>, p=<password>, [json]",
			},
		)
	}

	methodCfg, exists := cfg.Auth.Methods[module]
	if !exists || !methodCfg.Enabled || methodCfg.Options == nil {
		return nil
	}

	options, ok := methodCfg.Options.(*methodOptions)
	if !ok {
		return fmt.Errorf(`options for module "%s" is "%T", expected "%T"`, module, methodCfg.Options, options)
	}

	if options.Secret == "" {
		return fmt.Errorf(`secret for module "%s" cannot be empty`, module)
	}

	options.Lifetime, err = misc.Interval2Duration(options.LifetimeS)
	if err != nil {
		return fmt.Errorf(`lifetime for "%s": %s`, module, err)
	}

	if options.Lifetime <= 0 {
		options.Lifetime = config.JWTdefaultLifetime
	}

	ah.authCfg = &cfg.Auth
	ah.cfg = methodCfg
	ah.options = options

	return nil
}

//----------------------------------------------------------------------------------------------------------------------------//

// Add --
func Add(http *stdhttp.HTTP) (err error) {
	return http.AddAuthHandler(
		&AuthHandler{
			http: http,
		},
	)
}

//----------------------------------------------------------------------------------------------------------------------------//

// Enabled --
func (ah *AuthHandler) Enabled() bool {
	return ah.cfg != nil && ah.cfg.Enabled
}

//----------------------------------------------------------------------------------------------------------------------------//

// Score --
func (ah *AuthHandler) Score() int {
	return ah.cfg.Score
}

//----------------------------------------------------------------------------------------------------------------------------//

// WWWAuthHeader --
func (ah *AuthHandler) WWWAuthHeader() (name string, withRealm bool) {
	return method, false
}

//----------------------------------------------------------------------------------------------------------------------------//

// Check --
func (ah *AuthHandler) Check(id uint64, prefix string, path string, w http.ResponseWriter, r *http.Request) (identity *auth.Identity, tryNext bool) {
	if ah.options.Secret == "" {
		return nil, true
	}

	var userDef config.User
	u := ""

	code, msg := func() (code int, msg string) {
		code = http.StatusNoContent
		msg = ""

		s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(s) != 2 || s[0] != method {
			return
		}

		code = http.StatusForbidden

		keyFunc := func(t *jwt.Token) (interface{}, error) {
			return []byte(ah.options.Secret), nil
		}

		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(s[1], claims, keyFunc)

		if err != nil {
			msg = err.Error()
			return
		}

		ui, exists := claims["username"]
		if !exists {
			msg = `The "username" claim is not found in the authorization header`
			return
		}

		u, _ = ui.(string)
		userDef, exists = ah.authCfg.Users[u]
		if !exists {
			msg = fmt.Sprintf(`Unknown user "%v"`, ui)
			return
		}

		code = http.StatusOK
		return
	}()

	if code == http.StatusOK {
		return &auth.Identity{
				Method: module,
				User:   u,
				Groups: userDef.Groups,
				Extra:  nil,
			},
			false
	}

	if code == http.StatusNoContent {
		return nil, true
	}

	auth.Log.Message(log.INFO, `[%d] JWT login error: %s`, id, msg)

	return nil, false
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

// claims --
type claims struct {
	jwt.StandardClaims `json:"-"`
	User               string `json:"username"`
	Exp                int64  `json:"exp"`
}

// Valid --
func (c claims) Valid(v *jwt.ValidationHelper) error {
	return nil
}

func MakeToken(user string, secret string, lifetime time.Duration) (token string, exp int64, err error) {
	now := time.Now()
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
