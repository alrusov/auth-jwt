package jwt

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go/v4"

	"github.com/alrusov/auth"
	"github.com/alrusov/config"
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
		Secret   string          `toml:"secret"`
		Lifetime config.Duration `toml:"lifetime"`
	}
)

const (
	module = "jwt"
	method = "Bearer"
)

//----------------------------------------------------------------------------------------------------------------------------//

// Автоматическая регистрация при запуске приложения
func init() {
	config.AddAuthMethod(module, &methodOptions{})
}

// Проверка валидности дополнительных опций метода
func (options *methodOptions) Check(cfg interface{}) (err error) {
	msgs := misc.NewMessages()

	if options.Secret == "" {
		msgs.Add(`%s.checkConfig: secret parameter isn't defined"`, module)
	}

	if options.Lifetime <= 0 {
		msgs.Add(`%s.checkConfig: illegal lifetime"`, module)
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
		return fmt.Errorf(`options for module "%s" is "%T", "%T" expected`, module, methodCfg.Options, options)
	}

	if options.Secret == "" {
		return fmt.Errorf(`secret for module "%s" cannot be empty`, module)
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

//----------------------------------------------------------------------------------------------------------------------------//
