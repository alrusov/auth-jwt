package jwt

import (
	"errors"
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
		Secret          string          `toml:"secret"`
		LifetimeAccess  config.Duration `toml:"lifetime-access"`
		LifetimeRefresh config.Duration `toml:"lifetime-refresh"`
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
func (options *methodOptions) Check(cfg any) (err error) {
	msgs := misc.NewMessages()

	if options.Secret == "" {
		msgs.Add(`%s.checkConfig: secret parameter isn't defined"`, module)
	}

	//if options.LifetimeAccess <= 0 {
	//	msgs.Add(`%s.checkConfig: illegal lifetime-access"`, module)
	//}
	//
	//if options.LifetimeRefresh <= 0 {
	//	msgs.Add(`%s.checkConfig: illegal lifetime-refresh"`, module)
	//}

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
				"/tools/jwt/login":   "Get jwt access and refresh tokens. Body: {\"username\": <username>, \"password\": <password>}",
				"/tools/jwt/refresh": "Refresh jwt access and refresh tokens. Body: {\"refresh\": <refresh>}",
				"/tools/jwt/verify":  "verify jwt access or refresh tokens. Body: {\"token\": <token>}",
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

	if options.LifetimeAccess <= 0 {
		options.LifetimeAccess = config.JWTdefaultLifetimeAccess
	}

	if options.LifetimeRefresh <= 0 {
		options.LifetimeRefresh = config.JWTdefaultLifetimeRefresh
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
func (ah *AuthHandler) Check(id uint64, prefix string, path string, w http.ResponseWriter, r *http.Request) (identity *auth.Identity, tryNext bool, err error) {
	if ah.options.Secret == "" {
		return nil, true, nil
	}

	token := strings.SplitN(r.Header.Get(auth.Header), " ", 2)
	if len(token) != 2 || token[0] != method {
		return nil, true, nil
	}

	identity, err = CheckToken(token[1], "access", ah.options.Secret)
	if identity != nil {
		identity.Method = module
		return identity, false, nil
	}

	auth.Log.Message(log.INFO, `[%d] JWT login error: %s`, id, err.Error())

	return nil, false, err
}

//----------------------------------------------------------------------------------------------------------------------------//

// claims --
type claims struct {
	jwt.StandardClaims `json:"-"`
	User               string `json:"username"`
	Exp                int64  `json:"exp"`
	Type               string `json:"type"`
}

// Valid --
func (c claims) Valid(v *jwt.ValidationHelper) error {
	return nil
}

//----------------------------------------------------------------------------------------------------------------------------//

func CheckToken(tokenRaw, tokenType, secret string) (*auth.Identity, error) {

	keyFunc := func(t *jwt.Token) (any, error) {
		return []byte(secret), nil
	}

	claimsToken := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenRaw, claimsToken, keyFunc)

	if err != nil {
		return nil, err
	}

	tokenI, exists := claimsToken["type"]

	if !exists {
		return nil, errors.New(`The "type" claim is not found in the authorization header`)
	}

	token, _ := tokenI.(string)

	if token != tokenType {
		return nil, errors.New(fmt.Sprintf(`Token "type" is not %s`, tokenType))
	}

	ui, exists := claimsToken["username"]
	if !exists {
		return nil, errors.New(`The "username" claim is not found in the authorization header`)
	}

	u, _ := ui.(string)

	identity, err := auth.StdGetIdentity(u)
	if err != nil {
		return nil, err
	}

	if identity == nil {
		return nil, errors.New(fmt.Sprintf(`Unknown user "%s"`, u))
	}
	return identity, nil
}

// В теории является дубликатом CheckToken, не не знаю как лучше исправить
func ExtractToken(tokenRaw, secret string) (tokenType string, status bool, err error) {
	status = false
	keyFunc := func(t *jwt.Token) (any, error) {
		return []byte(secret), nil
	}

	claimsToken := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(tokenRaw, claimsToken, keyFunc)

	if err == nil {
		status = true
	} else {
		_, ok := err.(*jwt.TokenExpiredError)
		if !ok {
			return
		}
	}

	tokenI, exists := claimsToken["type"]

	if !exists {
		err = errors.New(`The "type" claim is not found in the authorization header`)
		return
	}

	tokenType, _ = tokenI.(string)

	if tokenType != "access" && tokenType != "refresh" {
		err = errors.New(fmt.Sprintf(`Unknown token "type" - %s`, tokenType))
		return
	}

	ui, exists := claimsToken["username"]
	if !exists {
		return "", false, errors.New(`The "username" claim is not found in the authorization header`)
	}

	u, _ := ui.(string)

	identity, err := auth.StdGetIdentity(u)
	if err != nil {
		return "", false, err
	}

	if identity == nil {
		return "", false, errors.New(fmt.Sprintf(`Unknown user "%s"`, u))
	}
	return
}
