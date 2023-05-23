package jwt

import (
	"encoding/json"
	"errors"
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

type UserData struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type JsonError struct {
	Error string `json:"error"`
}

type JWTTokens struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

type TokenVerify struct {
	Token string `json:"token"`
}

type TokenVerifyStatus struct {
	Type   string `json:"type"`
	Status bool   `json:"status"`
}

//----------------------------------------------------------------------------------------------------------------------------//

func (ah *AuthHandler) Handler(id uint64, prefix string, path string, w http.ResponseWriter, r *http.Request) (processed bool) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
	switch path {
	case "/tools/jwt/login":
		processed = true
		GetToken(ah.http.Config(), id, path, w, r)
		return
	case "/tools/jwt/refresh":
		processed = true
		RefreshToken(ah.http.Config(), id, path, w, r)
	case "/tools/jwt/verify":
		processed = true
		VerifyToken(ah.http.Config(), id, path, w, r)
	}

	return
}

//----------------------------------------------------------------------------------------------------------------------------//

// GetToken --
func GetToken(cfg *config.Listener, id uint64, path string, w http.ResponseWriter, r *http.Request) bool {

	userData := UserData{}
	_ = json.NewDecoder(r.Body).Decode(&userData)

	access, refresh, err := getToken(cfg, userData)

	var code int
	var result any

	if err == nil {
		auth.Log.Message(log.DEBUG, `[%d] JWT token_access: %s`, id, access)
		auth.Log.Message(log.DEBUG, `[%d] JWT token_refresh: %s`, id, refresh)
		code = http.StatusOK
		result = JWTTokens{Access: access, Refresh: refresh}
	} else {
		auth.Log.Message(log.DEBUG, `[%d] JWT token_%s: %s`, id, "error", err.Error())
		code = http.StatusForbidden
		result = JsonError{Error: err.Error()}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)

	data, _ := jsonw.Marshal(result)
	w.Write(data)
	return false
}

func getToken(cfg *config.Listener, userData UserData) (access, refresh string, err error) {

	options, err := getOptions(cfg)

	if err != nil {
		return
	}

	if userData.Username == "" {
		err = errors.New("Empty username")
		return
	}

	userDef, exists := cfg.Auth.Users[userData.Username]
	if !exists || userDef.Password != string(auth.Hash([]byte(userData.Password), []byte(userData.Username))) {
		err = errors.New(fmt.Sprintf(`Illegal login or password for "%s"`, userData.Username))
		return
	}

	access, refresh, _, err = MakeTokens(userData.Username, options.Secret, options.LifetimeAccess.D(), options.LifetimeRefresh.D())
	if err != nil {
		return
	}

	return
}

//----------------------------------------------------------------------------------------------------------------------------//

func MakeTokens(username string, secret string, lifetimeAccess, lifetimeRefresh time.Duration) (access, refresh string, exp int64, err error) {
	now := misc.NowUTC()
	expAccess := now.Add(lifetimeAccess)
	expRefresh := now.Add(lifetimeRefresh)
	exp = expAccess.Unix()
	access, err = CreateToken(username, secret, "access", now, expAccess)

	if err != nil {
		return
	}

	refresh, err = CreateToken(username, secret, "refresh", now, expRefresh)

	if err != nil {
		return
	}

	return
}

//----------------------------------------------------------------------------------------------------------------------------//

func CreateToken(username string, secret string, tokenType string, now, exp time.Time) (token string, err error) {
	claims := claims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: jwt.At(exp),
			IssuedAt:  jwt.At(now),
		},
		User: username,
		Exp:  exp.Unix(),
		Type: tokenType,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString([]byte(secret))
}

//----------------------------------------------------------------------------------------------------------------------------//

func RefreshToken(cfg *config.Listener, id uint64, path string, w http.ResponseWriter, r *http.Request) bool {

	token := JWTTokens{}
	_ = json.NewDecoder(r.Body).Decode(&token)

	access, refresh, err := refreshToken(cfg, token)

	var code int
	var result any

	if err == nil {
		auth.Log.Message(log.DEBUG, `[%d] JWT refresh token_access: %s`, id, access)
		auth.Log.Message(log.DEBUG, `[%d] JWT refresh token_refresh: %s`, id, refresh)
		code = http.StatusOK
		result = JWTTokens{Access: access, Refresh: refresh}
	} else {
		auth.Log.Message(log.DEBUG, `[%d] JWT refresh token_%s: %s`, id, "error", err.Error())
		code = http.StatusForbidden
		result = JsonError{Error: err.Error()}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)

	data, _ := jsonw.Marshal(result)
	w.Write(data)
	return false
}

func refreshToken(cfg *config.Listener, token JWTTokens) (access, refresh string, err error) {

	options, err := getOptions(cfg)

	if err != nil {
		return
	}

	if token.Refresh == "" {
		err = errors.New("Empty refresh field")
		return
	}

	identity, err := CheckToken(token.Refresh, "refresh", options.Secret)

	if err != nil {
		return
	}

	access, refresh, _, err = MakeTokens(identity.User, options.Secret, options.LifetimeAccess.D(), options.LifetimeRefresh.D())

	return

}

//----------------------------------------------------------------------------------------------------------------------------//

func VerifyToken(cfg *config.Listener, id uint64, path string, w http.ResponseWriter, r *http.Request) bool {

	token := TokenVerify{}
	_ = json.NewDecoder(r.Body).Decode(&token)

	tokenType, status, err := verifyToken(cfg, token)

	var code int
	var result any

	if err == nil {
		auth.Log.Message(log.DEBUG, `[%d] JWT verify token_%s: %s status: %s'`, id, tokenType, token.Token, status)
		code = http.StatusOK
		result = TokenVerifyStatus{Type: tokenType, Status: status}
	} else {
		auth.Log.Message(log.DEBUG, `[%d] JWT verify token_error: %s`, id, err.Error())
		code = http.StatusForbidden
		result = JsonError{Error: err.Error()}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)

	data, _ := jsonw.Marshal(result)
	w.Write(data)
	return false
}

func verifyToken(cfg *config.Listener, token TokenVerify) (tokenType string, status bool, err error) {

	options, err := getOptions(cfg)

	if err != nil {
		return
	}

	if token.Token == "" {
		err = errors.New("Empty token field")
		return
	}

	tokenType, status, err = ExtractToken(token.Token, options.Secret)

	if err != nil {
		return
	}

	return
}

func getOptions(cfg *config.Listener) (*methodOptions, error) {
	methodCfg, exists := cfg.Auth.Methods[module]
	if !exists || !methodCfg.Enabled || methodCfg.Options == nil {
		return nil, errors.New("JWT auth is disabled")
	}

	options, ok := methodCfg.Options.(*methodOptions)
	if !ok || options.Secret == "" {
		return nil, errors.New(fmt.Sprintf(`Method "%s" is misconfigured`, module))
	}
	return options, nil
}
