package rpcutils

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/signatory-io/signatory-core/logger"
)

func constantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

type UserData struct {
	Password   string    `yaml:"password"`
	Exp        uint64    `yaml:"jwt_exp"`
	Secret     string    `yaml:"secret"`
	OldCredExp string    `yaml:"old_cred_exp,omitempty"`
	NewData    *UserData `yaml:"new_data"`
}

type JWT struct {
	Users map[string]UserData `yaml:"users"`
	mu    sync.RWMutex        `yaml:"-"`
}

func (j *JWT) SetNewCred(user string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if u, ok := j.Users[user]; ok {
		if u.NewData != nil {
			u.Password = u.NewData.Password
			u.Secret = u.NewData.Secret
			u.Exp = u.NewData.Exp
			u.NewData = nil
			j.Users[user] = u
		}
		return nil
	}
	return fmt.Errorf("JWT: user not found")
}

func (j *JWT) GetUserData(user string) (*UserData, bool) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	if u, ok := j.Users[user]; ok {
		return &u, true
	}
	return nil, false
}

func (j *JWT) GenerateToken(user string, pass string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user"] = user
	ud, ok := j.GetUserData(user)
	if !ok {
		return "", fmt.Errorf("JWT: user not found")
	}
	if !constantTimeCompare(pass, ud.Password) {
		ud = ud.NewData
	}
	if ud == nil {
		return "", fmt.Errorf("JWT: invalid credentials")
	}
	if ud.Exp == 0 {
		ud.Exp = 60
	}
	claims["exp"] = time.Now().Add(time.Minute * time.Duration(ud.Exp)).Unix()
	token.Claims = claims
	return token.SignedString([]byte(ud.Secret))
}

func (j *JWT) Authenticate(user string, token string) (string, error) {
	if user == "" {
		claims := jwt.MapClaims{}
		parser := jwt.NewParser()
		_, _, err := parser.ParseUnverified(token, claims)
		if err != nil {
			return "", fmt.Errorf("JWT: %w", err)
		}
		if u, ok := claims["user"].(string); ok {
			user = u
		} else {
			return "", fmt.Errorf("JWT: missing user claim")
		}
	}

	ud, ok := j.GetUserData(user)
	if !ok {
		return "", fmt.Errorf("JWT: user not found")
	}

	tok, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(ud.Secret), nil
	})
	if err != nil {
		if ud.NewData != nil {
			tok, err = jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
				return []byte(ud.NewData.Secret), nil
			})
			if err != nil {
				return "", err
			}
		} else {
			return "", err
		}
	}

	if tu := tok.Claims.(jwt.MapClaims)["user"]; tu != nil {
		if tu.(string) != user {
			return "", fmt.Errorf("JWT: token user mismatch")
		}
	} else {
		return "", fmt.Errorf("JWT: invalid token")
	}
	if _, ok := tok.Claims.(jwt.MapClaims); ok && tok.Valid {
		return tok.Claims.(jwt.MapClaims)["user"].(string), nil
	}
	return "", fmt.Errorf("JWT: invalid token")
}

func (j *JWT) CheckUpdateNewCred(log logger.Logger) error {
	j.mu.RLock()
	snapshot := make(map[string]UserData, len(j.Users))
	for k, v := range j.Users {
		snapshot[k] = v
	}
	j.mu.RUnlock()

	for user, data := range snapshot {
		if err := validateSecretAndPass([]string{data.Password, data.Secret}); err != nil {
			return fmt.Errorf("JWT: config validation failed for user %s: %w", user, err)
		}

		if data.NewData == nil {
			continue
		}

		if constantTimeCompare(data.NewData.Password, data.Password) || constantTimeCompare(data.NewData.Secret, data.Secret) {
			return fmt.Errorf("JWT: new credentials are same as old for user %s", user)
		}
		if err := validateSecretAndPass([]string{data.NewData.Password, data.NewData.Secret}); err != nil {
			return fmt.Errorf("JWT: config validation failed for new credentials of user %s: %w", user, err)
		}

		if data.OldCredExp == "" {
			if err := j.SetNewCred(user); err != nil {
				return fmt.Errorf("JWT: failed to set new credentials for %s: %w", user, err)
			}
			log.Infof("JWT: Applied new credentials for user %s", user)
			continue
		}

		t, err := time.Parse("2006-01-02 15:04:05", data.OldCredExp)
		if err != nil {
			return fmt.Errorf("JWT: invalid old_cred_exp format for user %s: %w", user, err)
		}

		duration := time.Until(t)
		if duration <= 0 {
			if err := j.SetNewCred(user); err != nil {
				return fmt.Errorf("JWT: failed to set new credentials for %s: %w", user, err)
			}
			log.Infof("JWT: Applied new credentials for user %s (expiry passed)", user)
			continue
		}

		log.Infof("JWT: Scheduled credential rotation for user %s in %v", user, duration)
		go func(u string, d time.Duration) {
			time.Sleep(d)
			if err := j.SetNewCred(u); err != nil {
				log.Errorf("JWT: Failed to rotate credentials for %s: %v", u, err)
			} else {
				log.Infof("JWT: Rotated credentials for user %s", u)
			}
		}(user, duration)
	}
	return nil
}

func validateSecretAndPass(secret []string) error {
	length := 16
	stype := "password"
	for _, s := range secret {
		if len(s) < length {
			return fmt.Errorf("%s should be at least %d characters", stype, length)
		}
		hasUppercase := false
		for _, c := range s {
			if c >= 'A' && c <= 'Z' {
				hasUppercase = true
				break
			}
		}
		if !hasUppercase {
			return fmt.Errorf("%s should contain at least one uppercase character", stype)
		}

		hasLowercase := false
		for _, c := range s {
			if c >= 'a' && c <= 'z' {
				hasLowercase = true
				break
			}
		}
		if !hasLowercase {
			return fmt.Errorf("%s should contain at least one lowercase character", stype)
		}

		hasDigit := false
		for _, c := range s {
			if c >= '0' && c <= '9' {
				hasDigit = true
				break
			}
		}
		if !hasDigit {
			return fmt.Errorf("%s should contain at least one digit", stype)
		}

		hasSpecialChar := false
		for _, c := range s {
			if c >= 32 && c <= 126 && !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
				hasSpecialChar = true
				break
			}
		}
		if !hasSpecialChar {
			return fmt.Errorf("%s should contain at least one special character", stype)
		}
		length = 32
		stype = "secret"
	}
	return nil
}

type jwtContextKey struct{}

func JWTAuthMiddleware(j *JWT, exempt []string, next http.Handler) http.Handler {
	if j == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range exempt {
			if r.URL.Path == p {
				next.ServeHTTP(w, r)
				return
			}
		}

		token := r.Header.Get("Authorization")
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("token required"))
			return
		}
		token = strings.TrimPrefix(token, "Bearer ")

		user := r.Header.Get("username")
		u, err := j.Authenticate(user, token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		}
		ctx := context.WithValue(r.Context(), jwtContextKey{}, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func JWTUser(ctx context.Context) (string, bool) {
	u, ok := ctx.Value(jwtContextKey{}).(string)
	return u, ok
}

func LoginHandler(j *JWT) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Header.Get("username")
		pass := r.Header.Get("password")
		if user == "" || pass == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("username and password required"))
			return
		}

		ud, ok := j.GetUserData(user)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Access denied"))
			return
		}
		if !constantTimeCompare(ud.Password, pass) {
			if ud.NewData != nil {
				if !constantTimeCompare(ud.NewData.Password, pass) {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("Access denied"))
					return
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Access denied"))
				return
			}
		}

		token, err := j.GenerateToken(user, pass)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(token))
	}
}
