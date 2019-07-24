package auth

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lehoangthienan/Library/domain"
)

// GenerateToken .
func GenerateToken(user *domain.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, domain.JWTClaims{
		User:           user,
		StandardClaims: jwt.StandardClaims{ExpiresAt: time.Now().Add(time.Hour).Unix()},
	})

	// Sign and get the complete encoded token as a string using the secret
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

func validateToken(tokenString string) (*domain.JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*domain.JWTClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("Invalid token")
}

func getResolversNotAuth() map[string][]string {
	return map[string][]string{
		"mutation": []string{"login", "signup"},
	}
}

// MiddlewareJWT .
func MiddlewareJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// read body
		b, _ := ioutil.ReadAll(r.Body)
		r.Body.Close()
		r.Body = ioutil.NopCloser(bytes.NewBuffer(b))

		body := string(b)
		body = strings.Replace(body, " ", "", -1)
		body = strings.Replace(body, `\n`, "", -1)
		body = strings.Replace(body, `\r`, "", -1)
		body = body[10:]

		// define no auth resolver
		resolversNotAuth := getResolversNotAuth()
		for t, resolvers := range resolversNotAuth {
			for _, resolver := range resolvers {
				check := t + "{" + resolver
				if body[:len(check)] == check {
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		// auth
		tokenString := r.Header.Get("Authorization")
		if len(tokenString) > 7 {
			tokenString = tokenString[7:]
		}
		claims, err := validateToken(tokenString)
		if err != nil {
			http.Error(w, "Require auth", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "token_info", claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAuth .
func RequireAuth(ctx context.Context) (*domain.JWTClaims, error) {
	claims := ctx.Value("token_info").(*domain.JWTClaims)
	if claims == nil {
		return nil, errors.New("Require auth")
	}
	return claims, nil
}
