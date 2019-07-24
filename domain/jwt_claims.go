package domain

import jwt "github.com/dgrijalva/jwt-go"

// JWTClaims .
type JWTClaims struct {
	User *User
	jwt.StandardClaims
}
