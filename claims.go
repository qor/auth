package auth

import jwt "github.com/dgrijalva/jwt-go"

type Claims struct {
	Username string `json:"username,omitempty"`
	jwt.StandardClaims
}
