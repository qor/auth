package auth

import jwt "github.com/dgrijalva/jwt-go"

type Claims struct {
	Provider string `json:"provider,omitempty"`
	Username string `json:"username,omitempty"`
	jwt.StandardClaims
}
