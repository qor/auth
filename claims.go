package auth

import jwt "github.com/dgrijalva/jwt-go"

type Claims struct {
	Type     string `json:"typ,omitempty"`
	Username string `json:"username,omitempty"`
	jwt.StandardClaims
}
