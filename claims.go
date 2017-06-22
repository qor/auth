package auth

import jwt "github.com/dgrijalva/jwt-go"

type Claims struct {
	Provider string `json:"provider,omitempty"`
	UserID   string `json:"userid,omitempty"`
	jwt.StandardClaims
}
