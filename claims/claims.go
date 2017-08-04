package claims

import (
	jwt "github.com/dgrijalva/jwt-go"
)

// Claims auth claims
type Claims struct {
	Provider string `json:"provider,omitempty"`
	UserID   string `json:"userid,omitempty"`
	jwt.StandardClaims
}

// ToClaims implement ClaimerInterface
func (claims *Claims) ToClaims() *Claims {
	return claims
}

// ClaimerInterface claimer interface
type ClaimerInterface interface {
	ToClaims() *Claims
}
