package claims

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// Claims auth claims
type Claims struct {
	Provider                             string         `json:"provider,omitempty"`
	UserID                               string         `json:"userid,omitempty"`
	LastAuthTime                         *time.Time     `json:"auth_time,omitempty"`
	LastActivityTime                     *time.Time     `json:"activity_time,omitempty"`
	LongestDistractionTimeSinceLastLogin *time.Duration `json:"longest_distraction,omitempty"`
	LoggedAs                             []string       `json:"logged_as,omitempty"`
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
