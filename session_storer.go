package auth

import (
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/qor/auth/claims"
	"github.com/qor/session"
)

// SessionStorerInterface session storer interface for Auth
type SessionStorerInterface interface {
	Get(req *http.Request) *claims.Claims
	Update(claims *claims.Claims, req *http.Request) error
	Delete(req *http.Request) error
}

// SessionStorer default session storer
type SessionStorer struct {
	SessionName    string
	SigningMethod  jwt.SigningMethod
	SignedString   string
	SessionManager session.ManagerInterface
}
