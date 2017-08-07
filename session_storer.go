package auth

import (
	"errors"
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/qor/auth/claims"
	"github.com/qor/session"
)

// SessionStorerInterface session storer interface for Auth
type SessionStorerInterface interface {
	Get(req *http.Request) (*claims.Claims, error)
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

// Get get claims from request
func (sessionStorer *SessionStorer) Get(req *http.Request) (*claims.Claims, error) {
	tokenString := req.Header.Get("Authorization")

	// Get Token from Cookie
	if tokenString == "" {
		tokenString = sessionStorer.SessionManager.Get(req, sessionStorer.SessionName)
	}

	return sessionStorer.Validate(tokenString)
}

// Update update claims with session manager
func (sessionStorer *SessionStorer) Update(claims *claims.Claims, req *http.Request) error {
	return nil
}

// Delete delete claims from session manager
func (sessionStorer *SessionStorer) Delete(req *http.Request) error {
	return nil
}

// SignedToken generate signed token with Claims
func (sessionStorer *SessionStorer) SignedToken(claims *claims.Claims) string {
	token := jwt.NewWithClaims(sessionStorer.SigningMethod, claims)
	signedToken, _ := token.SignedString([]byte(sessionStorer.SignedString))

	return signedToken
}

// Validate validate auth token
func (sessionStorer *SessionStorer) Validate(tokenString string) (*claims.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &claims.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != sessionStorer.SigningMethod {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(sessionStorer.SignedString), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*claims.Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
