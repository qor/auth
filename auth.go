package auth

import (
	"errors"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
)

type Auth struct {
	*Config
	providers map[string]Provider
}

type Config struct {
	SigningMethod jwt.SigningMethod
	SignedString  string
}

func New(config *Config) *Auth {
	if config == nil {
		config = &Config{}
	}

	if config.SigningMethod == nil {
		config.SigningMethod = jwt.SigningMethodHS256
	}

	return &Auth{Config: config}
}

// RegisterProvider register auth provider
func (auth *Auth) RegisterProvider(name string, provider Provider) {
	auth.providers[name] = provider
}

// GetProvider get provider with name
func (auth *Auth) GetProvider(name string) Provider {
	return auth.providers[name]
}

// SignedToken generate signed token with Claims
func (auth *Auth) SignedToken(claims *Claims) string {
	// TODO
	// update based on configuration claims.ExpiresAt

	token := jwt.NewWithClaims(auth.SigningMethod, claims)
	signedToken, _ := token.SignedString([]byte(auth.SignedString))

	return signedToken
}

// Validate validate auth token
func (auth *Auth) Validate(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != auth.Config.SigningMethod {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(auth.Config.SignedString), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
