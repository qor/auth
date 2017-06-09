package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/qor/render"
)

type Auth struct {
	*Config
	providers []Provider
}

type Config struct {
	SessionName   string
	Prefix        string
	Render        *render.Render
	SigningMethod jwt.SigningMethod
	SignedString  string

	LoginHandler    func(request *http.Request, writer http.ResponseWriter, currentUser interface{}, claims *Claims)
	LogoutHandler   func(request *http.Request, writer http.ResponseWriter, currentUser interface{}, claims *Claims)
	RegisterHandler func(request *http.Request, writer http.ResponseWriter, currentUser interface{}, claims *Claims)
}

// New initialize Auth
func New(config *Config) *Auth {
	if config == nil {
		config = &Config{}
	}

	if config.SigningMethod == nil {
		config.SigningMethod = jwt.SigningMethodHS256
	}

	if config.Render == nil {
		config.Render = render.New()
	}

	if config.Prefix == "" {
		config.Prefix = "/auth/"
	} else {
		config.Prefix = fmt.Sprintf("/%v/", strings.Trim(config.Prefix, "/"))
	}

	if config.SessionName == "" {
		config.SessionName = "_session"
	}

	config.Render.RegisterViewPath("github.com/qor/auth/views")

	auth := &Auth{Config: config}

	return auth
}

// RegisterProvider register auth provider
func (auth *Auth) RegisterProvider(provider Provider) {
	name := provider.GetName()
	for _, p := range auth.providers {
		if p.GetName() == name {
			fmt.Printf("warning: auth provider %v already registered", name)
			return
		}
	}

	provider.ConfigAuth(auth)
	auth.providers = append(auth.providers, provider)
}

// GetProviders return registered providers
func (auth *Auth) GetProviders() (providers []Provider) {
	for _, provider := range auth.providers {
		providers = append(providers, provider)
	}
	return
}

// GetProvider get provider with name
func (auth *Auth) GetProvider(name string) Provider {
	for _, provider := range auth.providers {
		if provider.GetName() == name {
			return provider
		}
	}
	return nil
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
