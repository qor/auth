package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/render"
	"github.com/qor/session"
	"github.com/qor/session/manager"
)

// Auth auth struct
type Auth struct {
	*Config
	providers []Provider
}

// Config auth config
type Config struct {
	DB                *gorm.DB
	SessionName       string
	Prefix            string
	Render            *render.Render
	SigningMethod     jwt.SigningMethod
	SignedString      string
	UserModel         interface{}
	AuthIdentityModel interface{}
	UserStorer        Storer
	SessionManager    session.ManagerInterface
	ViewPaths         []string

	LoginHandler    func(*Context, func(*Context) (*claims.Claims, error))
	RegisterHandler func(*Context, func(*Context) (*claims.Claims, error))
	LogoutHandler   func(*Context)
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
		config.SessionName = "_auth_session"
	}

	if config.AuthIdentityModel == nil {
		config.AuthIdentityModel = &auth_identity.AuthIdentity{}
	}

	if config.LoginHandler == nil {
		config.LoginHandler = DefaultLoginHandler
	}

	if config.RegisterHandler == nil {
		config.RegisterHandler = DefaultRegisterHandler
	}

	if config.LogoutHandler == nil {
		config.LogoutHandler = DefaultLogoutHandler
	}

	if config.UserStorer == nil {
		config.UserStorer = &UserStorer{}
	}

	if config.SessionManager == nil {
		config.SessionManager = manager.SessionManager
	}

	for _, viewPath := range config.ViewPaths {
		config.Render.RegisterViewPath(viewPath)
	}

	config.Render.RegisterViewPath("github.com/qor/auth/views")

	auth := &Auth{Config: config}

	return auth
}

// GetDB get db from request
func (auth *Auth) GetDB(request *http.Request) *gorm.DB {
	db := request.Context().Value("DB")
	if tx, ok := db.(*gorm.DB); ok {
		return tx
	}
	return auth.Config.DB
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
func (auth *Auth) SignedToken(claims *claims.Claims) string {
	// TODO
	// update based on configuration claims.ExpiresAt

	token := jwt.NewWithClaims(auth.SigningMethod, claims)
	signedToken, _ := token.SignedString([]byte(auth.SignedString))

	return signedToken
}

// Validate validate auth token
func (auth *Auth) Validate(tokenString string) (*claims.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &claims.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != auth.Config.SigningMethod {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(auth.Config.SignedString), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*claims.Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
