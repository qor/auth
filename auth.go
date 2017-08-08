package auth

import (
	"fmt"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/mailer"
	"github.com/qor/redirect_back"
	"github.com/qor/render"
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
	UserModel         interface{}
	AuthIdentityModel interface{}
	URLPrefix         string
	ViewPaths         []string

	Render        *render.Render
	Mailer        *mailer.Mailer
	UserStorer    UserStorerInterface
	SessionStorer SessionStorerInterface
	Redirector    RedirectorInterface

	LoginHandler    func(*Context, func(*Context) (*claims.Claims, error))
	RegisterHandler func(*Context, func(*Context) (*claims.Claims, error))
	LogoutHandler   func(*Context)
}

// New initialize Auth
func New(config *Config) *Auth {
	if config == nil {
		config = &Config{}
	}

	if config.Render == nil {
		config.Render = render.New()
	}

	if config.URLPrefix == "" {
		config.URLPrefix = "/auth/"
	} else {
		config.URLPrefix = fmt.Sprintf("/%v/", strings.Trim(config.URLPrefix, "/"))
	}

	if config.AuthIdentityModel == nil {
		config.AuthIdentityModel = &auth_identity.AuthIdentity{}
	}

	if config.Redirector == nil {
		config.Redirector = &Redirector{redirect_back.New(&redirect_back.Config{
			SessionManager:  manager.SessionManager,
			IgnoredPrefixes: []string{config.URLPrefix},
		})}
	}

	if config.SessionStorer == nil {
		config.SessionStorer = &SessionStorer{
			SessionName:    "_auth_session",
			SessionManager: manager.SessionManager,
			SigningMethod:  jwt.SigningMethodHS256,
		}
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

	for _, viewPath := range config.ViewPaths {
		config.Render.RegisterViewPath(viewPath)
	}

	config.Render.RegisterViewPath("github.com/qor/auth/views")

	auth := &Auth{Config: config}

	return auth
}
