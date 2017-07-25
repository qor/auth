package database

import (
	"strings"

	"github.com/qor/auth"
	"github.com/qor/auth/claims"
	"github.com/qor/auth/database/encryptor"
	"github.com/qor/auth/database/encryptor/bcrypt_encryptor"
)

// Config database config
type Config struct {
	Confirmable         bool
	ConfirmMailer       func(email string, context *auth.Context, claims *claims.Claims, currentUser interface{}) error
	ResetPasswordMailer func(email string, context *auth.Context, claims *claims.Claims, currentUser interface{}) error
	Encryptor           encryptor.Interface
	AuthorizeHandler    func(*auth.Context) (*claims.Claims, error)
	RegisterHandler     func(*auth.Context) (*claims.Claims, error)
	ConfirmHandler      func(*auth.Context) error
}

// New initialize database provider
func New(config *Config) *Provider {
	if config == nil {
		config = &Config{}
	}

	if config.Encryptor == nil {
		config.Encryptor = bcrypt_encryptor.New(&bcrypt_encryptor.Config{})
	}

	if config.ConfirmMailer == nil {
		config.ConfirmMailer = DefaultConfirmationMailer
	}

	if config.ResetPasswordMailer == nil {
		config.ResetPasswordMailer = DefaultResetPasswordMailer
	}

	provider := &Provider{Config: config}

	if config.AuthorizeHandler == nil {
		config.AuthorizeHandler = DefaultAuthorizeHandler
	}

	if config.RegisterHandler == nil {
		config.RegisterHandler = DefaultRegisterHandler
	}

	return provider
}

// Provider provide login with database method
type Provider struct {
	*Config
}

// GetName return provider name
func (Provider) GetName() string {
	return "database"
}

// Login implemented login with database provider
func (provider Provider) Login(context *auth.Context) {
	context.Auth.LoginHandler(context, provider.AuthorizeHandler)
}

// Register implemented register with database provider
func (provider Provider) Register(context *auth.Context) {
	context.Auth.RegisterHandler(context, provider.RegisterHandler)
}

// Logout implemented logout with database provider
func (provider Provider) Logout(context *auth.Context) {
	context.Auth.LogoutHandler(context)
}

// Callback implement Callback with database provider
func (provider Provider) Callback(context *auth.Context) {
}

// ServeHTTP implement ServeHTTP with database provider
func (provider Provider) ServeHTTP(context *auth.Context) {
	var (
		req     = context.Request
		reqPath = strings.TrimPrefix(req.URL.Path, context.Auth.Prefix)
		paths   = strings.Split(reqPath, "/")
	)

	if len(paths) >= 2 {
		// eg: /database/confirm
		switch paths[1] {
		case "confirm":
			provider.ConfirmHandler(context)
		case "password":
			if len(paths) >= 3 {
				switch paths[2] {
				case "new":
					context.Auth.Config.Render.Execute("auth/password/new", context, context.Request, context.Writer)
				default:
					return
				}
			}
			provider.ResetPasswordMailer(context)
		}
		return
	}
}
