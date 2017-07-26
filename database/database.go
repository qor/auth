package database

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/qor/auth"
	"github.com/qor/auth/claims"
	"github.com/qor/auth/database/encryptor"
	"github.com/qor/auth/database/encryptor/bcrypt_encryptor"
	"github.com/qor/session"
)

// Config database config
type Config struct {
	Confirmable          bool
	ConfirmMailer        func(email string, context *auth.Context, claims *claims.Claims, currentUser interface{}) error
	ConfirmHandler       func(*auth.Context) error
	ResetPasswordMailer  func(email string, context *auth.Context, claims *claims.Claims, currentUser interface{}) error
	ResetPasswordHandler func(*auth.Context) error
	Encryptor            encryptor.Interface
	AuthorizeHandler     func(*auth.Context) (*claims.Claims, error)
	RegisterHandler      func(*auth.Context) (*claims.Claims, error)
}

// New initialize database provider
func New(config *Config) *Provider {
	if config == nil {
		config = &Config{}
	}

	if config.Encryptor == nil {
		config.Encryptor = bcrypt_encryptor.New(&bcrypt_encryptor.Config{})
	}

	provider := &Provider{Config: config}

	if config.ConfirmMailer == nil {
		config.ConfirmMailer = DefaultConfirmationMailer
	}

	if config.ConfirmHandler == nil {
		config.ConfirmHandler = DefaultConfirmHandler
	}

	if config.ResetPasswordMailer == nil {
		config.ResetPasswordMailer = DefaultResetPasswordMailer
	}

	if config.ResetPasswordHandler == nil {
		config.ResetPasswordHandler = DefaultResetPasswordHandler
	}

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

// ConfigAuth config auth
func (provider Provider) ConfigAuth(auth *auth.Auth) {
	auth.Render.RegisterViewPath("github.com/qor/auth/database/views")

	if auth.Mailer != nil {
		auth.Mailer.RegisterViewPath("github.com/qor/auth/database/views/mailers")
	}
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
				case "edit":
					if len(paths) == 4 {
						context.Auth.Config.Render.Funcs(template.FuncMap{
							"reset_password_token": func() string { return paths[3] },
						}).Execute("auth/password/edit", context, context.Request, context.Writer)
						return
					}
					context.SessionManager.Flash(req, session.Message{Message: ErrInvalidResetPasswordToken.Error(), Type: "error"})
					http.Redirect(context.Writer, context.Request, context.Auth.AuthURL("database/password/new"), http.StatusSeeOther)
				case "recover":
					err := provider.ResetPasswordHandler(context)
					if err != nil {
						context.SessionManager.Flash(req, session.Message{Message: err.Error(), Type: "error"})
						http.Redirect(context.Writer, context.Request, context.Auth.AuthURL("database/password/new"), http.StatusSeeOther)
						return
					}
				default:
					return
				}
			}
		}
		return
	}
}
