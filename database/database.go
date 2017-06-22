package database

import (
	"reflect"
	"strings"

	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/auth/database/encryptor"
	"github.com/qor/auth/database/encryptor/bcrypt_encryptor"
	"github.com/qor/qor/utils"
)

type Config struct {
	Encryptor        encryptor.Interface
	AuthorizeHandler func(*auth.Context) (*claims.Claims, error)
	RegisterHandler  func(*auth.Context) (*claims.Claims, error)
}

// New initialize database provider
func New(config *Config) *DatabaseProvider {
	if config == nil {
		config = &Config{}
	}

	if config.Encryptor == nil {
		config.Encryptor = bcrypt_encryptor.New(&bcrypt_encryptor.Config{})
	}

	provider := &DatabaseProvider{Config: config}

	if config.AuthorizeHandler == nil {
		config.AuthorizeHandler = func(context *auth.Context) (*claims.Claims, error) {
			var (
				authInfo auth_identity.Basic
				req      = context.Request
				tx       = context.Auth.GetDB(req)
			)

			req.ParseForm()
			authInfo.Provider = provider.GetName()
			authInfo.UID = strings.TrimSpace(req.Form.Get("login"))

			if tx.Model(context.Auth.AuthIdentityModel).Where(authInfo).Scan(&authInfo).RecordNotFound() {
				return nil, auth.ErrInvalidAccount
			}

			if err := config.Encryptor.Compare(authInfo.EncryptedPassword, strings.TrimSpace(req.Form.Get("password"))); err == nil {
				return authInfo.ToClaims(), err
			}

			return nil, auth.ErrInvalidPassword
		}
	}

	if config.RegisterHandler == nil {
		config.RegisterHandler = func(context *auth.Context) (*claims.Claims, error) {
			var (
				err          error
				schema       auth.Schema
				authInfo     auth_identity.Basic
				request      = context.Request
				tx           = context.Auth.GetDB(request)
				authIdentity = reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
			)

			request.ParseForm()
			if request.Form.Get("login") == "" {
				return nil, auth.ErrInvalidAccount
			}

			if request.Form.Get("password") == "" {
				return nil, auth.ErrInvalidPassword
			}

			{
				schema.Provider = provider.GetName()
				schema.UID = strings.TrimSpace(request.Form.Get("login"))
				schema.Email = strings.TrimSpace(request.Form.Get("login"))
				schema.RawInfo = request
			}

			authInfo.Provider = schema.Provider
			authInfo.UID = schema.UID

			if !tx.Model(context.Auth.AuthIdentityModel).Where(authInfo).Scan(&authInfo).RecordNotFound() {
				return nil, auth.ErrInvalidAccount
			}

			if authInfo.EncryptedPassword, err = config.Encryptor.Digest(strings.TrimSpace(request.Form.Get("password"))); err == nil {
				if _, userID, err := context.Auth.UserStorer.Save(&schema, context); err == nil {
					authInfo.UserID = userID
				} else {
					return nil, err
				}

				// create auth identity
				if err = tx.Where(authInfo).FirstOrCreate(authIdentity).Error; err == nil {
					return authInfo.ToClaims(), err
				}
			}

			return nil, err
		}
	}

	return provider
}

// DatabaseProvider provide login with database method
type DatabaseProvider struct {
	*Config
}

// GetName return provider name
func (DatabaseProvider) GetName() string {
	return "database"
}

// Login implemented login with database provider
func (provider DatabaseProvider) Login(context *auth.Context) {
	context.Auth.LoginHandler(context, provider.AuthorizeHandler)
}

// Register implemented register with database provider
func (provider DatabaseProvider) Register(context *auth.Context) {
	context.Auth.RegisterHandler(context, provider.RegisterHandler)
}

// Logout implemented logout with database provider
func (provider DatabaseProvider) Logout(context *auth.Context) {
	context.Auth.LogoutHandler(context)
}

// Callback implement Callback with database provider
func (provider DatabaseProvider) Callback(context *auth.Context) {
}

// ServeHTTP implement ServeHTTP with database provider
func (provider DatabaseProvider) ServeHTTP(context *auth.Context) {
}
