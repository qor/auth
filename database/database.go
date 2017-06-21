package database

import (
	"fmt"
	"reflect"

	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/database/encryptor"
	"github.com/qor/auth/database/encryptor/bcrypt_encryptor"
	"github.com/qor/qor/utils"
)

type Config struct {
	Encryptor        encryptor.Interface
	AuthorizeHandler func(*auth.Context) (interface{}, error)
	RegisterHandler  func(*auth.Context) (interface{}, error)
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
		config.AuthorizeHandler = func(context *auth.Context) (interface{}, error) {
			var (
				authInfo auth_identity.Basic
				request  = context.Request
				tx       = context.Auth.GetDB(request)
			)

			request.ParseForm()
			authInfo.Provider = provider.GetName()
			authInfo.UID = request.Form.Get("login")
			if tx.Model(context.Auth.AuthIdentityModel).Where(authInfo).Scan(&authInfo).RecordNotFound() {
				return nil, auth.ErrInvalidAccount
			}

			if err := config.Encryptor.Compare(authInfo.EncryptedPassword, request.Form.Get("password")); err == nil {
				if context.Auth.Config.UserModel != nil {
					if authInfo.UserID == "" {
						return nil, auth.ErrInvalidAccount
					}
					currentUser := reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
					err := tx.First(currentUser, authInfo.UserID).Error
					return currentUser, err
				}
				return authInfo, err
			}

			return nil, auth.ErrInvalidPassword
		}
	}

	if config.RegisterHandler == nil {
		config.RegisterHandler = func(context *auth.Context) (interface{}, error) {
			var (
				err      error
				authInfo auth_identity.Basic
				request  = context.Request
				tx       = context.Auth.GetDB(request)
			)

			request.ParseForm()
			if request.Form.Get("login") == "" {
				return nil, auth.ErrInvalidAccount
			}

			if request.Form.Get("password") == "" {
				return nil, auth.ErrInvalidPassword
			}

			authInfo.Provider = provider.GetName()
			authInfo.UID = request.Form.Get("login")

			if !tx.Model(context.Auth.AuthIdentityModel).Where(authInfo).Scan(&authInfo).RecordNotFound() {
				return nil, auth.ErrInvalidAccount
			}

			if authInfo.EncryptedPassword, err = config.Encryptor.Digest(request.Form.Get("password")); err == nil {
				if context.Auth.Config.UserModel != nil {
					user := reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
					if err = tx.Create(user).Error; err == nil {
						authInfo.UserID = fmt.Sprint(tx.NewScope(user).PrimaryKeyValue())
					} else {
						return nil, err
					}
				}

				authIdentity := reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
				err = tx.Where(authInfo).FirstOrCreate(authIdentity).Error
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
