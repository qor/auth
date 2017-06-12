package database

import (
	"net/http"
	"reflect"

	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/qor/utils"
)

// New initialize database provider
func New() *DatabaseProvider {
	return &DatabaseProvider{}
}

// DatabaseProvider provide login with database method
type DatabaseProvider struct {
	Auth      *auth.Auth
	Authorize func(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) (interface{}, error)
}

// GetName return provider name
func (DatabaseProvider) GetName() string {
	return "database"
}

// ConfigAuth implemented ConfigAuth for database provider
func (provider DatabaseProvider) ConfigAuth(Auth *auth.Auth) {
	provider.Auth = Auth

	if provider.Authorize == nil {
		provider.Authorize = func(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) (interface{}, error) {
			var (
				authInfo auth_identity.Basic
				tx       = Auth.GetDB(request)
			)

			request.ParseForm()
			tx.Model(Auth.AuthIdentityModel).Where("uid = ?", request.Form.Get("login")).First(authInfo)

			if encryptedPassword, err := Auth.Config.Encryptor.Digest(request.Form.Get("password")); err == nil {
				if encryptedPassword == authInfo.EncryptedPassword {
					currentUser := reflect.New(utils.ModelType(Auth.Config.UserModel))
					err := tx.First(currentUser, authInfo.UserID).Error
					return currentUser, err
				}
			}

			return nil, auth.ErrInvalidPassword
		}
	}
}

// Login implemented login with database provider
func (provider DatabaseProvider) Login(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
	currentUser, err := provider.Authorize(request, writer, claims)
	if err == nil && currentUser != nil {
		provider.Auth.LoginHandler(request, writer, currentUser, claims)
	}
}

// Logout implemented logout with database provider
func (provider DatabaseProvider) Logout(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
	provider.Auth.LogoutHandler(request, writer, nil, claims)
}

// Register implemented register with database provider
func (provider DatabaseProvider) Register(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
	provider.Auth.RegisterHandler(request, writer, nil, claims)
}

// Callback implement Callback with database provider
func (provider DatabaseProvider) Callback(*http.Request, http.ResponseWriter, *auth.Claims) {
}

// ServeHTTP implement ServeHTTP with database provider
func (provider DatabaseProvider) ServeHTTP(*http.Request, http.ResponseWriter, *auth.Claims) {
}
