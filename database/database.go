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
	Authorize func(request *http.Request, writer http.ResponseWriter, session *auth.Session) (interface{}, error)
}

// GetName return provider name
func (DatabaseProvider) GetName() string {
	return "database"
}

// ConfigAuth implemented ConfigAuth for database provider
func (provider *DatabaseProvider) ConfigAuth(Auth *auth.Auth) {
	provider.Auth = Auth

	if provider.Authorize == nil {
		provider.Authorize = func(request *http.Request, writer http.ResponseWriter, session *auth.Session) (interface{}, error) {
			var (
				authInfo auth_identity.Basic
				tx       = Auth.GetDB(request)
			)

			request.ParseForm()
			if tx.Model(Auth.AuthIdentityModel).Where("uid = ?", request.Form.Get("login")).Scan(authInfo).RecordNotFound() {
				return nil, auth.ErrInvalidAccount
			}

			if err := Auth.Config.Encryptor.Compare(authInfo.EncryptedPassword, request.Form.Get("password")); err == nil {
				currentUser := reflect.New(utils.ModelType(Auth.Config.UserModel))
				err := tx.First(currentUser, authInfo.UserID).Error
				return currentUser, err
			}

			return nil, auth.ErrInvalidPassword
		}
	}
}

// Login implemented login with database provider
func (provider DatabaseProvider) Login(request *http.Request, writer http.ResponseWriter, session *auth.Session) {
	provider.Auth.LoginHandler(request, writer, session, provider.Authorize)
}

// Logout implemented logout with database provider
func (provider DatabaseProvider) Logout(request *http.Request, writer http.ResponseWriter, session *auth.Session) {
	provider.Auth.LogoutHandler(request, writer, nil, session)
}

// Register implemented register with database provider
func (provider DatabaseProvider) Register(request *http.Request, writer http.ResponseWriter, session *auth.Session) {
	provider.Auth.RegisterHandler(request, writer, nil, session)
}

// Callback implement Callback with database provider
func (provider DatabaseProvider) Callback(req *http.Request, writer http.ResponseWriter, session *auth.Session) {
}

// ServeHTTP implement ServeHTTP with database provider
func (provider DatabaseProvider) ServeHTTP(req *http.Request, writer http.ResponseWriter, session *auth.Session) {
}
