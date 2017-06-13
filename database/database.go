package database

import (
	"fmt"
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
	Auth             *auth.Auth
	AuthorizeHandler func(request *http.Request, writer http.ResponseWriter, session *auth.Session) (interface{}, error)
	RegisterHandler  func(request *http.Request, writer http.ResponseWriter, session *auth.Session) (interface{}, error)
}

// GetName return provider name
func (DatabaseProvider) GetName() string {
	return "database"
}

// ConfigAuth implemented ConfigAuth for database provider
func (provider *DatabaseProvider) ConfigAuth(Auth *auth.Auth) {
	provider.Auth = Auth

	if provider.AuthorizeHandler == nil {
		provider.AuthorizeHandler = func(request *http.Request, writer http.ResponseWriter, session *auth.Session) (interface{}, error) {
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

	if provider.RegisterHandler == nil {
		provider.RegisterHandler = func(request *http.Request, writer http.ResponseWriter, session *auth.Session) (interface{}, error) {
			var (
				err      error
				authInfo auth_identity.Basic
				tx       = Auth.GetDB(request)
			)

			request.ParseForm()
			if request.Form.Get("login") == "" {
				return nil, auth.ErrInvalidAccount
			}

			if request.Form.Get("password") == "" {
				return nil, auth.ErrInvalidPassword
			}

			authInfo.UID = request.Form.Get("login")
			if authInfo.EncryptedPassword, err = session.Auth.Config.Encryptor.Digest(request.Form.Get("password")); err != nil {
				return nil, err
			}

			fmt.Println(authInfo)
			if tx.Model(Auth.AuthIdentityModel).Where("uid = ?", request.Form.Get("login")).Scan(authInfo).RecordNotFound() {
				return nil, auth.ErrInvalidAccount
			}

			return nil, nil
		}
	}
}

// Login implemented login with database provider
func (provider DatabaseProvider) Login(request *http.Request, writer http.ResponseWriter, session *auth.Session) {
	provider.Auth.LoginHandler(request, writer, session, provider.AuthorizeHandler)
}

// Register implemented register with database provider
func (provider DatabaseProvider) Register(request *http.Request, writer http.ResponseWriter, session *auth.Session) {
	provider.Auth.RegisterHandler(request, writer, session, provider.RegisterHandler)
}

// Logout implemented logout with database provider
func (provider DatabaseProvider) Logout(request *http.Request, writer http.ResponseWriter, session *auth.Session) {
	provider.Auth.LogoutHandler(request, writer, session)
}

// Callback implement Callback with database provider
func (provider DatabaseProvider) Callback(req *http.Request, writer http.ResponseWriter, session *auth.Session) {
}

// ServeHTTP implement ServeHTTP with database provider
func (provider DatabaseProvider) ServeHTTP(req *http.Request, writer http.ResponseWriter, session *auth.Session) {
}
