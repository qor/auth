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
			authInfo.Provider = provider.GetName()
			authInfo.UID = request.Form.Get("login")
			if tx.Model(Auth.AuthIdentityModel).Where(authInfo).Scan(&authInfo).RecordNotFound() {
				return nil, auth.ErrInvalidAccount
			}

			if err := Auth.Config.Encryptor.Compare(authInfo.EncryptedPassword, request.Form.Get("password")); err == nil {
				if Auth.Config.UserModel != nil {
					currentUser := reflect.New(utils.ModelType(Auth.Config.UserModel)).Interface()
					err := tx.First(currentUser, authInfo.UserID).Error
					return currentUser, err
				}
				return authInfo, err
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

			authInfo.Provider = provider.GetName()
			authInfo.UID = request.Form.Get("login")

			if !tx.Model(Auth.AuthIdentityModel).Where(authInfo).Scan(&authInfo).RecordNotFound() {
				return nil, auth.ErrInvalidAccount
			}

			if authInfo.EncryptedPassword, err = session.Auth.Config.Encryptor.Digest(request.Form.Get("password")); err == nil {
				if Auth.Config.UserModel != nil {
					user := reflect.New(utils.ModelType(Auth.Config.UserModel)).Interface()
					if err = tx.Where(authInfo).FirstOrCreate(user).Error; err == nil {
						authInfo.UserID = fmt.Sprint(tx.NewScope(user).PrimaryKeyValue())
					}
				}

				authIdentity := reflect.New(utils.ModelType(Auth.Config.AuthIdentityModel)).Interface()
				err = tx.Where(authInfo).FirstOrCreate(authIdentity).Error
			}

			return nil, err
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
