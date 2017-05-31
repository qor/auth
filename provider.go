package auth

import "net/http"

type Provider interface {
	GetProviderName() string
	Login(request *http.Request, writer http.ResponseWriter, claims *Claims)
	Logout(request *http.Request, writer http.ResponseWriter, claims *Claims)
	Register(request *http.Request, writer http.ResponseWriter, claims *Claims)
}
