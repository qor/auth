package auth

import "net/http"

// Provider define Provider interface
type Provider interface {
	GetProviderName() string

	Login(*http.Request, http.ResponseWriter, *Claims)
	Logout(*http.Request, http.ResponseWriter, *Claims)
	Register(*http.Request, http.ResponseWriter, *Claims)
	Callback(*http.Request, http.ResponseWriter, *Claims)
	ServeHTTP(*http.Request, http.ResponseWriter, *Claims)
}
