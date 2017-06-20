package auth

import "net/http"

// Provider define Provider interface
type Provider interface {
	GetName() string

	Login(*http.Request, http.ResponseWriter, *Session)
	Logout(*http.Request, http.ResponseWriter, *Session)
	Register(*http.Request, http.ResponseWriter, *Session)
	Callback(*http.Request, http.ResponseWriter, *Session)
	ServeHTTP(*http.Request, http.ResponseWriter, *Session)
}
