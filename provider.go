package auth

import "net/http"

type Provider interface {
	GetCurrentUser(*http.Request, http.ResponseWriter, *Claims) interface{}
	DestroyCurrentSession(*http.Request, http.ResponseWriter, *Claims) error
}
