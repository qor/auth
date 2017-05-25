package auth

import "net/http"

type Provider interface {
	CurrentUserFinder(*http.Request, *Claims) interface{}
}
