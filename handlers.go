package auth

import "net/http"

// DefaultLoginHandler default behaviour after logged in
var DefaultLoginHandler = func(request *http.Request, writer http.ResponseWriter, claims *Claims) {
	request.Cookie("_session")
}
