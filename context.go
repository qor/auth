package auth

import "net/http"

// Context context
type Context struct {
	*Auth
	Claims   *Claims
	Provider Provider
	Request  *http.Request
	Writer   http.ResponseWriter
}
