package auth

import (
	"net/http"

	"github.com/qor/auth/claims"
)

// Context context
type Context struct {
	*Auth
	Claims   *claims.Claims
	Provider Provider
	Request  *http.Request
	Writer   http.ResponseWriter
}
