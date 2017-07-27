package auth

import (
	"net/http"

	"github.com/qor/auth/claims"
	"github.com/qor/session"
)

// Context context
type Context struct {
	*Auth
	Event    Event
	Claims   *claims.Claims
	Provider Provider
	Request  *http.Request
	Writer   http.ResponseWriter
}

// Flashes get flash messages
func (context Context) Flashes() []session.Message {
	return context.SessionManager.Flashes(context.Request)
}

// FormValue get form value with name
func (context Context) FormValue(name string) string {
	return context.Request.Form.Get(name)
}
