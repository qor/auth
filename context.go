package auth

import (
	"net/http"

	"github.com/qor/auth/claims"
	"github.com/qor/session"
)

// Context context
type Context struct {
	*Auth
	Claims      *claims.Claims
	Provider    Provider
	Request     *http.Request
	Writer      http.ResponseWriter
	Errors      []error
	CurrentUser interface{}
	AuthInfo    interface{}
}

// Fire fire hooks
func (context *Context) Fire(event Event, fc func(*Context) error) {
	providerHooks, isProviderHooks := context.Provider.(HooksInterface)

	fireHooks := func(hooks []Hook) {
		for _, hook := range hooks {
			context.AddErr(hook.Handler(event, context))
		}
	}

	fireHooks(context.Hooks.beforeHooks[EventAny])
	fireHooks(context.Hooks.beforeHooks[event])

	if isProviderHooks {
		hooks := providerHooks.GetHooks()
		fireHooks(hooks.beforeHooks[EventAny])
		fireHooks(hooks.beforeHooks[event])
	}

	context.AddErr(fc(context))

	if isProviderHooks {
		hooks := providerHooks.GetHooks()
		fireHooks(hooks.afterHooks[EventAny])
		fireHooks(hooks.afterHooks[event])
	}

	fireHooks(context.Hooks.afterHooks[event])
	fireHooks(context.Hooks.afterHooks[EventAny])
}

// AddErr add error
func (context *Context) AddErr(err error) {
	if err != nil {
		context.Errors = append(context.Errors, err)
	}
}

// Flashes get flash messages
func (context Context) Flashes() []session.Message {
	return context.SessionManager.Flashes(context.Request)
}

// FormValue get form value with name
func (context Context) FormValue(name string) string {
	return context.Request.Form.Get(name)
}
