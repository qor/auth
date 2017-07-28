package auth

// Event event name
type Event string

var (
	// EventLogin login event
	EventLogin Event = "login"
	// EventRegister register event
	EventRegister Event = "register"
	// EventAny any event
	EventAny Event = "*"
)

// HooksInterface hooks interface
type HooksInterface interface {
	GetHooks() Hooks
}

// Hooks callbacks implemention
type Hooks struct {
	beforeHooks map[Event][]Hook
	afterHooks  map[Event][]Hook
}

// GetHooks get hooks
func (hooks Hooks) GetHooks() Hooks {
	return hooks
}

// Before register before hooks
func (hooks Hooks) Before(name Event, hook Hook) {
	if hs, ok := hooks.beforeHooks[name]; ok {
		hooks.beforeHooks[name] = append(hs, hook)
		return
	}

	hooks.beforeHooks[name] = []Hook{hook}
}

// After register after callbacks
func (hooks Hooks) After(name Event, hook Hook) {
	if hs, ok := hooks.afterHooks[name]; ok {
		hooks.afterHooks[name] = append(hs, hook)
		return
	}

	hooks.afterHooks[name] = []Hook{hook}
}

// Hook hook struct
type Hook struct {
	Name    string
	Handler func(event Event, context *Context) error
}
