package auth

// Event event name
type Event string

// Hooks callbacks implemention
type Hooks struct {
	beforeHooks map[string][]Hook
	afterHooks  map[string][]Hook
}

func (Hooks) Before(name string, hook Hook) {
}

func (Hooks) After(name string, hook Hook) {
}

func (Hooks) Register(hook Hook) {
}

// Execute execute hooks
func (Hooks) Execute(name string, context *Context) error {
	return nil
}

type Hook struct {
	Name   string
	Handle func(*Context) error
}
