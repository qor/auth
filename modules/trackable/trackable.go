package trackable

import "github.com/qor/auth"

type Config struct {
}

type Trackable struct {
	*Config
}

func New(config *Config) *Trackable {
	if config == nil {
		config = &Config{}
	}

	return &Trackable{Config: config}
}

func (Trackable) GetName() string {
	return "trackable"
}

func (Trackable) RegisterHooks(hooks *auth.Hooks) {
	hooks.After("*", auth.Hook{
		Name: "trakable",
		Handler: func(context *auth.Context) error {
		},
	})
}
