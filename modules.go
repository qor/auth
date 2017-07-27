package auth

// Modules modules container
type Modules struct {
	Modules []Module
}

// Use use module
func (modules *Modules) Use(module Module) {
	modules.Modules = append(modules.Modules, module)
}

// Get get used module by name
func (modules *Modules) Get(name string) Module {
	for _, module := range modules.Modules {
		if module.GetName() == name {
			return module
		}
	}
	return nil
}

// Module module definition
type Module interface {
	GetName() string
	RegisterHooks(*Hooks)
}
