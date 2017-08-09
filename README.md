# Auth

Auth is a modular authentication system for web development in Golang, it provides different authentication backends to accelerate your development.

Currently Auth has database password, github, google authentication support, and it is easy to add other support based on [Auth's Provider interface](https://godoc.org/github.com/qor/auth#Provider)

## Basic Usage

Auth aims to provide a easy to use authentication system that don't need much developer's effort.

To use it, firstly, you need to initialize Auth with configuration, register some providers, then register it into router, like:

```go
import (
	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/providers/github"
	"github.com/qor/auth/providers/google"
	"github.com/qor/auth/providers/password"
)

var (
	// Initialize gorm DB
	gormDB, _ = gorm.Open("sqlite3", "sample.db")

	// Initialize Auth with configuration
	Auth = auth.New(&auth.Config{
		DB: gormDB,
	})
)

func init() {
	// Migrate AuthIdentity table
	gormDB.AutoMigrate(&auth_identity.AuthIdentity{})

	// Register Auth providers
	Auth.RegisterProvider(password.New(&password.Config{}))

	Auth.RegisterProvider(github.New(&github.Config{
		ClientID:     "github client id",
		ClientSecret: "github client secret",
	}))

	Auth.RegisterProvider(google.New(&google.Config{
		ClientID:     "google client id",
		ClientSecret: "google client secret",
	}))
}

func main() {
	mux := http.NewServeMux()

	// Register Router
	mux.Handle("/auth/", Auth.NewServeMux())
	http.ListenAndServe(":9000", mux)
}
```

That's it, then you could goto `http://127.0.0.1:9000/auth/login` to try features Auth provides, like login, logout, register, forgot password...
