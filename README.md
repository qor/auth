# Auth

Auth is a modular authentication system for web development in Golang, it provides different authentication backends to accelerate your development.

Currently Auth has database password, github, google authentication support, and it is fairly easy to add other support based on [Auth's Provider interface](https://godoc.org/github.com/qor/auth#Provider)

## Basic Usage

Auth aims to provide a easy to use authentication system that don't require much developer's effort.

To use it, basic flow is:

* Initialize Auth with configuration
* Register some providers
* Register it into router

Here is an example:

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
	// Migrate AuthIdentity table, AuthIdentity table will be used to auth info, like username/password, oauth token.
	// AuthIdentity is just a default model that will be used to save those information, you could change it if you want.
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

That's it, then you could goto `http://127.0.0.1:9000/auth/login` to try features Auth provides, like login, logout, register, forgot/change password...

## Getting Started

To reduce developer's effort, Auth has lots of conventions, lets start from Auth's [Config struct](http://godoc.org/github.com/qor/auth#Config) to explain them.
