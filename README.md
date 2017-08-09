# Auth

Auth is a modular authentication system for web development in Golang, it provides different authentication backends to accelerate your development.

## Usage

```go
import (
	"github.com/qor/auth"
	"github.com/qor/auth/providers/password"
	"github.com/qor/auth/providers/github"
	"github.com/qor/auth/providers/google"
	"github.com/qor/auth/providers/phone"
)

var Auth = auth.New(&auth.Config{
	DB:        db.DB,
	UserModel: models.User{},
})

func init() {
	// Register Auth providers
	Auth.RegisterProvider(password.New(&password.Config{}))

	Auth.RegisterProvider(github.New(&github.Config{
		ClientID: "github client id",
		ClientSecret: "github client secret",
	}))

	Auth.RegisterProvider(google.New(&google.Config{
		ClientID: "google client id",
		ClientSecret: "google client secret",
	}))
}


func main() {
	mux := http.NewServeMux()

	mux.Handle("/auth/", auth.Auth.NewServeMux())
	http.ListenAndServe(":9000", mux)
}
```
