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
	"github.com/qor/session/manager"
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
	http.ListenAndServe(":9000", manager.SessionManager.Middleware(mux))
}
```

That's it, then you could goto `http://127.0.0.1:9000/auth/login` to try features Auth provides, like login, logout, register, forgot/change password...

## Getting Started

Auth has many configurations that used to customize it for different usage, lets start from Auth's [Config](http://godoc.org/github.com/qor/auth#Config).

### Models

Auth has two models, model `AuthIdentityModel` is used to save login information, model `UserModel` is used to save user information.

The reason we have two different models to save auth and user info, as we want to be able to link a user to mutliple auth info, so a user could have multiple ways to login.

If this is not a required feature for your application, you could set those two models to same one or skip the `UserModel`.

* `AuthIdentityModel`

Different provider usually use different information to login, like provider `password` use username/password, `github` use github user ID, so for each provider, it will be its own record to save those information.

Model `AuthIdentityModel`'s default definition is [AuthIdentity](http://godoc.org/github.com/qor/auth/auth_identity#AuthIdentity), if you want to customize it, make sure you have [auth_identity.Basic](http://godoc.org/github.com/qor/auth/auth_identity#Basic) embedded, as `Auth` assume you have same data structure in your database, so it could query/create new record with SQL.

* `UserModel`

By default, there is no `UserModel` defined, if so, you still be able to use `Auth`'s providers to register, login, logout, `Auth` will use `AuthIdentity`'s record as current user.

But usually your application will have a `User` model, after you set its value, when you register a new account with any provider, Auth will create/get a user with `UserStorer`, and link its ID to the auth identity record.

### Customize views

Auth using [Render](http://github.com/qor/render) to render pages, you could refer it for how to register func maps, and register new views paths that used for frontend, also be sure to refer [BindataFS](https://github.com/qor/bindatafs) if you want to compile your application into a binary.

If you want to preprend some paths into view paths, you could use config's `ViewPaths`, which could be helpful if you want to overwrite the default (ugly) login/register pages or you write some auth themes like [https://github.com/qor/auth_themes](https://github.com/qor/auth_themes)

### Sending Emails

Auth using [Mailer](http://github.com/qor/mailer) to send emails, by default, Auth will print emails to console, to send real one, please configure it.

### User Storer

Auth create a default solution to get/save user based on your `AuthIdentityModel`, `UserModel`'s definition, in case of you want to change it, you could implement your [User Storer](http://godoc.org/github.com/qor/auth#UserStorerInterface)

### Session Storer

Auth also has a default way to handle sessions, flash messages, overwrite it by implementing [Session Storer Interface](http://godoc.org/github.com/qor/auth#SessionStorerInterface), by default, Auth is using [session](https://github.com/qor/session)'s default manager to save data into cookies, but in order to save cookies correctly, you have to register session's Middleware into your router, e.g:

```go
func main() {
	mux := http.NewServeMux()

	// Register Router
	mux.Handle("/auth/", Auth.NewServeMux())
	http.ListenAndServe(":9000", manager.SessionManager.Middleware(mux))
}
```

### Redirector

After logged or registered a user, Auth will redirect user to some URL, you could configure which page to redirect with it, if it is not configured, will redirct to the home page.

If you just want to redirect to last visited page, [redirect_back](https://github.com/qor/redirect_back) could help you, you could configure it and use it as the Redirector, e.g:

```
var RedirectBack = redirect_back.New(&redirect_back.Config{
  SessionManager:  manager.SessionManager,
  IgnoredPrefixes: []string{"/auth"},
}

var Auth = auth.New(&auth.Config{
  ...
	Redirector: auth.Redirector{RedirectBack},
})
```

BTW, in order to store last visited URL, you need to mount `redirect_back`'s middleware into router also, btw, `redirect_back` also using SessionManager to save last visited URL into session storer, doesn't forgot its middleware in order to save it correctly.

```go
http.ListenAndServe(":9000", manager.SessionManager.Middleware(RedirectBack.Middleware(mux)))
```
