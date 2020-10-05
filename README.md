# Auth

Auth is a modular authentication system for web development in Golang. It provides different authentication backends to accelerate your development.

Currently Auth has database password, github, google, facebook, and twitter authentication support. It is fairly easy to add other support based on [Auth's Provider interface](https://godoc.org/github.com/qor/auth#Provider).

## Quick Start

Auth aims to provide an easy to use authentication system that doesn't require much developer effort.

The basic flow to use Auth is:

* Initialize Auth with configuration
* Register some providers
* Register it into router

Here is an example:

```go
package main

import (
  "github.com/qor/auth"
  "github.com/qor/auth/auth_identity"
  "github.com/qor/auth/providers/github"
  "github.com/qor/auth/providers/google"
  "github.com/qor/auth/providers/password"
  "github.com/qor/auth/providers/facebook"
  "github.com/qor/auth/providers/twitter"
  "github.com/qor/session/manager"

  _ "github.com/mattn/go-sqlite3"

  "net/http"
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
  // Migrate AuthIdentity model, AuthIdentity will be used to save auth info, like username/password, oauth token, you could change that.
  gormDB.AutoMigrate(&auth_identity.AuthIdentity{})

  // Register Auth providers
  // Allow use username/password
  Auth.RegisterProvider(password.New(&password.Config{}))

  // Allow use Github
  Auth.RegisterProvider(github.New(&github.Config{
    ClientID:     "github client id",
    ClientSecret: "github client secret",
  }))

  // Allow use Google
  Auth.RegisterProvider(google.New(&google.Config{
    ClientID:     "google client id",
    ClientSecret: "google client secret",
    AllowedDomains: []string{}, // Accept all domains, instead you can pass a whitelist of acceptable domains
  }))

  // Allow use Facebook
  Auth.RegisterProvider(facebook.New(&facebook.Config{
    ClientID:     "facebook client id",
    ClientSecret: "facebook client secret",
  }))

  // Allow use Twitter
  Auth.RegisterProvider(twitter.New(&twitter.Config{
    ClientID:     "twitter client id",
    ClientSecret: "twitter client secret",
  }))
}

func main() {
  mux := http.NewServeMux()

  // Mount Auth to Router
  mux.Handle("/auth/", Auth.NewServeMux())
  http.ListenAndServe(":9000", manager.SessionManager.Middleware(mux))
}
```

That's it! You could goto `http://127.0.0.1:9000/auth/login` to try Auth features, like login, logout, register, forgot/change password...

And it could be even easier with [Auth Themes](#auth-themes); you can integrate Auth into your application with a few line configurations.

## Usage

Auth has many configurations that could be used to customize it for different usage. Let's start from Auth's [Config](http://godoc.org/github.com/qor/auth#Config).

### Models

Auth has two models: model `AuthIdentityModel` is used to save login information, model `UserModel` is used to save user information.

The reason we save auth and user info as separate is to be able to link a user to multiple auth info records. That allows a user to have multiple ways to login.

If this is not required for you, you could just set those two models to same one or skip set `UserModel`.

* `AuthIdentityModel`

Different providers usually use different information to login. For example, the provider `password` uses username/password, `github` uses github user ID, and so on. Each provider will save its information into its own record.

It is not necessary to set `AuthIdentityModel` as Auth has a default [definition of AuthIdentityModel](http://godoc.org/github.com/qor/auth/auth_identity#AuthIdentity). In case of you want to change it, please make sure you have [auth_identity.Basic](http://godoc.org/github.com/qor/auth/auth_identity#Basic) embedded. This is needed as `Auth` assumes you have the same data structure in your database so it can query/create records with SQL.

* `UserModel`

By default, there is no `UserModel` defined. Even with this default, you are still able to use `Auth` features (`Auth` will return used auth info record as logged user).

But usually your application will have a `User` model. After you set its value, when you register a new account from any provider, Auth will create/get a user with `UserStorer` and link its ID to the auth identity record.

### Customize views

Auth uses [Render](http://github.com/qor/render) to render pages. You should refer to it to learn how to register func maps and extend views paths. Also, be sure to reference [BindataFS](https://github.com/qor/bindatafs) if you want to compile your application into a binary.

If you want to prepend view paths, you could add them to `ViewPaths`. This would be helpful if you want to overwrite the default (ugly) login/register pages or develop auth themes like [https://github.com/qor/auth_themes](https://github.com/qor/auth_themes)

### Sending Emails

Auth uses [Mailer](http://github.com/qor/mailer) to send emails. By default, Auth will print emails to the console. Please configure it to send to a real server.

### User Storer

Auth created a default UserStorer to get/save user based on your `AuthIdentityModel`, `UserModel`'s definition. If you wish to change it, you could implement your own [User Storer](http://godoc.org/github.com/qor/auth#UserStorerInterface).

### Session Storer

Auth also has a default way to handle sessions and flash messages. The default can be overridden by implementing your own custom [Session Storer Interface](http://godoc.org/github.com/qor/auth#SessionStorerInterface).

By default, Auth uses [session](https://github.com/qor/session)'s default manager to save data into cookies. In order to save cookies correctly, you must register session's Middleware into your router, e.g:

```go
func main() {
	mux := http.NewServeMux()

	// Register Router
	mux.Handle("/auth/", Auth.NewServeMux())
	http.ListenAndServe(":9000", manager.SessionManager.Middleware(mux))
}
```

### Redirector

After some Auth actions, like logged, registered or confirmed, Auth will redirect user to some URL. You can configure which page to redirect with `Redirector`. By default, this will redirect to home page.

If you want to redirect to last visited page, [redirect_back](https://github.com/qor/redirect_back) is for you! You would configure it and use it as the Redirector, like:

```go
var RedirectBack = redirect_back.New(&redirect_back.Config{
	SessionManager:  manager.SessionManager,
	IgnoredPrefixes: []string{"/auth"},
}

var Auth = auth.New(&auth.Config{
	...
	Redirector: auth.Redirector{RedirectBack},
})
```

BTW, to make the Redirector work correctly, `redirect_back` needs to save the last visisted URL into the session with session manager for each request. That means you need to mount `redirect_back`, and `SessionManager`'s middleware into router.

```go
http.ListenAndServe(":9000", manager.SessionManager.Middleware(RedirectBack.Middleware(mux)))
```

## Advanced Usage

### Auth Themes

In order to save you time and effort, we have created some [auth themes](https://github.com/qor/auth_themes).

The themes usually have well designed pages, especially if you don't have many custom requirements. With the themes, you can Auth system ready to use for your application with just a few lines. For example:

```go
import "github.com/qor/auth_themes/clean"

var Auth = clean.New(&auth.Config{
	DB:         db.DB,
	Render:     config.View,
	Mailer:     config.Mailer,
	UserModel:  models.User{},
})
```

Check Auth Theme's [document](https://github.com/qor/auth_themes) for How To use/create Auth themes

### Authorization

`Authentication` is the process of verifying who you are; `Authorization` is the process of verifying that you have access to something.

Auth package not only provides `Authentication`, but also `Authorization`. Please checkout [authority](https://github.com/qor/auth/tree/master/authority) for more details
