package auth

import (
	"fmt"
	"reflect"

	"github.com/jinzhu/copier"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/qor/utils"
)

// Storer storer interface
type Storer interface {
	Save(schema *Schema, context *Context) (user interface{}, userID string, err error)
	Get(claims *claims.Claims, context *Context) (user interface{}, err error)
}

// UserStorer default user storer
type UserStorer struct {
}

// Save defined how to save user
func (UserStorer) Save(schema *Schema, context *Context) (user interface{}, userID string, err error) {
	var tx = context.Auth.GetDB(context.Request)

	if context.Auth.Config.UserModel != nil {
		currentUser := reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
		copier.Copy(currentUser, schema)
		err = tx.Create(currentUser).Error
		return currentUser, fmt.Sprint(tx.NewScope(currentUser).PrimaryKeyValue()), err
	}
	return nil, "", nil
}

// Get defined how to get user with user id
func (UserStorer) Get(claims *claims.Claims, context *Context) (user interface{}, err error) {
	var tx = context.Auth.GetDB(context.Request)

	if context.Auth.Config.UserModel != nil {
		if claims.UserID != "" {
			currentUser := reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
			if err = tx.First(currentUser, claims.UserID).Error; err == nil {
				return currentUser, nil
			}
		}
		return nil, ErrInvalidAccount
	}

	var (
		authIdentity = reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
		authInfo     = auth_identity.Basic{
			Provider: claims.Provider,
			UID:      claims.Id,
		}
	)

	if !tx.Where(authInfo).First(authIdentity).RecordNotFound() {
		return authIdentity, nil
	}

	return nil, ErrInvalidAccount
}
