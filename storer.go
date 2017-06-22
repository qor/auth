package auth

import (
	"fmt"
	"reflect"

	"github.com/jinzhu/copier"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/qor/utils"
)

// Storer storer interface
type Storer interface {
	Create(schema *Schema, context *Context) (user interface{}, userID string, err error)
	Get(claims *Claims, context *Context) (user interface{}, err error)
}

// UserStorer default user storer
type UserStorer struct {
}

// Save defined how to save user
func (UserStorer) Create(schema *Schema, context *Context) (user interface{}, userID string, err error) {
	var (
		currentUser  interface{}
		authInfo     auth_identity.Basic
		authIdentity = reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
		tx           = context.Auth.GetDB(context.Request)
	)

	authInfo.Provider = schema.Provider
	authInfo.UID = schema.UID

	if !tx.Model(context.Auth.AuthIdentityModel).Where(authInfo).Scan(&authInfo).RecordNotFound() {
		return nil, "", ErrInvalidAccount
	}

	if context.Auth.Config.UserModel != nil {
		currentUser = reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
		copier.Copy(currentUser, schema)
		if err = tx.Create(currentUser).Error; err == nil {
			authInfo.UserID = fmt.Sprint(tx.NewScope(currentUser).PrimaryKeyValue())
		} else {
			return nil, "", err
		}
	} else {
		currentUser = authIdentity
	}

	err = tx.Where(authInfo).FirstOrCreate(authIdentity).Error
	if err == nil {
		return currentUser, authInfo.UserID, nil
	}
	return nil, "", err
}

// Get defined how to get user with user id
func (UserStorer) Get(claims *Claims, context *Context) (user interface{}, err error) {
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
