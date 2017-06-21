package auth

import (
	"fmt"
	"reflect"

	"github.com/jinzhu/copier"
	"github.com/qor/qor/utils"
)

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
		if err == nil {
			return currentUser, fmt.Sprint(tx.NewScope(currentUser).PrimaryKeyValue()), nil
		}
		return nil, "", err
	}

	return nil, "", nil
}

// Get defined how to get user with user id
func (UserStorer) Get(userID string, context *Context) (user interface{}, err error) {
	var tx = context.Auth.GetDB(context.Request)

	if context.Auth.Config.UserModel != nil {
		currentUser := reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
		err = tx.First(currentUser, userID).Error
		return currentUser, err
	}

	return nil, ErrInvalidAccount
}
