package auth

import (
	"fmt"
	"net/http"
)

// DefaultLoginHandler default behaviour after logged in
var DefaultLoginHandler = func(req *http.Request, w http.ResponseWriter, authorize func(*http.Request, http.ResponseWriter) (interface{}, error)) {
	currentUser, err := authorize(req, w)
	fmt.Println(currentUser)
	fmt.Println(err)
}
