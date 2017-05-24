package auth

import (
	"errors"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
)

type Claims struct {
	Username string `json:"username,omitempty"`
	jwt.StandardClaims
}

type Auth struct {
}

func (*Auth) SignedToken(claims Claims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString([]byte("secret"))

	return signedToken
}

func (*Auth) Validate(tokenString string) (*Claims, error) {
	if token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return []byte("secret"), nil
	}); err == nil {
	}

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
