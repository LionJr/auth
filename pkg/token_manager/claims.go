package token_manager

import (
	"github.com/golang-jwt/jwt/v5"
)

type AccessClaims struct {
	jwt.RegisteredClaims

	UserID string `json:"user_id"`
	IP     string `json:"ip"`
}

type RefreshClaims struct {
	jwt.RegisteredClaims

	IP string `json:"ip"`
}
