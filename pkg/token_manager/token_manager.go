package token_manager

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenManager struct {
	accessSigningKey  string
	refreshSigningKey string
}

func NewManager(accessSigningKey, refreshSigningKey string) (*TokenManager, error) {
	if accessSigningKey == "" || refreshSigningKey == "" {
		return nil, errors.New("empty signing key")
	}

	return &TokenManager{
		accessSigningKey:  accessSigningKey,
		refreshSigningKey: refreshSigningKey,
	}, nil
}

func (m *TokenManager) NewAccessToken(userId, jti, ip string, ttl time.Duration) (string, error) {
	accessClaims := &AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
		},
		UserID: userId,
		IP:     ip,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, accessClaims)

	return token.SignedString([]byte(m.accessSigningKey))
}

func (m *TokenManager) ParseAccessToken(accessToken string) (*AccessClaims, error) {
	accessClaims := &AccessClaims{}
	token, err := jwt.ParseWithClaims(accessToken, accessClaims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.accessSigningKey), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*AccessClaims)
	if !ok {
		return nil, fmt.Errorf("error get user claims from access token")
	}

	return claims, nil
}

func (m *TokenManager) NewRefreshToken(jti, ip string, ttl time.Duration) (string, error) {
	refreshClaims := &RefreshClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
		},
		IP: ip,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, refreshClaims)

	return token.SignedString([]byte(m.refreshSigningKey))
}

func (m *TokenManager) ParseRefreshToken(refreshToken string) (*RefreshClaims, error) {
	refreshClaims := &RefreshClaims{}
	token, err := jwt.ParseWithClaims(refreshToken, refreshClaims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.refreshSigningKey), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*RefreshClaims)
	if !ok {
		return nil, fmt.Errorf("error get user claims from refresh token")
	}

	return claims, nil
}
