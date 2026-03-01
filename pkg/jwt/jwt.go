package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Manager struct {
	secretKey     string
	tokenDuration time.Duration
}

type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

func New(secret string, duration time.Duration) *Manager {
	return &Manager{
		secretKey:     secret,
		tokenDuration: duration,
	}
}

func (m *Manager) Generate(userID string) (string, error) {

	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.tokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(m.secretKey))
}
