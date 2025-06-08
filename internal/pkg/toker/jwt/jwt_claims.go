package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/neatflowcv/identity/internal/pkg/domain"
)

type jwtClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func newJWTClaims(user *domain.User, issuedAt time.Time, expiresAt time.Time) *jwtClaims {
	return &jwtClaims{
		Username: user.Username(),
		RegisteredClaims: jwt.RegisteredClaims{ //nolint:exhaustruct
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			Subject:   user.Username(),
		},
	}
}
