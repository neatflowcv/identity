package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/toker/core"
)

type Vault struct {
	secretKey []byte
}

func NewVault(secretKey []byte) *Vault {
	return &Vault{
		secretKey: secretKey,
	}
}

func (v *Vault) Encrypt(issuedAt time.Time, expiresAt time.Time, user *domain.User) (string, error) {
	accessTokenClaims := newJWTClaims(user, issuedAt, expiresAt)
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)

	accessTokenString, err := accessToken.SignedString(v.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return accessTokenString, nil
}

var (
	ErrInvalidMethod = errors.New("unexpected signing method")
)

func (v *Vault) Decrypt(now time.Time, encryptedValue string) (string, error) {
	var claims jwtClaims

	_, err := jwt.ParseWithClaims(encryptedValue, &claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidMethod
		}

		return v.secretKey, nil
	}, jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenMalformed):
			return "", core.ErrInvalidToken
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return "", core.ErrInvalidToken
		case errors.Is(err, jwt.ErrTokenExpired):
			return "", core.ErrInvalidToken
		case errors.Is(err, ErrInvalidMethod):
			return "", core.ErrInvalidToken
		default:
			return "", fmt.Errorf("failed to parse token: %w", err)
		}
	}

	return claims.Username, nil
}
