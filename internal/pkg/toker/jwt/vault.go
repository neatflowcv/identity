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
	accessTokenClaims := newJWTClaims(user, issuedAt, expiresAt, "access", "", "")

	return v.encrypt(accessTokenClaims)
}

func (v *Vault) EncryptRefresh(
	issuedAt time.Time,
	expiresAt time.Time,
	user *domain.User,
	tokenID string,
	familyID string,
) (string, error) {
	refreshTokenClaims := newJWTClaims(user, issuedAt, expiresAt, "refresh", tokenID, familyID)

	return v.encrypt(refreshTokenClaims)
}

var (
	ErrInvalidMethod = errors.New("unexpected signing method")
)

func (v *Vault) Decrypt(now time.Time, encryptedValue string) (string, error) {
	claims, err := v.decryptClaims(now, encryptedValue)
	if err != nil {
		return "", err
	}

	return claims.Username, nil
}

func (v *Vault) DecryptRefresh(now time.Time, encryptedValue string) (*jwtClaims, error) {
	claims, err := v.decryptClaims(now, encryptedValue)
	if err != nil {
		return nil, err
	}

	if claims.TokenUse != "refresh" || claims.ID == "" || claims.FamilyID == "" {
		return nil, core.ErrInvalidToken
	}

	return claims, nil
}

func (v *Vault) decryptClaims(now time.Time, encryptedValue string) (*jwtClaims, error) {
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
			return nil, core.ErrInvalidToken
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, core.ErrInvalidToken
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, core.ErrInvalidToken
		case errors.Is(err, ErrInvalidMethod):
			return nil, core.ErrInvalidToken
		default:
			return nil, fmt.Errorf("failed to parse token: %w", err)
		}
	}

	return &claims, nil
}

func (v *Vault) encrypt(claims *jwtClaims) (string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	accessTokenString, err := accessToken.SignedString(v.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return accessTokenString, nil
}
