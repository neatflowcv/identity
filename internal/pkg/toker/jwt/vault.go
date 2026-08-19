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

	if !validRefreshClaims(now, claims) {
		return nil, core.ErrInvalidToken
	}

	return claims, nil
}

func validRefreshClaims(now time.Time, claims *jwtClaims) bool {
	if claims.TokenUse != "refresh" || claims.Username == "" || claims.Subject != claims.Username {
		return false
	}

	if claims.ID == "" || claims.FamilyID == "" || claims.ExpiresAt == nil || claims.IssuedAt == nil {
		return false
	}

	if claims.IssuedAt.After(now) {
		return false
	}

	return claims.NotBefore == nil || !claims.NotBefore.After(now)
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
		return nil, core.ErrInvalidToken
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
