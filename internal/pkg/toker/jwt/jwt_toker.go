package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/toker/core"
)

var _ core.Toker = (*Toker)(nil)

type Toker struct {
	secretKey []byte
}

func NewToker(secretKey []byte) *Toker {
	return &Toker{
		secretKey: secretKey,
	}
}

func (t *Toker) CreateToken(user *domain.User, policy *domain.TokenPolicy) *domain.Token {
	now := time.Now()
	accessTokenString := t.createTokenString(user, now, now.Add(policy.AccessTokenTTL()))
	refreshTokenString := t.createTokenString(user, now, now.Add(policy.RefreshTokenTTL()))
	payload := domain.NewPayload(user.Username())
	token := domain.NewToken(
		domain.TokenTypeBearer,
		accessTokenString,
		refreshTokenString,
		policy.AccessTokenTTL(),
		payload,
	)

	return token
}

func (t *Toker) ParseToken(spec *domain.TokenSpec) (domain.Username, error) {
	refreshTokenClaims, err := t.parseTokenString(spec.RefreshToken())
	if err == nil {
		return domain.Username(refreshTokenClaims.Username), nil
	}

	totalErr := err

	accessTokenClaims, err := t.parseTokenString(spec.AccessToken())
	if err == nil {
		return domain.Username(accessTokenClaims.Username), nil
	}

	totalErr = errors.Join(totalErr, err)

	return "", totalErr
}

func (t *Toker) createTokenString(user *domain.User, issuedAt time.Time, expiresAt time.Time) string {
	accessTokenClaims := newJWTClaims(user, issuedAt, expiresAt)
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)

	accessTokenString, err := accessToken.SignedString(t.secretKey)
	if err != nil {
		panic(err)
	}

	return accessTokenString
}

func (t *Toker) parseTokenString(tokenString string) (*jwtClaims, error) {
	var tmpClaims jwtClaims

	token, err := jwt.ParseWithClaims(tokenString, &tmpClaims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %w", core.ErrInvalidToken)
		}

		return t.secretKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh token: %w", core.ErrInvalidToken)
	}

	claims, ok := token.Claims.(*jwtClaims)
	if !ok || !token.Valid {
		return nil, core.ErrInvalidToken
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, core.ErrInvalidToken
	}

	return claims, nil
}
