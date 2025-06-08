package jwt

import (
	"errors"
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

func (t *Toker) CreateToken(now time.Time, user *domain.User, policy *domain.TokenPolicy) *domain.Token {
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

func (t *Toker) ParseToken(now time.Time, spec *domain.TokenSpec) (domain.Username, error) {
	refreshTokenClaims, err := t.parseTokenString(now, spec.RefreshToken())
	if err == nil {
		return domain.Username(refreshTokenClaims.Username), nil
	}

	totalErr := err

	accessTokenClaims, err := t.parseTokenString(now, spec.AccessToken())
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

var (
	ErrInvalidMethod = errors.New("unexpected signing method")
)

func (t *Toker) parseTokenString(now time.Time, tokenString string) (*jwtClaims, error) {
	var claims jwtClaims

	_, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidMethod
		}

		return t.secretKey, nil
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
			panic(err)
		}
	}

	return &claims, nil
}
