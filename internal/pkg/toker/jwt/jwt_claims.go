package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/neatflowcv/identity/internal/pkg/domain"
)

type jwtClaims struct {
	jwt.RegisteredClaims

	Username string `json:"username"`
	TokenUse string `json:"token_use,omitempty"`
	FamilyID string `json:"family_id,omitempty"`
}

func newJWTClaims(
	user *domain.User,
	issuedAt time.Time,
	expiresAt time.Time,
	tokenUse string,
	tokenID string,
	familyID string,
) *jwtClaims {
	return &jwtClaims{
		Username: user.Username(),
		TokenUse: tokenUse,
		FamilyID: familyID,
		RegisteredClaims: jwt.RegisteredClaims{ //nolint:exhaustruct
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ID:        tokenID,
			Subject:   user.Username(),
		},
	}
}
