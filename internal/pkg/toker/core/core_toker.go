package core

import (
	"time"

	"github.com/neatflowcv/identity/internal/pkg/domain"
)

type Toker interface {
	CreateToken(now time.Time, user *domain.User, policy *domain.TokenPolicy) *domain.Token
	CreateTokenWithFamily(
		now time.Time,
		user *domain.User,
		policy *domain.TokenPolicy,
		familyID string,
	) *domain.Token
	ParseToken(now time.Time, spec *domain.TokenSpec) (domain.Username, error)
	ParseRefreshToken(now time.Time, spec *domain.TokenSpec) (*RefreshTokenClaims, error)
}

type RefreshTokenClaims struct {
	Username domain.Username
	TokenID  string
	FamilyID string
}
