package core

import (
	"time"

	"github.com/neatflowcv/identity/internal/pkg/domain"
)

type Toker interface {
	CreateToken(now time.Time, user *domain.User, policy *domain.TokenPolicy) *domain.Token
	ParseToken(now time.Time, spec *domain.TokenSpec) (domain.Username, error)
}
