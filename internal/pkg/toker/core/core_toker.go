package core

import (
	"github.com/neatflowcv/identity/internal/pkg/domain"
)

type Toker interface {
	CreateToken(user *domain.User, policy *domain.TokenPolicy) *domain.Token
	ParseToken(spec *domain.TokenSpec) (domain.Username, error)
}
