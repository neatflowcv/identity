package core

import (
	"context"

	"github.com/neatflowcv/identity/internal/pkg/domain"
)

type Repository interface {
	CreateUser(ctx context.Context, user *domain.User) (*domain.User, error)
	GetUser(ctx context.Context, username string) (*domain.User, error)
}
