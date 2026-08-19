package core

import (
	"context"

	"github.com/neatflowcv/identity/internal/pkg/domain"
)

type Repository interface {
	CreateUser(ctx context.Context, user *domain.User) (*domain.User, error)
	GetUser(ctx context.Context, username string) (*domain.User, error)
	CreateRefreshSession(ctx context.Context, session *domain.RefreshSession) error
	RotateRefreshToken(ctx context.Context, rotation *domain.RefreshTokenRotation) error
	RevokeRefreshFamily(ctx context.Context, familyID string) error
}
