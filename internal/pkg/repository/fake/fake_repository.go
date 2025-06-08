package fake

import (
	"context"

	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/repository/core"
)

var _ core.Repository = (*Repository)(nil)

type Repository struct {
	users map[string]*domain.User
}

func NewRepository() *Repository {
	return &Repository{
		users: make(map[string]*domain.User),
	}
}

func (r *Repository) CreateUser(ctx context.Context, user *domain.User) (*domain.User, error) {
	_, ok := r.users[user.Username()]
	if ok {
		return nil, core.ErrUserExists
	}

	r.users[user.Username()] = user

	return user, nil
}

func (r *Repository) GetUser(ctx context.Context, username string) (*domain.User, error) {
	ret, ok := r.users[username]
	if !ok {
		return nil, core.ErrUserNotFound
	}

	return ret, nil
}
