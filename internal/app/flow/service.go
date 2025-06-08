package flow

import (
	"context"
	"errors"
	"time"

	"github.com/neatflowcv/identity/internal/pkg/domain"
	corerepository "github.com/neatflowcv/identity/internal/pkg/repository/core"
	coretoker "github.com/neatflowcv/identity/internal/pkg/toker/core"
)

type Service struct {
	toker      coretoker.Toker
	repository corerepository.Repository
}

func NewService(toker coretoker.Toker, repository corerepository.Repository) *Service {
	return &Service{
		toker:      toker,
		repository: repository,
	}
}

func (s *Service) CreateUser(ctx context.Context, user *domain.User) (*domain.User, error) {
	dUser, err := s.repository.CreateUser(ctx, user)
	if err != nil {
		return nil, ErrUserExists
	}

	return dUser, nil
}

func (s *Service) CreateToken(ctx context.Context, user *domain.User) (*domain.Token, error) {
	now := time.Now()

	dUser, err := s.repository.GetUser(ctx, user.Username())
	if err != nil {
		return nil, mappingError(err, corerepository.ErrUserNotFound, ErrUserNotFound)
	}

	if !dUser.EqualPassword(user) {
		return nil, ErrAuthenticationFailed
	}

	policy := domain.NewTokenPolicy()
	token := s.toker.CreateToken(now, dUser, policy)

	return token, nil
}

func (s *Service) RefreshToken(ctx context.Context, spec *domain.TokenSpec) (*domain.Token, error) {
	now := time.Now()

	username, err := s.toker.ParseToken(now, spec)
	if err != nil {
		return nil, mappingError(err, coretoker.ErrInvalidToken, ErrInvalidToken)
	}

	dUser, err := s.repository.GetUser(ctx, string(username))
	if err != nil {
		return nil, mappingError(err, corerepository.ErrUserNotFound, ErrUserNotFound)
	}

	policy := domain.NewTokenPolicy()

	token := s.toker.CreateToken(now, dUser, policy)

	return token, nil
}

func mappingError(err error, from error, to error) error {
	switch {
	case errors.Is(err, from):
		return to
	default:
		return errors.Join(ErrUnknown, err)
	}
}
