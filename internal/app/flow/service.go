package flow

import (
	"context"
	"errors"

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
	dUser, err := s.repository.GetUser(ctx, user.Username())
	if err != nil {
		return nil, mappingError(err, ErrUserNotFound)
	}

	if !dUser.EqualPassword(user) {
		return nil, ErrAuthenticationFailed
	}

	policy := domain.NewTokenPolicy()
	token := s.toker.CreateToken(dUser, policy)

	return token, nil
}

func (s *Service) RefreshToken(ctx context.Context, spec *domain.TokenSpec) (*domain.Token, error) {
	username, err := s.toker.ParseToken(spec)
	if err != nil {
		return nil, mappingError(err, ErrInvalidToken)
	}

	dUser, err := s.repository.GetUser(ctx, string(username))
	if err != nil {
		switch {
		case errors.Is(err, corerepository.ErrUserNotFound):
			return nil, ErrUserNotFound
		default:
			return nil, errors.Join(ErrUnknown, err)
		}
	}

	policy := domain.NewTokenPolicy()

	token := s.toker.CreateToken(dUser, policy)

	return token, nil
}

func mappingError(from error, to error) error {
	switch {
	case errors.Is(from, to):
		return to
	default:
		return errors.Join(from, to)
	}
}
