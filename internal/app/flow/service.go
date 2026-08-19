package flow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/hasher"
	corerepository "github.com/neatflowcv/identity/internal/pkg/repository/core"
	coretoker "github.com/neatflowcv/identity/internal/pkg/toker/core"
)

type Service struct {
	toker          coretoker.Toker
	repository     corerepository.Repository
	passwordHasher hasher.Hasher
}

func NewService(
	toker coretoker.Toker,
	repository corerepository.Repository,
	passwordHasher hasher.Hasher,
) *Service {
	return &Service{
		toker:          toker,
		repository:     repository,
		passwordHasher: passwordHasher,
	}
}

// CreateUser creates a new user in the system
// Returns:
//   - ErrUserExists: when a user with the same username already exists
//   - ErrUnknown: for any other unexpected errors
func (s *Service) CreateUser(ctx context.Context, user *domain.User) (*domain.User, error) {
	hash, err := s.passwordHasher.Hash(user.Password())
	if err != nil {
		return nil, errors.Join(ErrUnknown, err)
	}

	storedUser := domain.NewUserWithPasswordHash(user.Username(), hash)

	dUser, err := s.repository.CreateUser(ctx, storedUser)
	if err != nil {
		return nil, mappingError(err, corerepository.ErrUserExists, ErrUserExists)
	}

	return dUser, nil
}

// CreateToken creates an authentication token for a user
// Returns:
//   - ErrUserNotFound: when the specified user does not exist
//   - ErrAuthenticationFailed: when the provided password is incorrect
//   - ErrUnknown: for any other unexpected errors
func (s *Service) CreateToken(ctx context.Context, user *domain.User) (*domain.Token, error) {
	now := time.Now()

	dUser, err := s.repository.GetUser(ctx, user.Username())
	if err != nil {
		return nil, mappingError(err, corerepository.ErrUserNotFound, ErrUserNotFound)
	}

	verified, err := s.passwordHasher.Verify(user.Password(), dUser.PasswordHash())
	if err != nil {
		return nil, errors.Join(ErrUnknown, err)
	}

	if !verified {
		return nil, ErrAuthenticationFailed
	}

	policy := domain.NewTokenPolicy()
	token := s.toker.CreateToken(now, dUser, policy)

	claims, err := s.toker.ParseRefreshToken(now, domain.NewTokenSpec(token.RefreshToken()))
	if err != nil {
		return nil, errors.Join(ErrUnknown, err)
	}

	err = s.repository.CreateRefreshSession(ctx, &domain.RefreshSession{
		FamilyID:  claims.FamilyID,
		Username:  claims.Username,
		TokenID:   claims.TokenID,
		TokenHash: hashRefreshToken(token.RefreshToken()),
		ExpiresAt: now.Add(policy.RefreshTokenTTL()),
		RevokedAt: nil,
	})
	if err != nil {
		return nil, errors.Join(ErrUnknown, err)
	}

	return token, nil
}

// RefreshToken refreshes an existing authentication token
// Returns:
//   - ErrInvalidToken: when the provided token is invalid or expired
//   - ErrUserNotFound: when the user associated with the token does not exist
//   - ErrUnknown: for any other unexpected errors
func (s *Service) RefreshToken(ctx context.Context, spec *domain.TokenSpec) (*domain.Token, error) {
	now := time.Now()

	claims, err := s.toker.ParseRefreshToken(now, spec)
	if err != nil {
		return nil, mappingError(err, coretoker.ErrInvalidToken, ErrInvalidToken)
	}

	dUser, err := s.repository.GetUser(ctx, string(claims.Username))
	if err != nil {
		return nil, mappingError(err, corerepository.ErrUserNotFound, ErrUserNotFound)
	}

	policy := domain.NewTokenPolicy()

	token := s.toker.CreateTokenWithFamily(now, dUser, policy, claims.FamilyID)

	nextClaims, err := s.toker.ParseRefreshToken(now, domain.NewTokenSpec(token.RefreshToken()))
	if err != nil {
		return nil, errors.Join(ErrUnknown, err)
	}

	err = s.repository.RotateRefreshToken(ctx, &domain.RefreshTokenRotation{
		FamilyID:       claims.FamilyID,
		CurrentTokenID: claims.TokenID,
		CurrentHash:    hashRefreshToken(spec.RefreshToken()),
		NextTokenID:    nextClaims.TokenID,
		NextHash:       hashRefreshToken(token.RefreshToken()),
		ExpiresAt:      now.Add(policy.RefreshTokenTTL()),
		Now:            now,
	})
	if err != nil {
		return nil, mappingError(err, corerepository.ErrRefreshTokenInvalid, ErrInvalidToken)
	}

	return token, nil
}

func hashRefreshToken(token string) string {
	digest := sha256.Sum256([]byte(token))

	return hex.EncodeToString(digest[:])
}

func mappingError(err error, from error, to error) error {
	switch {
	case errors.Is(err, from):
		return to
	default:
		return errors.Join(ErrUnknown, err)
	}
}
