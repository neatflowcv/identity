package fake

import (
	"context"
	"sync"
	"time"

	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/repository/core"
)

var _ core.Repository = (*Repository)(nil)

type Repository struct {
	mu              sync.RWMutex
	users           map[string]*domain.User
	refreshSessions map[string]*domain.RefreshSession
}

func NewRepository() *Repository {
	return &Repository{
		mu:              sync.RWMutex{},
		users:           make(map[string]*domain.User),
		refreshSessions: make(map[string]*domain.RefreshSession),
	}
}

func (r *Repository) CreateUser(ctx context.Context, user *domain.User) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, ok := r.users[user.Username()]
	if ok {
		return nil, core.ErrUserExists
	}

	r.users[user.Username()] = domain.NewUserWithPasswordHash(user.Username(), user.PasswordHash())

	return user, nil
}

func (r *Repository) GetUser(ctx context.Context, username string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ret, ok := r.users[username]
	if !ok {
		return nil, core.ErrUserNotFound
	}

	return domain.NewUserWithPasswordHash(ret.Username(), ret.PasswordHash()), nil
}

func (r *Repository) CreateRefreshSession(ctx context.Context, session *domain.RefreshSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.refreshSessions[session.FamilyID]; ok {
		return core.ErrRefreshSessionExists
	}

	r.refreshSessions[session.FamilyID] = cloneRefreshSession(session)

	return nil
}

func (r *Repository) RotateRefreshToken(ctx context.Context, rotation *domain.RefreshTokenRotation) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	session, ok := r.refreshSessions[rotation.FamilyID]
	if !ok {
		return core.ErrRefreshTokenInvalid
	}

	if session.RevokedAt != nil || !rotation.Now.Before(session.ExpiresAt) ||
		session.TokenID != rotation.CurrentTokenID || session.TokenHash != rotation.CurrentHash {
		now := rotation.Now
		session.RevokedAt = &now

		return core.ErrRefreshTokenInvalid
	}

	session.TokenID = rotation.NextTokenID
	session.TokenHash = rotation.NextHash
	session.ExpiresAt = rotation.ExpiresAt

	return nil
}

func (r *Repository) RevokeRefreshFamily(ctx context.Context, familyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	session, ok := r.refreshSessions[familyID]
	if !ok || session.RevokedAt != nil {
		return nil
	}

	now := time.Now()
	session.RevokedAt = &now

	return nil
}

func cloneRefreshSession(session *domain.RefreshSession) *domain.RefreshSession {
	clone := *session
	if session.RevokedAt != nil {
		revokedAt := *session.RevokedAt
		clone.RevokedAt = &revokedAt
	}

	return &clone
}
