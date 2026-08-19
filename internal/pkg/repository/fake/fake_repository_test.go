package fake_test

import (
	"testing"
	"time"

	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/repository/core"
	"github.com/neatflowcv/identity/internal/pkg/repository/fake"
	"github.com/stretchr/testify/require"
)

const (
	testFamilyID       = "family"
	testCurrentTokenID = "token-0"
	testCurrentHash    = "hash-0"
)

func TestRepository_RotateRefreshToken(t *testing.T) {
	t.Parallel()

	now := time.Unix(100, 0)
	repo := fake.NewRepository()
	session := &domain.RefreshSession{
		FamilyID:  testFamilyID,
		Username:  "user",
		TokenID:   testCurrentTokenID,
		TokenHash: testCurrentHash,
		ExpiresAt: now.Add(time.Hour),
		RevokedAt: nil,
	}
	require.NoError(t, repo.CreateRefreshSession(t.Context(), session))

	err := repo.RotateRefreshToken(t.Context(), &domain.RefreshTokenRotation{
		FamilyID:       testFamilyID,
		CurrentTokenID: testCurrentTokenID,
		CurrentHash:    testCurrentHash,
		NextTokenID:    "token-1",
		NextHash:       "hash-1",
		ExpiresAt:      now.Add(2 * time.Hour),
		Now:            now,
	})
	require.NoError(t, err)

	err = repo.RotateRefreshToken(t.Context(), &domain.RefreshTokenRotation{
		FamilyID:       testFamilyID,
		CurrentTokenID: testCurrentTokenID,
		CurrentHash:    testCurrentHash,
		NextTokenID:    "token-2",
		NextHash:       "hash-2",
		ExpiresAt:      now.Add(3 * time.Hour),
		Now:            now,
	})
	require.ErrorIs(t, err, core.ErrRefreshTokenInvalid)

	err = repo.RotateRefreshToken(t.Context(), &domain.RefreshTokenRotation{
		FamilyID:       testFamilyID,
		CurrentTokenID: "token-1",
		CurrentHash:    "hash-1",
		NextTokenID:    "token-3",
		NextHash:       "hash-3",
		ExpiresAt:      now.Add(4 * time.Hour),
		Now:            now,
	})
	require.ErrorIs(t, err, core.ErrRefreshTokenInvalid)
}
