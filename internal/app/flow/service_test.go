package flow_test

import (
	"testing"

	"github.com/neatflowcv/identity/internal/app/flow"
	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/repository/fake"
	"github.com/neatflowcv/identity/internal/pkg/toker/jwt"
	"github.com/stretchr/testify/require"
)

func TestCreateUser(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		service := flow.NewService(nil, fake.NewRepository())
		ctx := t.Context()
		user := domain.NewUser("test", "test")

		ret, err := service.CreateUser(ctx, user)

		require.NoError(t, err)
		require.Equal(t, user, ret)
	})

	t.Run("user already exists", func(t *testing.T) {
		t.Parallel()

		repo := fake.NewRepository()
		_, _ = repo.CreateUser(t.Context(), domain.NewUser("test", "test"))
		service := flow.NewService(nil, repo)
		ctx := t.Context()
		user := domain.NewUser("test", "test")

		_, err := service.CreateUser(ctx, user)

		require.ErrorIs(t, err, flow.ErrUserExists)
	})
}

func TestCreateToken(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		repo := fake.NewRepository()
		user := domain.NewUser("test", "test")
		_, _ = repo.CreateUser(t.Context(), user)
		toker := jwt.NewToker([]byte("test-secret-key"))

		service := flow.NewService(toker, repo)
		ctx := t.Context()

		ret, err := service.CreateToken(ctx, user)

		require.NoError(t, err)
		require.NotEmpty(t, ret.AccessToken())
		require.NotEmpty(t, ret.RefreshToken())
		require.NotZero(t, ret.ExpiresIn())
		require.Equal(t, user.Username(), ret.Payload().Username())
	})

	t.Run("user not found", func(t *testing.T) {
		t.Parallel()

		service := flow.NewService(nil, fake.NewRepository())
		ctx := t.Context()
		user := domain.NewUser("test", "test")

		_, err := service.CreateToken(ctx, user)

		require.ErrorIs(t, err, flow.ErrUserNotFound)
	})

	t.Run("authentication failed", func(t *testing.T) {
		t.Parallel()

		service := flow.NewService(nil, fake.NewRepository())
		ctx := t.Context()
		rightUser := domain.NewUser("test", "test")
		_, _ = service.CreateUser(ctx, rightUser)
		wrongUser := domain.NewUser("test", "wrong-password")

		_, err := service.CreateToken(ctx, wrongUser)

		require.ErrorIs(t, err, flow.ErrAuthenticationFailed)
	})
}
