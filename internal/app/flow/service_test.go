package flow_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/neatflowcv/identity/internal/app/flow"
	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/hasher/argon"
	"github.com/neatflowcv/identity/internal/pkg/repository/fake"
	"github.com/neatflowcv/identity/internal/pkg/toker/jwt"
	"github.com/stretchr/testify/require"
)

func TestCreateUser(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		service := flow.NewService(nil, fake.NewRepository(), testHasher(t))
		ctx := t.Context()
		user := domain.NewUser("test", "test")

		ret, err := service.CreateUser(ctx, user)

		require.NoError(t, err)
		require.Equal(t, user.Username(), ret.Username())
		require.NotEmpty(t, ret.PasswordHash())
		require.NotContains(t, ret.PasswordHash(), user.Password())
	})

	t.Run("user already exists", func(t *testing.T) {
		t.Parallel()

		repo := fake.NewRepository()
		service := flow.NewService(nil, repo, testHasher(t))
		_, err := service.CreateUser(t.Context(), domain.NewUser("test", "test"))
		require.NoError(t, err)
		ctx := t.Context()
		user := domain.NewUser("test", "test")

		_, err = service.CreateUser(ctx, user)

		require.ErrorIs(t, err, flow.ErrUserExists)
	})
}

func TestCreateToken(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		repo := fake.NewRepository()
		user := domain.NewUser("test", "test")
		toker := jwt.NewToker([]byte("test-public-key"), []byte("test-private-key"))

		service := flow.NewService(toker, repo, testHasher(t))
		ctx := t.Context()
		_, err := service.CreateUser(ctx, user)
		require.NoError(t, err)

		ret, err := service.CreateToken(ctx, user)

		require.NoError(t, err)
		require.NotEmpty(t, ret.AccessToken())
		require.NotEmpty(t, ret.RefreshToken())
		require.NotZero(t, ret.ExpiresIn())
		require.Equal(t, user.Username(), ret.Payload().Username())
	})

	t.Run("user not found", func(t *testing.T) {
		t.Parallel()

		service := flow.NewService(nil, fake.NewRepository(), testHasher(t))
		ctx := t.Context()
		user := domain.NewUser("test", "test")

		_, err := service.CreateToken(ctx, user)

		require.ErrorIs(t, err, flow.ErrUserNotFound)
	})

	t.Run("authentication failed", func(t *testing.T) {
		t.Parallel()

		service := flow.NewService(nil, fake.NewRepository(), testHasher(t))
		ctx := t.Context()
		rightUser := domain.NewUser("test", "test")
		_, err := service.CreateUser(ctx, rightUser)
		require.NoError(t, err)

		wrongUser := domain.NewUser("test", "wrong-password")

		_, err = service.CreateToken(ctx, wrongUser)

		require.ErrorIs(t, err, flow.ErrAuthenticationFailed)
	})
}

func TestCreateToken_MissingUserVerifiesDummyPasswordHash(t *testing.T) {
	t.Parallel()

	hasher := &recordingHasher{encodedHash: "", verifyCalled: false}
	service := flow.NewService(nil, fake.NewRepository(), hasher)

	_, err := service.CreateToken(t.Context(), domain.NewUser("missing", "password"))

	require.ErrorIs(t, err, flow.ErrUserNotFound)
	require.True(t, hasher.verifyCalled)
	require.True(t, strings.HasPrefix(hasher.encodedHash, "$argon2id$v=19$m=65536,t=3,p=4$"))

	productionHasher := argon.NewDefaultArgon2id()
	verified, verifyErr := productionHasher.Verify("password", hasher.encodedHash)
	require.NoError(t, verifyErr)
	require.False(t, verified)
}

func TestRefreshToken(t *testing.T) { //nolint:funlen
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		repo := fake.NewRepository()
		user := domain.NewUser("test", "test")
		toker := jwt.NewToker([]byte("test-public-key"), []byte("test-private-key"))
		service := flow.NewService(toker, repo, testHasher(t))
		ctx := t.Context()
		_, err := service.CreateUser(ctx, user)
		require.NoError(t, err)
		initialToken, err := service.CreateToken(ctx, user)
		require.NoError(t, err)

		spec := domain.NewTokenSpec(initialToken.RefreshToken())

		newToken, err := service.RefreshToken(ctx, spec)

		require.NoError(t, err)
		require.NotNil(t, newToken)
		require.NotEmpty(t, newToken.AccessToken())
		require.NotEmpty(t, newToken.RefreshToken())
		require.NotZero(t, newToken.ExpiresIn())
		require.Equal(t, user.Username(), newToken.Payload().Username())
		require.Equal(t, domain.TokenTypeBearer, newToken.TokenType())
	})

	t.Run("previous refresh token is rejected and revokes the family", func(t *testing.T) {
		t.Parallel()

		repo := fake.NewRepository()
		user := domain.NewUser("test", "test")
		toker := jwt.NewToker([]byte("test-public-key"), []byte("test-private-key"))
		service := flow.NewService(toker, repo, testHasher(t))
		ctx := t.Context()
		_, err := service.CreateUser(ctx, user)
		require.NoError(t, err)
		initialToken, err := service.CreateToken(ctx, user)
		require.NoError(t, err)

		rotatedToken, err := service.RefreshToken(ctx, domain.NewTokenSpec(initialToken.RefreshToken()))
		require.NoError(t, err)

		_, err = service.RefreshToken(ctx, domain.NewTokenSpec(initialToken.RefreshToken()))
		require.ErrorIs(t, err, flow.ErrInvalidToken)

		_, err = service.RefreshToken(ctx, domain.NewTokenSpec(rotatedToken.RefreshToken()))
		require.ErrorIs(t, err, flow.ErrInvalidToken)
	})

	t.Run("concurrent refresh has one successful rotation", func(t *testing.T) {
		t.Parallel()

		repo := fake.NewRepository()
		user := domain.NewUser("test", "test")
		toker := jwt.NewToker([]byte("test-public-key"), []byte("test-private-key"))
		service := flow.NewService(toker, repo, testHasher(t))
		ctx := t.Context()
		_, err := service.CreateUser(ctx, user)
		require.NoError(t, err)
		initialToken, err := service.CreateToken(ctx, user)
		require.NoError(t, err)

		var waitGroup sync.WaitGroup

		results := make(chan error, 2)

		for range 2 {
			waitGroup.Go(func() {
				_, refreshErr := service.RefreshToken(ctx, domain.NewTokenSpec(initialToken.RefreshToken()))
				results <- refreshErr
			})
		}

		waitGroup.Wait()

		close(results)

		successes := 0

		invalidTokens := 0

		for refreshErr := range results {
			if refreshErr == nil {
				successes++

				continue
			}

			require.ErrorIs(t, refreshErr, flow.ErrInvalidToken, "unexpected refresh error: %v", refreshErr)

			invalidTokens++
		}

		require.Equal(t, 1, successes)
		require.Equal(t, 1, invalidTokens)
	})

	t.Run("invalid token", func(t *testing.T) {
		t.Parallel()

		service := flow.NewService(
			jwt.NewToker([]byte("test-public-key"), []byte("test-private-key")),
			fake.NewRepository(),
			testHasher(t),
		)
		ctx := t.Context()
		spec := domain.NewTokenSpec("invalid-refresh-token")

		_, err := service.RefreshToken(ctx, spec)

		require.ErrorIs(t, err, flow.ErrInvalidToken)
	})

	t.Run("user not found", func(t *testing.T) {
		t.Parallel()

		repo := fake.NewRepository()
		user := domain.NewUser("test", "test")
		toker := jwt.NewToker([]byte("test-public-key"), []byte("test-private-key"))
		service := flow.NewService(toker, repo, testHasher(t))
		ctx := t.Context()
		_, err := service.CreateUser(ctx, user)
		require.NoError(t, err)
		token, err := service.CreateToken(ctx, user)
		require.NoError(t, err)

		spec := domain.NewTokenSpec(token.RefreshToken())
		emptyRepo := fake.NewRepository()
		serviceWithEmptyRepo := flow.NewService(toker, emptyRepo, testHasher(t))

		_, err = serviceWithEmptyRepo.RefreshToken(ctx, spec)

		require.ErrorIs(t, err, flow.ErrUserNotFound)
	})

	t.Run("empty token spec", func(t *testing.T) {
		t.Parallel()

		service := flow.NewService(
			jwt.NewToker([]byte("test-public-key"), []byte("test-private-key")),
			fake.NewRepository(),
			testHasher(t),
		)
		ctx := t.Context()
		spec := domain.NewTokenSpec("")

		_, err := service.RefreshToken(ctx, spec)

		require.ErrorIs(t, err, flow.ErrInvalidToken)
	})

	t.Run("expired token", func(t *testing.T) {
		t.Parallel()

		repo := fake.NewRepository()
		user := domain.NewUser("test", "test")
		toker := jwt.NewToker([]byte("test-public-key"), []byte("test-private-key"))
		service := flow.NewService(toker, repo, testHasher(t))
		ctx := t.Context()
		_, err := service.CreateUser(ctx, user)
		require.NoError(t, err)

		expiredSpec := domain.NewTokenSpec("expired.refresh.here")

		_, err = service.RefreshToken(ctx, expiredSpec)

		require.ErrorIs(t, err, flow.ErrInvalidToken)
	})
}

func testHasher(t *testing.T) *argon.Argon2id {
	t.Helper()

	hasher, err := argon.NewArgon2id(argon.Parameters{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
	require.NoError(t, err)

	return hasher
}

type recordingHasher struct {
	encodedHash  string
	verifyCalled bool
}

func (h *recordingHasher) Hash(string) (string, error) {
	return "", nil
}

func (h *recordingHasher) Verify(_ string, encodedHash string) (bool, error) {
	h.verifyCalled = true
	h.encodedHash = encodedHash

	return false, nil
}
