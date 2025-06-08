package jwt_test

import (
	"testing"

	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/toker/jwt"
	"github.com/stretchr/testify/require"
)

func TestJWTToker_CreateToken(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {

		secretKey := []byte("test-secret-key")
		toker := jwt.NewToker(secretKey)

		user := domain.NewUser("testuser", "password123")
		policy := domain.NewTokenPolicy()

		token := toker.CreateToken(user, policy)

		require.NotNil(t, token)
		require.NotEmpty(t, token.AccessToken())
		require.NotEmpty(t, token.RefreshToken())
		require.Equal(t, domain.TokenTypeBearer, token.TokenType())
		require.NotNil(t, token.Payload())
		require.Equal(t, "testuser", token.Payload().Username())
		require.Positive(t, token.ExpiresIn())
	})
}

func TestJWTToker_ParseToken_WithAccessToken(t *testing.T) {
	t.Parallel()

	secretKey := []byte("test-secret-key")
	toker := jwt.NewToker(secretKey)
	user := domain.NewUser("testuser", "password123")
	policy := domain.NewTokenPolicy()
	token := toker.CreateToken(user, policy)
	spec := domain.NewTokenSpec(token.AccessToken(), "")

	username, err := toker.ParseToken(spec)

	require.NoError(t, err)
	require.Equal(t, "testuser", string(username))
}

func TestJWTToker_ParseToken_WithRefreshToken(t *testing.T) {
	t.Parallel()

	secretKey := []byte("test-secret-key")
	toker := jwt.NewToker(secretKey)

	user := domain.NewUser("testuser", "password123")
	policy := domain.NewTokenPolicy()

	token := toker.CreateToken(user, policy)

	spec := domain.NewTokenSpec("", token.RefreshToken())
	username, err := toker.ParseToken(spec)
	require.NoError(t, err)
	require.Equal(t, "testuser", string(username))
}

func TestJWTToker_ParseToken_WithBothTokens(t *testing.T) {
	t.Parallel()

	secretKey := []byte("test-secret-key")
	toker := jwt.NewToker(secretKey)

	user := domain.NewUser("testuser", "password123")
	policy := domain.NewTokenPolicy()

	token := toker.CreateToken(user, policy)

	spec := domain.NewTokenSpec(token.AccessToken(), token.RefreshToken())
	username, err := toker.ParseToken(spec)
	require.NoError(t, err)
	require.Equal(t, "testuser", string(username))
}

func TestJWTToker_ParseToken_InvalidToken(t *testing.T) {
	t.Parallel()

	secretKey := []byte("test-secret-key")
	toker := jwt.NewToker(secretKey)

	spec := domain.NewTokenSpec("invalid-token", "invalid-refresh-token")
	_, err := toker.ParseToken(spec)
	require.Error(t, err)
}

func TestJWTToker_ParseToken_EmptyTokens(t *testing.T) {
	t.Parallel()

	secretKey := []byte("test-secret-key")
	toker := jwt.NewToker(secretKey)

	spec := domain.NewTokenSpec("", "")
	_, err := toker.ParseToken(spec)
	require.Error(t, err)
}

func TestJWTToker_ParseToken_DifferentSecretKey(t *testing.T) {
	t.Parallel()

	// Create token with one secret key
	secretKey1 := []byte("secret-key-1")
	toker1 := jwt.NewToker(secretKey1)

	user := domain.NewUser("testuser", "password123")
	policy := domain.NewTokenPolicy()

	token := toker1.CreateToken(user, policy)

	secretKey2 := []byte("secret-key-2")
	toker2 := jwt.NewToker(secretKey2)

	spec := domain.NewTokenSpec(token.AccessToken(), token.RefreshToken())
	_, err := toker2.ParseToken(spec)
	require.Error(t, err)
}

func TestJWTToker_TokenRoundTrip(t *testing.T) {
	t.Parallel()

	secretKey := []byte("test-secret-key")
	toker := jwt.NewToker(secretKey)

	testCases := []struct {
		name     string
		username string
		password string
	}{
		{"basic user", "user1", "pass1"},
		{"user with special chars", "user@domain.com", "p@ssw0rd!"},
		{"user with spaces", "user name", "password with spaces"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			user := domain.NewUser(tc.username, tc.password)
			policy := domain.NewTokenPolicy()

			token := toker.CreateToken(user, policy)

			spec := domain.NewTokenSpec(token.AccessToken(), token.RefreshToken())
			username, err := toker.ParseToken(spec)
			require.NoError(t, err)
			require.Equal(t, tc.username, string(username))
		})
	}
}
