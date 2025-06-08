package jwt_test

import (
	"testing"
	"time"

	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/toker/core"
	"github.com/neatflowcv/identity/internal/pkg/toker/jwt"
	"github.com/stretchr/testify/require"
)

func TestJWTToker_CreateToken(t *testing.T) {
	t.Parallel()

	publicKey := []byte("test-public-key")
	privateKey := []byte("test-private-key")
	toker := jwt.NewToker(publicKey, privateKey)
	user := domain.NewUser("testuser", "password123")
	policy := domain.NewTokenPolicy()
	now := time.Unix(0, 0)

	token := toker.CreateToken(now, user, policy)

	require.NotNil(t, token)
	require.NotEmpty(t, token.AccessToken())
	require.NotEmpty(t, token.RefreshToken())
	require.Equal(t, domain.TokenTypeBearer, token.TokenType())
	require.NotNil(t, token.Payload())
	require.Equal(t, "testuser", token.Payload().Username())
	require.Positive(t, token.ExpiresIn())
}

func TestJWTToker_ParseToken(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		t.Run("access token", func(t *testing.T) {
			t.Parallel()

			publicKey := []byte("test-public-key")
			privateKey := []byte("test-private-key")
			toker := jwt.NewToker(publicKey, privateKey)
			user := domain.NewUser("testuser", "password123")
			policy := domain.NewTokenPolicy()
			now := time.Unix(0, 0)
			token := toker.CreateToken(now, user, policy)
			spec := domain.NewTokenSpec(token.AccessToken(), "")

			username, err := toker.ParseToken(now, spec)

			require.NoError(t, err)
			require.Equal(t, "testuser", string(username))
		})

		t.Run("refresh token", func(t *testing.T) {
			t.Parallel()

			publicKey := []byte("test-public-key")
			privateKey := []byte("test-private-key")
			toker := jwt.NewToker(publicKey, privateKey)
			user := domain.NewUser("testuser", "password123")
			policy := domain.NewTokenPolicy()
			now := time.Unix(0, 0)
			token := toker.CreateToken(now, user, policy)
			spec := domain.NewTokenSpec("", token.RefreshToken())

			username, err := toker.ParseToken(now, spec)

			require.NoError(t, err)
			require.Equal(t, "testuser", string(username))
		})

		t.Run("both tokens", func(t *testing.T) {
			t.Parallel()

			publicKey := []byte("test-public-key")
			privateKey := []byte("test-private-key")
			toker := jwt.NewToker(publicKey, privateKey)
			user := domain.NewUser("testuser", "password123")
			policy := domain.NewTokenPolicy()
			now := time.Unix(0, 0)
			token := toker.CreateToken(now, user, policy)
			spec := domain.NewTokenSpec(token.AccessToken(), token.RefreshToken())

			username, err := toker.ParseToken(now, spec)

			require.NoError(t, err)
			require.Equal(t, "testuser", string(username))
		})
	})
}

func TestJWTToker_ParseToken_InvalidToken(t *testing.T) {
	t.Parallel()

	publicKey := []byte("test-public-key")
	privateKey := []byte("test-private-key")
	toker := jwt.NewToker(publicKey, privateKey)
	spec := domain.NewTokenSpec("invalid-token", "invalid-refresh-token")
	now := time.Unix(0, 0)

	_, err := toker.ParseToken(now, spec)

	require.ErrorIs(t, err, core.ErrInvalidToken)
}

func TestJWTToker_ParseToken_EmptyTokens(t *testing.T) {
	t.Parallel()

	publicKey := []byte("test-public-key")
	privateKey := []byte("test-private-key")
	toker := jwt.NewToker(publicKey, privateKey)
	spec := domain.NewTokenSpec("", "")
	now := time.Unix(0, 0)

	_, err := toker.ParseToken(now, spec)

	require.ErrorIs(t, err, core.ErrInvalidToken)
}

func TestJWTToker_ParseToken_DifferentSecretKey(t *testing.T) {
	t.Parallel()

	// Create token with one secret key
	publicKey1 := []byte("test-public-key-1")
	privateKey1 := []byte("test-private-key-1")
	toker1 := jwt.NewToker(publicKey1, privateKey1)
	user := domain.NewUser("testuser", "password123")
	policy := domain.NewTokenPolicy()
	now := time.Unix(0, 0)
	token := toker1.CreateToken(now, user, policy)
	publicKey2 := []byte("test-public-key-2")
	privateKey2 := []byte("test-private-key-2")
	toker2 := jwt.NewToker(publicKey2, privateKey2)
	spec := domain.NewTokenSpec(token.AccessToken(), token.RefreshToken())

	_, err := toker2.ParseToken(now, spec)

	require.ErrorIs(t, err, core.ErrInvalidToken)
}

func TestJWTToker_ParseToken_ExpiredRefreshToken(t *testing.T) {
	t.Parallel()

	publicKey := []byte("test-public-key")
	privateKey := []byte("test-private-key")
	toker := jwt.NewToker(publicKey, privateKey)
	user := domain.NewUser("testuser", "password123")
	policy := domain.NewTokenPolicy()
	now := time.Unix(0, 0)
	token := toker.CreateToken(now, user, policy)
	spec := domain.NewTokenSpec(token.AccessToken(), token.RefreshToken())

	_, err := toker.ParseToken(now.Add(policy.RefreshTokenTTL()), spec)

	require.ErrorIs(t, err, core.ErrInvalidToken)
}

func TestJWTToker_ParseToken_InvalidMethod(t *testing.T) {
	t.Parallel()

	publicKey := []byte("test-public-key")
	privateKey := []byte("test-private-key")
	toker := jwt.NewToker(publicKey, privateKey)
	user := domain.NewUser("testuser", "password123")
	policy := domain.NewTokenPolicy()
	now := time.Unix(0, 0)
	token := toker.CreateToken(now, user, policy)
	// RSA token generated by https://jwt.io/
	spec := domain.NewTokenSpec(`eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ`, token.RefreshToken()) //nolint:lll

	_, err := toker.ParseToken(now.Add(policy.RefreshTokenTTL()), spec)

	require.ErrorIs(t, err, core.ErrInvalidToken)
}
