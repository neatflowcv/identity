package jwt_test

import (
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/toker/core"
	"github.com/neatflowcv/identity/internal/pkg/toker/jwt"
	"github.com/stretchr/testify/require"
)

const (
	refreshTestUser   = "user"
	refreshTestUse    = "refresh"
	refreshTestFamily = "family-id"
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

		t.Run("refresh token", func(t *testing.T) {
			t.Parallel()

			publicKey := []byte("test-public-key")
			privateKey := []byte("test-private-key")
			toker := jwt.NewToker(publicKey, privateKey)
			user := domain.NewUser("testuser", "password123")
			policy := domain.NewTokenPolicy()
			now := time.Unix(0, 0)
			token := toker.CreateToken(now, user, policy)
			spec := domain.NewTokenSpec(token.RefreshToken())

			username, err := toker.ParseToken(now, spec)

			require.NoError(t, err)
			require.Equal(t, "testuser", string(username))
		})
	})
}

func TestJWTToker_ParseToken_RequiresRefreshToken(t *testing.T) {
	t.Parallel()

	publicKey := []byte("test-public-key")
	privateKey := []byte("test-private-key")
	toker := jwt.NewToker(publicKey, privateKey)
	now := time.Unix(0, 0)
	tests := []struct {
		name         string
		refreshToken string
	}{
		{name: "empty refresh token", refreshToken: ""},
		{name: "invalid refresh token", refreshToken: "invalid-refresh-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spec := domain.NewTokenSpec(tt.refreshToken)

			_, err := toker.ParseToken(now, spec)

			require.ErrorIs(t, err, core.ErrInvalidToken)
		})
	}
}

func TestJWTToker_ParseToken_RejectsAccessToken(t *testing.T) {
	t.Parallel()

	toker := jwt.NewToker([]byte("test-public-key"), []byte("test-private-key"))
	user := domain.NewUser("testuser", "password123")
	now := time.Unix(0, 0)
	token := toker.CreateToken(now, user, domain.NewTokenPolicy())

	_, err := toker.ParseToken(now, domain.NewTokenSpec(token.AccessToken()))

	require.ErrorIs(t, err, core.ErrInvalidToken)
}

func TestJWTToker_ParseToken_InvalidToken(t *testing.T) {
	t.Parallel()

	publicKey := []byte("test-public-key")
	privateKey := []byte("test-private-key")
	toker := jwt.NewToker(publicKey, privateKey)
	spec := domain.NewTokenSpec("invalid-refresh-token")
	now := time.Unix(0, 0)

	_, err := toker.ParseToken(now, spec)

	require.ErrorIs(t, err, core.ErrInvalidToken)
}

func TestJWTToker_ParseToken_EmptyTokens(t *testing.T) {
	t.Parallel()

	publicKey := []byte("test-public-key")
	privateKey := []byte("test-private-key")
	toker := jwt.NewToker(publicKey, privateKey)
	spec := domain.NewTokenSpec("")
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
	spec := domain.NewTokenSpec(token.RefreshToken())

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
	spec := domain.NewTokenSpec(token.RefreshToken())

	_, err := toker.ParseToken(now.Add(policy.RefreshTokenTTL()), spec)

	require.ErrorIs(t, err, core.ErrInvalidToken)
}

func TestJWTToker_ParseToken_InvalidMethod(t *testing.T) {
	t.Parallel()

	publicKey := []byte("test-public-key")
	privateKey := []byte("test-private-key")
	toker := jwt.NewToker(publicKey, privateKey)
	policy := domain.NewTokenPolicy()
	now := time.Unix(0, 0)
	// RSA token generated by https://jwt.io/
	spec := domain.NewTokenSpec(`eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ`) //nolint:lll

	_, err := toker.ParseToken(now.Add(policy.RefreshTokenTTL()), spec)

	require.ErrorIs(t, err, core.ErrInvalidToken)
}

func TestJWTToker_ParseRefreshToken_ClaimsErrorsAreIndistinguishable(t *testing.T) {
	t.Parallel()

	toker := jwt.NewToker([]byte("test-public-key"), []byte("test-private-key"))
	now := time.Now()
	cases := []struct {
		name   string
		claims refreshTestClaims
	}{
		{
			name: "not yet valid",
			claims: refreshTestClaims{
				RegisteredClaims: jwtv5.RegisteredClaims{ //nolint:exhaustruct
					ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
					IssuedAt:  jwtv5.NewNumericDate(now),
					NotBefore: jwtv5.NewNumericDate(now.Add(time.Minute)),
					ID:        "token-id",
					Subject:   refreshTestUser,
				},
				Username: refreshTestUser,
				TokenUse: refreshTestUse,
				FamilyID: refreshTestFamily,
			},
		},
		{
			name: "used before issued",
			claims: refreshTestClaims{
				RegisteredClaims: jwtv5.RegisteredClaims{ //nolint:exhaustruct
					ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
					IssuedAt:  jwtv5.NewNumericDate(now.Add(time.Minute)),
					ID:        "token-id",
					Subject:   refreshTestUser,
				},
				Username: refreshTestUser,
				TokenUse: refreshTestUse,
				FamilyID: refreshTestFamily,
			},
		},
		{
			name: "invalid required claims",
			claims: refreshTestClaims{
				RegisteredClaims: jwtv5.RegisteredClaims{}, //nolint:exhaustruct
				Username:         "",
				TokenUse:         refreshTestUse,
				FamilyID:         refreshTestFamily,
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			token := signRefreshTestClaims(t, []byte("test-private-key"), testCase.claims)
			_, err := toker.ParseRefreshToken(now, domain.NewTokenSpec(token))

			require.ErrorIs(t, err, core.ErrInvalidToken)
			require.Equal(t, core.ErrInvalidToken.Error(), err.Error())
		})
	}
}

type refreshTestClaims struct {
	jwtv5.RegisteredClaims

	Username string `json:"username"`
	TokenUse string `json:"token_use"`
	FamilyID string `json:"family_id"`
}

func signRefreshTestClaims(t *testing.T, key []byte, claims refreshTestClaims) string {
	t.Helper()

	token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
	signed, err := token.SignedString(key)
	require.NoError(t, err)

	return signed
}
