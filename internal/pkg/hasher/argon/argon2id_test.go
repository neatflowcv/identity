package argon_test

import (
	"strings"
	"testing"

	"github.com/neatflowcv/identity/internal/pkg/hasher/argon"
	"github.com/stretchr/testify/require"
)

func TestArgon2idHashAndVerify(t *testing.T) {
	t.Parallel()

	hasher := newTestHasher(t)
	hash, err := hasher.Hash("correct horse battery staple")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(hash, "$argon2id$v=19$m=8192,t=1,p=1$"))
	require.NotContains(t, hash, "correct horse battery staple")

	verified, err := hasher.Verify("correct horse battery staple", hash)
	require.NoError(t, err)
	require.True(t, verified)
}

func TestArgon2idUsesUniqueSalt(t *testing.T) {
	t.Parallel()

	hasher := newTestHasher(t)
	firstHash, err := hasher.Hash("same password")
	require.NoError(t, err)
	secondHash, err := hasher.Hash("same password")
	require.NoError(t, err)

	require.NotEqual(t, firstHash, secondHash)
}

func TestArgon2idRejectsInvalidPasswordsAndHashes(t *testing.T) {
	t.Parallel()

	hasher := newTestHasher(t)
	hash, err := hasher.Hash("correct password")
	require.NoError(t, err)

	verified, err := hasher.Verify("wrong password", hash)
	require.NoError(t, err)
	require.False(t, verified)

	verified, err = hasher.Verify("correct password", "$argon2id$v=19$m=999999999,t=1,p=1$invalid$invalid")
	require.NoError(t, err)
	require.False(t, verified)

	verified, err = hasher.Verify("correct password", "not-a-password-hash")
	require.NoError(t, err)
	require.False(t, verified)
}

func newTestHasher(t *testing.T) *argon.Argon2id {
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
