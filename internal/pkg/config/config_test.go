package config_test

import (
	"testing"

	"github.com/neatflowcv/identity/internal/pkg/config"
	"github.com/stretchr/testify/require"
)

const (
	jwtPublicKeyEnv  = "JWT_PUBLIC_KEY"
	jwtPrivateKeyEnv = "JWT_PRIVATE_KEY"
	databaseURLEnv   = "DATABASE_URL"
	testDatabaseURL  = "postgres://managed-user@example/identity"
)

func TestLoadUsesEnvironmentValues(t *testing.T) {
	t.Parallel()

	publicKey := "public-key-with-at-least-32-bytes-1234"
	privateKey := "private-key-with-at-least-32-bytes-5678"
	databaseURL := testDatabaseURL
	getenv := environment(map[string]string{
		"PORT":           "8081",
		jwtPublicKeyEnv:  publicKey,
		jwtPrivateKeyEnv: privateKey,
		databaseURLEnv:   databaseURL,
	})

	loadedConfig, err := config.Load(getenv)

	require.NoError(t, err)
	require.Equal(t, 8081, loadedConfig.Port)
	require.Equal(t, []byte(publicKey), loadedConfig.JWTPublicKey)
	require.Equal(t, []byte(privateKey), loadedConfig.JWTPrivateKey)
	require.Equal(t, databaseURL, loadedConfig.DatabaseURL)
}

func TestLoadUsesDefaultPort(t *testing.T) {
	t.Parallel()

	getenv := environment(map[string]string{
		jwtPublicKeyEnv:  validKey("public"),
		jwtPrivateKeyEnv: validKey("private"),
		databaseURLEnv:   testDatabaseURL,
	})

	loadedConfig, err := config.Load(getenv)

	require.NoError(t, err)
	require.Equal(t, 8080, loadedConfig.Port)
}

func TestLoadRequiresPublicKey(t *testing.T) {
	t.Parallel()

	getenv := environment(map[string]string{
		jwtPrivateKeyEnv: validKey("private"),
		databaseURLEnv:   testDatabaseURL,
	})

	_, err := config.Load(getenv)

	require.ErrorIs(t, err, config.ErrPublicKeyRequired)
}

func TestLoadRejectsShortPublicKey(t *testing.T) {
	t.Parallel()

	getenv := environment(map[string]string{
		jwtPublicKeyEnv:  "short-key",
		jwtPrivateKeyEnv: validKey("private"),
		databaseURLEnv:   testDatabaseURL,
	})

	_, err := config.Load(getenv)

	require.ErrorIs(t, err, config.ErrPublicKeyTooShort)
}

func TestLoadRequiresPrivateKey(t *testing.T) {
	t.Parallel()

	getenv := environment(map[string]string{
		jwtPublicKeyEnv: validKey("public"),
		databaseURLEnv:  testDatabaseURL,
	})

	_, err := config.Load(getenv)

	require.ErrorIs(t, err, config.ErrPrivateKeyRequired)
}

func TestLoadRejectsShortPrivateKey(t *testing.T) {
	t.Parallel()

	getenv := environment(map[string]string{
		jwtPublicKeyEnv:  validKey("public"),
		jwtPrivateKeyEnv: "short-key",
		databaseURLEnv:   testDatabaseURL,
	})

	_, err := config.Load(getenv)

	require.ErrorIs(t, err, config.ErrPrivateKeyTooShort)
}

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Parallel()

	getenv := environment(map[string]string{
		jwtPublicKeyEnv:  validKey("public"),
		jwtPrivateKeyEnv: validKey("private"),
	})

	_, err := config.Load(getenv)

	require.ErrorIs(t, err, config.ErrDatabaseURLRequired)
}

func TestLoadRejectsInvalidPort(t *testing.T) {
	t.Parallel()

	getenv := environment(map[string]string{
		"PORT":           "65536",
		jwtPublicKeyEnv:  validKey("public"),
		jwtPrivateKeyEnv: validKey("private"),
		databaseURLEnv:   testDatabaseURL,
	})

	_, err := config.Load(getenv)

	require.ErrorIs(t, err, config.ErrInvalidPort)
}

func environment(values map[string]string) func(string) string {
	return func(name string) string {
		return values[name]
	}
}

func validKey(prefix string) string {
	return prefix + "-key-with-at-least-32-bytes-1234"
}
