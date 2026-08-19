package config

import (
	"errors"
	"strconv"
	"strings"
)

const (
	defaultPort     = 8080
	minJWTKeyLength = 32
	publicKeyEnv    = "JWT_PUBLIC_KEY"
	privateKeyEnv   = "JWT_PRIVATE_KEY"
	databaseURLEnv  = "DATABASE_URL"
)

var (
	ErrInvalidPort         = errors.New("invalid PORT: must be an integer between 1 and 65535")
	ErrPublicKeyRequired   = errors.New("JWT_PUBLIC_KEY is required")
	ErrPublicKeyTooShort   = errors.New("JWT_PUBLIC_KEY must be at least 32 bytes")
	ErrPrivateKeyRequired  = errors.New("JWT_PRIVATE_KEY is required")
	ErrPrivateKeyTooShort  = errors.New("JWT_PRIVATE_KEY must be at least 32 bytes")
	ErrDatabaseURLRequired = errors.New("DATABASE_URL is required")
)

type Config struct {
	Port          int
	JWTPublicKey  []byte
	JWTPrivateKey []byte
	DatabaseURL   string
}

func Load(getenv func(string) string) (Config, error) {
	port := defaultPort
	portValue := getenv("PORT")

	if portValue != "" {
		parsedPort, err := strconv.Atoi(portValue)
		if err != nil || parsedPort < 1 || parsedPort > 65535 {
			return Config{}, ErrInvalidPort
		}

		port = parsedPort
	}

	publicKey, err := requiredJWTKey(getenv, publicKeyEnv)
	if err != nil {
		return Config{}, err
	}

	privateKey, err := requiredJWTKey(getenv, privateKeyEnv)
	if err != nil {
		return Config{}, err
	}

	databaseURL := getenv(databaseURLEnv)
	if strings.TrimSpace(databaseURL) == "" {
		return Config{}, ErrDatabaseURLRequired
	}

	return Config{
		Port:          port,
		JWTPublicKey:  publicKey,
		JWTPrivateKey: privateKey,
		DatabaseURL:   databaseURL,
	}, nil
}

func requiredJWTKey(getenv func(string) string, name string) ([]byte, error) {
	value := getenv(name)
	if strings.TrimSpace(value) == "" {
		if name == publicKeyEnv {
			return nil, ErrPublicKeyRequired
		}

		return nil, ErrPrivateKeyRequired
	}

	if len([]byte(value)) < minJWTKeyLength {
		if name == publicKeyEnv {
			return nil, ErrPublicKeyTooShort
		}

		return nil, ErrPrivateKeyTooShort
	}

	return []byte(value), nil
}
