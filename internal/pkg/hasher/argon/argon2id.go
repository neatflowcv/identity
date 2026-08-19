package argon

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/neatflowcv/identity/internal/pkg/hasher"
	"golang.org/x/crypto/argon2"
)

const (
	algorithm = "argon2id"
	version   = 19

	// These limits protect the login endpoint from attacker-controlled work factors.
	maxMemoryKiB   = 256 * 1024
	maxIterations  = 10
	maxParallelism = 8
	minSaltLength  = 16
	maxSaltLength  = 64
	minKeyLength   = 16
	maxKeyLength   = 64
	maxConcurrent  = 4
	defaultMemory  = 64 * 1024
	defaultTime    = 3
	defaultThreads = 4
	defaultSalt    = 16
	defaultKey     = 32
	parameterCount = 3
)

// Shared process-wide KDF concurrency limit.
var workSemaphore = make(chan struct{}, maxConcurrent) //nolint:gochecknoglobals

var (
	errInvalidHashFormat     = errors.New("invalid password hash format")
	errUnsupportedVersion    = errors.New("unsupported password hash version")
	errInvalidSalt           = errors.New("invalid password salt")
	errInvalidKey            = errors.New("invalid password key")
	errInvalidParameters     = errors.New("invalid password parameters")
	errParametersTooLarge    = errors.New("password parameters exceed safe limits")
	errInvalidParameter      = errors.New("invalid password parameter")
	errMemoryOutOfRange      = errors.New("password memory parameter is outside the safe range")
	errIterationsOutOfRange  = errors.New("password iteration parameter is outside the safe range")
	errParallelismOutOfRange = errors.New("password parallelism parameter is outside the safe range")
	errMemoryTooSmall        = errors.New("password memory parameter is too small")
	errSaltLengthOutOfRange  = errors.New("password salt length is outside the safe range")
	errKeyLengthOutOfRange   = errors.New("password key length is outside the safe range")
)

// Parameters controls the Argon2id work factor used for newly-created hashes.
// Benchmark this configuration on the production hardware and adjust it to the
// login latency and concurrency budget before deploying at scale.
type Parameters struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// Argon2id implements hasher.Hasher using the Argon2id variant from x/crypto.
type Argon2id struct {
	parameters Parameters
}

var _ hasher.Hasher = (*Argon2id)(nil)

// NewArgon2id creates an Argon2id hasher with the supplied parameters.
func NewArgon2id(parameters Parameters) (*Argon2id, error) {
	err := validateParameters(parameters)
	if err != nil {
		return nil, err
	}

	if parameters.SaltLength == 0 || parameters.KeyLength == 0 {
		return nil, errInvalidParameters
	}

	return &Argon2id{parameters: parameters}, nil
}

// NewDefaultArgon2id returns a practical starting configuration. The values
// must be benchmarked and tuned for the deployment hardware and concurrency.
func NewDefaultArgon2id() *Argon2id {
	hasher, err := NewArgon2id(Parameters{
		Memory:      defaultMemory,
		Iterations:  defaultTime,
		Parallelism: defaultThreads,
		SaltLength:  defaultSalt,
		KeyLength:   defaultKey,
	})
	if err != nil {
		panic("invalid default Argon2id parameters: " + err.Error())
	}

	return hasher
}

// Hash returns a self-contained PHC-style Argon2id string.
func (h *Argon2id) Hash(password string) (string, error) {
	salt := make([]byte, h.parameters.SaltLength)

	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	key := h.derive(password, salt, h.parameters)

	return formatHash(h.parameters, salt, key), nil
}

// Verify returns false for malformed, unsupported, or unsafe encoded hashes.
// Such values are authentication failures, not server errors.
func (h *Argon2id) Verify(password string, encodedHash string) (bool, error) {
	parsed, err := parseHash(encodedHash)
	if err != nil {
		return false, nil //nolint:nilerr // malformed hashes are authentication failures
	}

	key := h.derive(password, parsed.salt, parsed.parameters)

	if len(key) != len(parsed.key) {
		return false, nil
	}

	return subtle.ConstantTimeCompare(key, parsed.key) == 1, nil
}

func (h *Argon2id) derive(password string, salt []byte, parameters Parameters) []byte {
	workSemaphore <- struct{}{}
	defer func() {
		<-workSemaphore
	}()

	return argon2.IDKey(
		[]byte(password),
		salt,
		parameters.Iterations,
		parameters.Memory,
		parameters.Parallelism,
		parameters.KeyLength,
	)
}

type parsedHash struct {
	parameters Parameters
	salt       []byte
	key        []byte
}

func formatHash(parameters Parameters, salt []byte, key []byte) string {
	encode := base64.RawStdEncoding.EncodeToString

	return fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		algorithm,
		version,
		parameters.Memory,
		parameters.Iterations,
		parameters.Parallelism,
		encode(salt),
		encode(key),
	)
}

func parseHash(encodedHash string) (parsedHash, error) { //nolint:cyclop // every untrusted PHC field is validated
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != algorithm {
		return parsedHash{}, errInvalidHashFormat
	}

	parsedVersion, err := parseUintField(parts[2], "v")
	if err != nil || parsedVersion != version {
		return parsedHash{}, errUnsupportedVersion
	}

	parameters, err := parseParameters(parts[3])
	if err != nil {
		return parsedHash{}, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < minSaltLength || len(salt) > maxSaltLength {
		return parsedHash{}, errInvalidSalt
	}

	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < minKeyLength || len(key) > maxKeyLength {
		return parsedHash{}, errInvalidKey
	}

	parameters.SaltLength = uint32(len(salt)) //nolint:gosec // decoded length is bounded above
	parameters.KeyLength = uint32(len(key))   //nolint:gosec // decoded length is bounded above

	return parsedHash{
		parameters: parameters,
		salt:       salt,
		key:        key,
	}, nil
}

func parseParameters(encodedParameters string) (Parameters, error) {
	parts := strings.Split(encodedParameters, ",")
	if len(parts) != parameterCount {
		return Parameters{}, errInvalidParameters
	}

	memory, err := parseUintField(parts[0], "m")
	if err != nil {
		return Parameters{}, err
	}

	iterations, err := parseUintField(parts[1], "t")
	if err != nil {
		return Parameters{}, err
	}

	parallelism, err := parseUintField(parts[2], "p")
	if err != nil {
		return Parameters{}, err
	}

	if memory > maxMemoryKiB || iterations > maxIterations || parallelism > maxParallelism {
		return Parameters{}, errParametersTooLarge
	}

	parameters := Parameters{
		Memory:      uint32(memory),
		Iterations:  uint32(iterations),
		Parallelism: uint8(parallelism),
		SaltLength:  0,
		KeyLength:   0,
	}

	err = validateParameters(parameters)
	if err != nil {
		return Parameters{}, err
	}

	return parameters, nil
}

func parseUintField(value string, name string) (uint64, error) {
	parts := strings.Split(value, "=")
	if len(parts) != 2 || parts[0] != name || parts[1] == "" {
		return 0, errInvalidParameter
	}

	parsed, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, errInvalidParameter
	}

	return parsed, nil
}

//nolint:cyclop // independent bounds protect each untrusted cost field
func validateParameters(parameters Parameters) error {
	if parameters.Memory == 0 || parameters.Memory > maxMemoryKiB {
		return errMemoryOutOfRange
	}

	if parameters.Iterations == 0 || parameters.Iterations > maxIterations {
		return errIterationsOutOfRange
	}

	if parameters.Parallelism == 0 || parameters.Parallelism > maxParallelism {
		return errParallelismOutOfRange
	}

	if parameters.Memory < uint32(parameters.Parallelism)*8 {
		return errMemoryTooSmall
	}

	if parameters.SaltLength != 0 && (parameters.SaltLength < minSaltLength || parameters.SaltLength > maxSaltLength) {
		return errSaltLengthOutOfRange
	}

	if parameters.KeyLength != 0 && (parameters.KeyLength < minKeyLength || parameters.KeyLength > maxKeyLength) {
		return errKeyLengthOutOfRange
	}

	return nil
}
