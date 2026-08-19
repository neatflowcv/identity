package httpapi_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/neatflowcv/identity/internal/app/flow"
	"github.com/neatflowcv/identity/internal/app/transport/httpapi"
	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/hasher"
	"github.com/neatflowcv/identity/internal/pkg/hasher/argon"
	"github.com/neatflowcv/identity/internal/pkg/repository/fake"
	"github.com/neatflowcv/identity/internal/pkg/toker/jwt"
	"github.com/stretchr/testify/require"
)

type problemResponse struct {
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

type recordingLogger struct {
	category  string
	operation string
}

const (
	sensitivePassword = "sensitive-password"
	refreshUser       = "user"
	refreshTokenID    = "token-id"
	refreshFamilyID   = "family-id"
	refreshUse        = "refresh"
)

var errInternalCause = errors.New("password hash backend failed: internal-detail")

func TestCreateTokenDoesNotRevealAccountExistence(t *testing.T) {
	t.Parallel()

	repository := fake.NewRepository()
	service := newTestService(t, repository)
	router := newRouter(service)

	notFound := postToken(t, router, "missing", "password")

	_, err := service.CreateUser(t.Context(), domain.NewUser("existing", "password"))
	require.NoError(t, err)

	wrongPassword := postToken(t, router, "existing", "wrong-password")

	require.Equal(t, http.StatusUnauthorized, notFound.Code)
	require.Equal(t, notFound.Code, wrongPassword.Code)
	require.Equal(t, notFound.Body.String(), wrongPassword.Body.String())
	require.Contains(t, notFound.Body.String(), "invalid username or password")
	require.NotContains(t, notFound.Body.String(), flow.ErrUserNotFound.Error())
	require.NotContains(t, wrongPassword.Body.String(), flow.ErrAuthenticationFailed.Error())
}

func TestHTTPErrorDoesNotExposeInternalCause(t *testing.T) {
	t.Parallel()

	service := flow.NewService(nil, fake.NewRepository(), failingHasher{err: errInternalCause})
	router := newRouter(service)

	request := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/identity/v1/users",
		strings.NewReader(`{"user":{"username":"user","password":"password"}}`),
	)
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	var problem problemResponse

	err := json.NewDecoder(response.Body).Decode(&problem)
	require.NoError(t, err)
	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.Equal(t, http.StatusInternalServerError, problem.Status)
	require.Equal(t, "internal server error", problem.Detail)
	require.NotContains(t, response.Body.String(), errInternalCause.Error())
}

func TestHTTPInputErrorsDoNotEchoSensitiveValues(t *testing.T) {
	t.Parallel()

	router := newRouter(newTestService(t, fake.NewRepository()))
	cases := []struct {
		name   string
		path   string
		body   string
		secret string
	}{
		{
			name:   "malformed login JSON",
			path:   "/identity/v1/tokens",
			body:   `{"user":{"username":"sensitive-user","password":"` + sensitivePassword + `"}`,
			secret: sensitivePassword,
		},
		{
			name:   "invalid login field type",
			path:   "/identity/v1/tokens",
			body:   `{"user":{"username":"sensitive-user","password":["` + sensitivePassword + `"]}}`,
			secret: sensitivePassword,
		},
		{
			name:   "malformed refresh JSON",
			path:   "/identity/v1/refresh",
			body:   `{"token":{"refresh_token":"sensitive-refresh-token"}`,
			secret: "sensitive-refresh-token",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			response := postJSON(t, router, testCase.path, testCase.body)
			assertSafeInputError(t, response, testCase.secret)
		})
	}
}

func TestDuplicateUserConflictUsesGenericMessage(t *testing.T) {
	t.Parallel()

	service := newTestService(t, fake.NewRepository())
	router := newRouter(service)
	username := "duplicate-user"
	password := "duplicate-password"

	created := postUser(t, router, username, password)
	duplicate := postUser(t, router, username, password)

	require.Equal(t, http.StatusNoContent, created.Code)
	require.Equal(t, http.StatusConflict, duplicate.Code)
	require.Contains(t, duplicate.Body.String(), "unable to create user")
	require.NotContains(t, duplicate.Body.String(), username)
	require.NotContains(t, duplicate.Body.String(), password)
}

func TestFailureLoggerReceivesNoSensitiveValues(t *testing.T) {
	t.Parallel()

	logger := &recordingLogger{category: "", operation: ""}
	service := flow.NewService(nil, fake.NewRepository(), failingHasher{err: errInternalCause})
	router := httpapi.NewRouterWithLogger(service, logger)
	secretUsername := "sensitive-user"
	secretPassword := "sensitive-password"

	response := postUser(t, router, secretUsername, secretPassword)

	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.Equal(t, "create_user", logger.operation)
	require.Equal(t, "internal", logger.category)
	require.NotContains(t, logger.operation, secretUsername)
	require.NotContains(t, logger.category, secretPassword)
}

func TestRefreshTokenErrorIsGeneric(t *testing.T) {
	t.Parallel()

	service := newTestService(t, fake.NewRepository())
	router := newRouter(service)
	request := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/identity/v1/refresh",
		strings.NewReader(`{"token":{"refresh_token":"malformed-token"}}`),
	)
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	var problem problemResponse

	err := json.NewDecoder(response.Body).Decode(&problem)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.Equal(t, "invalid refresh token", problem.Detail)
	require.NotContains(t, response.Body.String(), flow.ErrInvalidToken.Error())
}

func TestRefreshFailureTypesHaveSameHTTPResponse(t *testing.T) { //nolint:funlen
	t.Parallel()

	key := []byte("test-private-key")
	now := time.Now()
	service := newTestService(t, fake.NewRepository())
	router := newRouter(service)
	refreshFailures := []string{
		"malformed-token",
		signedRefreshToken(t, []byte("wrong-signing-key"), refreshClaims{
			RegisteredClaims: jwtv5.RegisteredClaims{ //nolint:exhaustruct
				ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwtv5.NewNumericDate(now),
				ID:        refreshTokenID,
				Subject:   refreshUser,
			},
			Username: refreshUser,
			TokenUse: refreshUse,
			FamilyID: refreshFamilyID,
		}),
		signedRefreshToken(t, key, refreshClaims{
			RegisteredClaims: jwtv5.RegisteredClaims{ //nolint:exhaustruct
				ExpiresAt: jwtv5.NewNumericDate(now.Add(-time.Minute)),
				IssuedAt:  jwtv5.NewNumericDate(now.Add(-2 * time.Minute)),
				ID:        refreshTokenID,
				Subject:   refreshUser,
			},
			Username: refreshUser,
			TokenUse: refreshUse,
			FamilyID: refreshFamilyID,
		}),
		signedRefreshToken(t, key, refreshClaims{
			RegisteredClaims: jwtv5.RegisteredClaims{ //nolint:exhaustruct
				ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwtv5.NewNumericDate(now),
				NotBefore: jwtv5.NewNumericDate(now.Add(time.Minute)),
				ID:        refreshTokenID,
				Subject:   refreshUser,
			},
			Username: refreshUser,
			TokenUse: refreshUse,
			FamilyID: refreshFamilyID,
		}),
		signedRefreshToken(t, key, refreshClaims{
			RegisteredClaims: jwtv5.RegisteredClaims{ //nolint:exhaustruct
				ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwtv5.NewNumericDate(now.Add(time.Minute)),
				ID:        refreshTokenID,
				Subject:   refreshUser,
			},
			Username: refreshUser,
			TokenUse: refreshUse,
			FamilyID: refreshFamilyID,
		}),
		signedRefreshToken(t, key, refreshClaims{
			RegisteredClaims: jwtv5.RegisteredClaims{}, //nolint:exhaustruct
			TokenUse:         refreshUse,
			FamilyID:         refreshFamilyID,
			Username:         "",
		}),
	}

	responses := make([]*httptest.ResponseRecorder, 0, len(refreshFailures)+1)
	for _, refreshToken := range refreshFailures {
		responses = append(responses, postRefresh(t, router, refreshToken))
	}

	userRepo := fake.NewRepository()
	userService := newTestService(t, userRepo)
	_, err := userService.CreateUser(t.Context(), domain.NewUser("deleted-user", "password"))
	require.NoError(t, err)
	deletedUserToken, err := userService.CreateToken(t.Context(), domain.NewUser("deleted-user", "password"))
	require.NoError(t, err)
	deletedUserRouter := newRouter(newTestService(t, fake.NewRepository()))
	responses = append(responses, postRefresh(t, deletedUserRouter, deletedUserToken.RefreshToken()))

	for _, response := range responses {
		require.Equal(t, http.StatusUnauthorized, response.Code)
		require.Equal(t, responses[0].Body.String(), response.Body.String())
		require.Contains(t, response.Body.String(), "invalid refresh token")
	}
}

func newRouter(service *flow.Service) http.Handler {
	return httpapi.NewRouter(service)
}

func postToken(t *testing.T, router http.Handler, username string, password string) *httptest.ResponseRecorder {
	t.Helper()

	body := `{"user":{"username":"` + username + `","password":"` + password + `"}}`
	request := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/identity/v1/tokens",
		strings.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	return response
}

func postUser(t *testing.T, router http.Handler, username string, password string) *httptest.ResponseRecorder {
	t.Helper()

	body := `{"user":{"username":"` + username + `","password":"` + password + `"}}`

	return postJSON(t, router, "/identity/v1/users", body)
}

func postRefresh(t *testing.T, router http.Handler, refreshToken string) *httptest.ResponseRecorder {
	t.Helper()

	body := `{"token":{"refresh_token":"` + refreshToken + `"}}`

	return postJSON(t, router, "/identity/v1/refresh", body)
}

func postJSON(t *testing.T, router http.Handler, path string, body string) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	return response
}

func assertSafeInputError(t *testing.T, response *httptest.ResponseRecorder, secret string) {
	t.Helper()

	var problem map[string]any

	err := json.Unmarshal(response.Body.Bytes(), &problem)
	require.NoError(t, err)
	require.GreaterOrEqual(t, response.Code, http.StatusBadRequest)
	require.Less(t, response.Code, http.StatusInternalServerError)
	require.Equal(t, "invalid request", problem["detail"])
	_, hasErrors := problem["errors"]
	require.False(t, hasErrors)
	require.NotContains(t, response.Body.String(), secret)
}

type refreshClaims struct {
	jwtv5.RegisteredClaims

	Username string `json:"username"`
	TokenUse string `json:"token_use"`
	FamilyID string `json:"family_id"`
}

func signedRefreshToken(t *testing.T, key []byte, claims refreshClaims) string {
	t.Helper()

	token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
	signed, err := token.SignedString(key)
	require.NoError(t, err)

	return signed
}

func (l *recordingLogger) LogFailure(operation string, category string) {
	l.operation = operation
	l.category = category
}

func newTestService(t *testing.T, repository *fake.Repository) *flow.Service {
	t.Helper()

	hasher, err := argon.NewArgon2id(argon.Parameters{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
	require.NoError(t, err)

	return flow.NewService(
		jwt.NewToker([]byte("test-public-key"), []byte("test-private-key")),
		repository,
		hasher,
	)
}

type failingHasher struct {
	err error
}

func (h failingHasher) Hash(string) (string, error) {
	return "", h.err
}

func (failingHasher) Verify(string, string) (bool, error) {
	return false, nil
}

var _ hasher.Hasher = failingHasher{err: errInternalCause}
