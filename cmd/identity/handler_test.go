package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neatflowcv/identity/cmd/identity/model"
	"github.com/neatflowcv/identity/internal/app/flow"
	"github.com/neatflowcv/identity/internal/pkg/hasher/argon"
	"github.com/neatflowcv/identity/internal/pkg/repository/fake"
	"github.com/neatflowcv/identity/internal/pkg/toker/jwt"
	"github.com/stretchr/testify/require"
)

func newTestRouter() http.Handler {
	toker := jwt.NewToker([]byte("test-public-key"), []byte("test-private-key"))

	hasher, err := argon.NewArgon2id(argon.Parameters{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
	if err != nil {
		panic(err)
	}

	service := flow.NewService(toker, fake.NewRepository(), hasher)

	return NewRouter(service)
}

func TestRouterProvidesHumaDocumentation(t *testing.T) {
	t.Parallel()

	router := newTestRouter()

	tests := []struct {
		name       string
		path       string
		content    string
		statusCode int
	}{
		{
			name:       "openapi json",
			path:       "/identity/v1/openapi.json",
			content:    "application/openapi+json",
			statusCode: http.StatusOK,
		},
		{
			name:       "openapi yaml",
			path:       "/identity/v1/openapi.yaml",
			content:    "application/openapi+yaml",
			statusCode: http.StatusOK,
		},
		{name: "docs", path: "/identity/v1/docs", content: "text/html", statusCode: http.StatusOK},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			require.Equal(t, test.statusCode, response.Code)
			require.Contains(t, response.Header().Get("Content-Type"), test.content)
			require.NotEmpty(t, response.Body)
		})
	}
}

func TestRouterHandlesIdentityOperations(t *testing.T) {
	t.Parallel()

	router := newTestRouter()
	createUserResponse := requestJSON(
		t,
		router,
		http.MethodPost,
		"/identity/v1/users",
		`{"user":{"username":"alice","password":"secret"}}`,
	)
	require.Equal(t, http.StatusNoContent, createUserResponse.Code)

	createTokenResponse := requestJSON(
		t,
		router,
		http.MethodPost,
		"/identity/v1/tokens",
		`{"user":{"username":"alice","password":"secret"}}`,
	)
	require.Equal(t, http.StatusOK, createTokenResponse.Code)

	var token model.CreateTokenResponse
	require.NoError(t, json.Unmarshal(createTokenResponse.Body.Bytes(), &token))
	require.Equal(t, "Bearer", token.TokenType)
	require.NotEmpty(t, token.AccessToken)
	require.NotEmpty(t, token.RefreshToken)

	refreshTokenResponse := requestJSON(
		t,
		router,
		http.MethodPost,
		"/identity/v1/refresh",
		`{"token":{"access_token":"`+token.AccessToken+`","refresh_token":"`+token.RefreshToken+`"}}`,
	)
	require.Equal(t, http.StatusOK, refreshTokenResponse.Code)
}

func requestJSON(
	t *testing.T,
	router http.Handler,
	method string,
	path string,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	return response
}
