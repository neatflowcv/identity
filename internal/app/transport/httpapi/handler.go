package httpapi

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/neatflowcv/identity/cmd/identity/model"
	"github.com/neatflowcv/identity/internal/app/flow"
	"github.com/neatflowcv/identity/internal/pkg/domain"
)

type Handler struct {
	service *flow.Service
	logger  FailureLogger
}

const (
	apiVersion                 = "1.0.0"
	createUserConflictMessage  = "unable to create user"
	internalFailureCategory    = "internal"
	internalServerErrorMessage = "internal server error"
	authenticationErrorMessage = "invalid username or password"
	refreshTokenErrorMessage   = "invalid refresh token"
	invalidRequestMessage      = "invalid request"
)

// FailureLogger records a non-sensitive error classification for an HTTP
// operation. Implementations must not include request credentials or tokens.
type FailureLogger interface {
	LogFailure(operation string, category string)
}

type standardFailureLogger struct{}

func (standardFailureLogger) LogFailure(operation string, category string) {
	log.Printf("identity request failed: operation=%s category=%s", operation, category)
}

func NewRouter(service *flow.Service) http.Handler {
	return NewRouterWithLogger(service, nil)
}

func NewRouterWithLogger(service *flow.Service, logger FailureLogger) http.Handler {
	router := http.NewServeMux()
	config := huma.DefaultConfig("Identity API", apiVersion)
	config.OpenAPIPath = "/identity/v1/openapi"
	config.DocsPath = "/identity/v1/docs"
	config.SchemasPath = "/identity/v1/schemas"
	config.Info.Description = "This is an identity management API server."

	api := humago.New(router, config)
	NewHandlerWithLogger(service, logger).Register(api)

	return newSafeRouter(router)
}

func NewHandler(service *flow.Service) *Handler {
	return NewHandlerWithLogger(service, nil)
}

func NewHandlerWithLogger(service *flow.Service, logger FailureLogger) *Handler {
	if logger == nil {
		logger = standardFailureLogger{}
	}

	return &Handler{
		service: service,
		logger:  logger,
	}
}

type CreateUserInput struct {
	Body model.CreateUserRequest
}

type CreateUserOutput struct{}

type CreateTokenInput struct {
	Body model.CreateTokenRequest
}

type CreateTokenOutput struct {
	Body model.CreateTokenResponse
}

type RefreshTokenInput struct {
	Body model.RefreshTokenRequest
}

type RefreshTokenOutput struct {
	Body model.RefreshTokenResponse
}

func (h *Handler) Register(api huma.API) {
	huma.Register(api, huma.Operation{ //nolint:exhaustruct
		OperationID: "create-user",
		Method:      http.MethodPost,
		Path:        "/identity/v1/users",
		Summary:     "Create a new user",
		Description: "Create a new user with username and password.",
		Tags:        []string{"users"},
		Errors:      []int{http.StatusBadRequest, http.StatusConflict, http.StatusInternalServerError},
	}, h.CreateUser)

	huma.Register(api, huma.Operation{ //nolint:exhaustruct
		OperationID: "create-token",
		Method:      http.MethodPost,
		Path:        "/identity/v1/tokens",
		Summary:     "Create a new authentication token",
		Description: "Authenticate a user with username and password and return a token.",
		Tags:        []string{"auth"},
		Errors:      []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusInternalServerError},
	}, h.CreateToken)

	huma.Register(api, huma.Operation{ //nolint:exhaustruct
		OperationID: "refresh-token",
		Method:      http.MethodPost,
		Path:        "/identity/v1/refresh",
		Summary:     "Refresh an authentication token",
		Description: "Refresh an existing token using the refresh token to get a new access token.",
		Tags:        []string{"auth"},
		Errors:      []int{http.StatusUnauthorized, http.StatusInternalServerError},
	}, h.RefreshToken)
}

func (h *Handler) CreateUser(ctx context.Context, input *CreateUserInput) (*CreateUserOutput, error) {
	err := validateCredentials(input.Body.User.UserName, input.Body.User.Password)
	if err != nil {
		return nil, err
	}

	user := domain.NewUser(input.Body.User.UserName, input.Body.User.Password)

	_, err = h.service.CreateUser(ctx, user)
	if err != nil {
		category := internalFailureCategory

		switch {
		case errors.Is(err, flow.ErrUserExists):
			category = "user_exists"
			h.logger.LogFailure("create_user", category)

			return nil, huma.Error409Conflict(createUserConflictMessage)
		default:
			h.logger.LogFailure("create_user", category)

			return nil, huma.Error500InternalServerError(internalServerErrorMessage)
		}
	}

	return &CreateUserOutput{}, nil
}

func (h *Handler) CreateToken(ctx context.Context, input *CreateTokenInput) (*CreateTokenOutput, error) {
	err := validateCredentials(input.Body.User.UserName, input.Body.User.Password)
	if err != nil {
		return nil, err
	}

	user := domain.NewUser(input.Body.User.UserName, input.Body.User.Password)

	token, err := h.service.CreateToken(ctx, user)
	if err != nil {
		category := internalFailureCategory

		switch {
		case errors.Is(err, flow.ErrUserNotFound), errors.Is(err, flow.ErrAuthenticationFailed):
			category = "authentication_failed"
			h.logger.LogFailure("create_token", category)

			return nil, huma.Error401Unauthorized(authenticationErrorMessage)
		default:
			h.logger.LogFailure("create_token", category)

			return nil, huma.Error500InternalServerError(internalServerErrorMessage)
		}
	}

	return &CreateTokenOutput{
		Body: tokenResponse(token),
	}, nil
}

func (h *Handler) RefreshToken(
	ctx context.Context,
	input *RefreshTokenInput,
) (*RefreshTokenOutput, error) {
	spec := domain.NewTokenSpec(input.Body.Token.RefreshToken)

	token, err := h.service.RefreshToken(ctx, spec)
	if err != nil {
		category := internalFailureCategory

		switch {
		case errors.Is(err, flow.ErrInvalidToken), errors.Is(err, flow.ErrUserNotFound):
			category = "invalid_refresh_token"
			h.logger.LogFailure("refresh_token", category)

			return nil, huma.Error401Unauthorized(refreshTokenErrorMessage)
		default:
			h.logger.LogFailure("refresh_token", category)

			return nil, huma.Error500InternalServerError(internalServerErrorMessage)
		}
	}

	return &RefreshTokenOutput{
		Body: refreshTokenResponse(token),
	}, nil
}

func validateCredentials(username string, password string) error {
	if username == "" || password == "" {
		return huma.Error400BadRequest(invalidRequestMessage)
	}

	return nil
}

func tokenResponse(token *domain.Token) model.CreateTokenResponse {
	return model.CreateTokenResponse{
		TokenType:    string(token.TokenType()),
		AccessToken:  token.AccessToken(),
		RefreshToken: token.RefreshToken(),
		ExpiresIn:    int64(token.ExpiresIn().Seconds()),
	}
}

func refreshTokenResponse(token *domain.Token) model.RefreshTokenResponse {
	return model.RefreshTokenResponse{
		TokenType:    string(token.TokenType()),
		AccessToken:  token.AccessToken(),
		RefreshToken: token.RefreshToken(),
		ExpiresIn:    int64(token.ExpiresIn().Seconds()),
	}
}
