package main

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/neatflowcv/identity/cmd/identity/model"
	"github.com/neatflowcv/identity/internal/app/flow"
	"github.com/neatflowcv/identity/internal/pkg/domain"
)

type Handler struct {
	service *flow.Service
}

func NewHandler(service *flow.Service) *Handler {
	return &Handler{
		service: service,
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
		Errors:      []int{http.StatusConflict, http.StatusInternalServerError},
	}, h.CreateUser)

	huma.Register(api, huma.Operation{ //nolint:exhaustruct
		OperationID: "create-token",
		Method:      http.MethodPost,
		Path:        "/identity/v1/tokens",
		Summary:     "Create a new authentication token",
		Description: "Authenticate a user with username and password and return a token.",
		Tags:        []string{"auth"},
		Errors:      []int{http.StatusUnauthorized, http.StatusInternalServerError},
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
	user := domain.NewUser(input.Body.User.UserName, input.Body.User.Password)

	_, err := h.service.CreateUser(ctx, user)
	if err != nil {
		switch {
		case errors.Is(err, flow.ErrUserExists):
			return nil, huma.Error409Conflict(err.Error())
		case errors.Is(err, flow.ErrUnknown):
			return nil, huma.Error500InternalServerError(err.Error())
		default:
			return nil, huma.Error500InternalServerError(err.Error())
		}
	}

	return &CreateUserOutput{}, nil
}

func (h *Handler) CreateToken(ctx context.Context, input *CreateTokenInput) (*CreateTokenOutput, error) {
	user := domain.NewUser(input.Body.User.UserName, input.Body.User.Password)

	token, err := h.service.CreateToken(ctx, user)
	if err != nil {
		switch {
		case errors.Is(err, flow.ErrUserNotFound), errors.Is(err, flow.ErrAuthenticationFailed):
			return nil, huma.Error401Unauthorized(err.Error())
		case errors.Is(err, flow.ErrUnknown):
			return nil, huma.Error500InternalServerError(err.Error())
		default:
			return nil, huma.Error500InternalServerError(err.Error())
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
		switch {
		case errors.Is(err, flow.ErrInvalidToken), errors.Is(err, flow.ErrUserNotFound):
			return nil, huma.Error401Unauthorized(err.Error())
		case errors.Is(err, flow.ErrUnknown):
			return nil, huma.Error500InternalServerError(err.Error())
		default:
			return nil, huma.Error500InternalServerError(err.Error())
		}
	}

	return &RefreshTokenOutput{
		Body: refreshTokenResponse(token),
	}, nil
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
