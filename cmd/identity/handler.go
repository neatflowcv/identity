package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
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

// CreateUser godoc
// @Summary Create a new user
// @Description Create a new user with username and password
// @Tags users
// @Accept json
// @Produce json
// @Param user body model.CreateUserRequest true "User creation request"
// @Success 204 "User created successfully"
// @Failure 400 {object} model.ErrorResponse "Bad request"
// @Router /identity/v1/users [post]
func (h *Handler) CreateUser(ctx *gin.Context) {
	var req model.CreateUserRequest

	err := ctx.ShouldBindJSON(&req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: err.Error(),
		})

		return
	}

	user := domain.NewUser(req.User.UserName, req.User.Password)

	_, err = h.service.CreateUser(ctx, user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Error: err.Error(),
		})

		return
	}

	ctx.Status(http.StatusNoContent)
}

// CreateToken godoc
// @Summary Create a new authentication token
// @Description Authenticate user with username and password and return a token
// @Tags auth
// @Accept json
// @Produce json
// @Param user body model.CreateTokenRequest true "Token creation request"
// @Success 200 {object} model.CreateTokenResponse "Token created successfully"
// @Failure 400 {object} model.ErrorResponse "Bad request"
// @Failure 401 {object} model.ErrorResponse "Unauthorized"
// @Router /identity/v1/tokens [post]
func (h *Handler) CreateToken(ctx *gin.Context) { //nolint:dupl
	var req model.CreateTokenRequest

	err := ctx.ShouldBindJSON(&req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: err.Error(),
		})

		return
	}

	user := domain.NewUser(req.User.UserName, req.User.Password)

	token, err := h.service.CreateToken(ctx, user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Error: err.Error(),
		})

		return
	}

	response := model.CreateTokenResponse{
		TokenType:    string(token.TokenType()),
		AccessToken:  token.AccessToken(),
		RefreshToken: token.RefreshToken(),
		ExpiresIn:    int64(token.ExpiresIn().Seconds()),
	}

	ctx.JSON(http.StatusOK, response)
}

// RefreshToken godoc
// @Summary Refresh an authentication token
// @Description Refresh an existing token using the refresh token to get a new access token
// @Tags auth
// @Accept json
// @Produce json
// @Param token body model.RefreshTokenRequest true "Token refresh request"
// @Success 200 {object} model.RefreshTokenResponse "Token refreshed successfully"
// @Failure 400 {object} model.ErrorResponse "Bad request"
// @Failure 401 {object} model.ErrorResponse "Unauthorized"
// @Router /identity/v1/refresh [post]
func (h *Handler) RefreshToken(ctx *gin.Context) { //nolint:dupl
	var req model.RefreshTokenRequest

	err := ctx.ShouldBindJSON(&req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: err.Error(),
		})

		return
	}

	spec := domain.NewTokenSpec(req.Token.AccessToken, req.Token.RefreshToken)

	token, err := h.service.RefreshToken(ctx, spec)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, model.ErrorResponse{
			Error: err.Error(),
		})

		return
	}

	response := model.RefreshTokenResponse{
		TokenType:    string(token.TokenType()),
		AccessToken:  token.AccessToken(),
		RefreshToken: token.RefreshToken(),
		ExpiresIn:    int64(token.ExpiresIn().Seconds()),
	}

	ctx.JSON(http.StatusOK, response)
}
