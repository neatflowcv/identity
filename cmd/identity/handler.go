package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/neatflowcv/identity/cmd/identity/model"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
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

	ctx.Status(http.StatusNoContent)
}
