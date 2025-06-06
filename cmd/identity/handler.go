package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

type CreateUserRequest struct {
	User CreateUserBody `json:"user" binding:"required"`
}

type CreateUserBody struct {
	UserName string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// CreateUser godoc
// @Summary Create a new user
// @Description Create a new user with username and password
// @Tags users
// @Accept json
// @Produce json
// @Param user body CreateUserRequest true "User creation request"
// @Success 204 "User created successfully"
// @Failure 400 {object} ErrorResponse "Bad request"
// @Router /identity/v1/users [post]
func (h *Handler) CreateUser(ctx *gin.Context) {
	var req CreateUserRequest

	err := ctx.ShouldBindJSON(&req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
		})

		return
	}

	ctx.Status(http.StatusNoContent)
}
