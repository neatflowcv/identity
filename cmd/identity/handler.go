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
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Name     string `json:"name" binding:"required"`
}

type CreateUserResponse struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Message  string `json:"message"`
}

func (h *Handler) CreateUser(ctx *gin.Context) {
	var req CreateUserRequest

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})

		return
	}

	// 실제 데이터베이스 저장 로직은 여기에 구현
	// 현재는 mock 응답을 반환
	response := CreateUserResponse{
		ID:       1,
		Username: req.Username,
		Email:    req.Email,
		Name:     req.Name,
		Message:  "User created successfully",
	}

	ctx.JSON(http.StatusCreated, response)
}
