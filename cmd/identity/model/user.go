package model

type CreateUserRequest struct {
	User CreateUserBody `json:"user" binding:"required"`
}

type CreateUserBody struct {
	UserName string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

