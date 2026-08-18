package model

type CreateUserRequest struct {
	User CreateUserBody `json:"user"`
}

type CreateUserBody struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}
