package core

import "errors"

var (
	ErrUserNotFound         = errors.New("user not found")
	ErrUserExists           = errors.New("user exists")
	ErrRefreshSessionExists = errors.New("refresh session exists")
	ErrRefreshTokenInvalid  = errors.New("refresh token invalid")
)
