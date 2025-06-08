package flow

import "errors"

var (
	ErrUserNotFound         = errors.New("user not found")
	ErrUserExists           = errors.New("user already exists")
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrUnknown              = errors.New("unknown error")
	ErrInvalidToken         = errors.New("invalid token")
)
