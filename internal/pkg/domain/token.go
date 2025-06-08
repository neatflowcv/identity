package domain

import "time"

type TokenType string

const (
	TokenTypeBearer TokenType = "Bearer"
)

type TokenSpec struct {
	accessToken  string
	refreshToken string
}

func NewTokenSpec(accessToken string, refreshToken string) *TokenSpec {
	return &TokenSpec{
		accessToken:  accessToken,
		refreshToken: refreshToken,
	}
}

func (t *TokenSpec) AccessToken() string {
	return t.accessToken
}

func (t *TokenSpec) RefreshToken() string {
	return t.refreshToken
}

type Token struct {
	tokenType    TokenType
	accessToken  string
	refreshToken string
	expiresIn    time.Duration
	payload      *Payload
}

func NewToken(
	tokenType TokenType,
	accessToken string,
	refreshToken string,
	expiresIn time.Duration,
	payload *Payload,
) *Token {
	return &Token{
		tokenType:    tokenType,
		accessToken:  accessToken,
		refreshToken: refreshToken,
		expiresIn:    expiresIn,
		payload:      payload,
	}
}

func (t *Token) AccessToken() string {
	return t.accessToken
}

func (t *Token) RefreshToken() string {
	return t.refreshToken
}

func (t *Token) ExpiresIn() time.Duration {
	return t.expiresIn
}

func (t *Token) Payload() *Payload {
	return t.payload
}

func (t *Token) TokenType() TokenType {
	return t.tokenType
}
