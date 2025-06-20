package model

type CreateTokenRequest struct {
	User CreateTokenBody `json:"user" binding:"required"`
}

type CreateTokenBody struct {
	UserName string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type CreateTokenResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type RefreshTokenRequest struct {
	Token RefreshTokenBody `json:"token" binding:"required"`
}

type RefreshTokenBody struct {
	AccessToken  string `json:"access_token" binding:"required"`
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type RefreshTokenResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}
