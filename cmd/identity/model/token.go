package model

type CreateTokenRequest struct {
	User CreateTokenBody `json:"user"`
}

type CreateTokenBody struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

type CreateTokenResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type RefreshTokenRequest struct {
	Token RefreshTokenBody `json:"token"`
}

type RefreshTokenBody struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}
