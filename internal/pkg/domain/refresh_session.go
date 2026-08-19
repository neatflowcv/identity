package domain

import "time"

// RefreshSession is the server-side state for one refresh-token family.
// TokenHash contains a digest of the token and never the token itself.
type RefreshSession struct {
	FamilyID  string
	Username  Username
	TokenID   string
	TokenHash string
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// RefreshTokenRotation describes an atomic replacement of the current token
// in a refresh-token family.
type RefreshTokenRotation struct {
	FamilyID       string
	CurrentTokenID string
	CurrentHash    string
	NextTokenID    string
	NextHash       string
	ExpiresAt      time.Time
	Now            time.Time
}
