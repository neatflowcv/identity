package domain

import "time"

type TokenPolicy struct {
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

func NewTokenPolicy() *TokenPolicy {
	return &TokenPolicy{
		accessTokenTTL:  15 * time.Minute,    //nolint:mnd // 15 minutes
		refreshTokenTTL: 24 * time.Hour * 14, //nolint:mnd // 2 weeks
	}
}

func (p *TokenPolicy) AccessTokenTTL() time.Duration {
	return p.accessTokenTTL
}

func (p *TokenPolicy) RefreshTokenTTL() time.Duration {
	return p.refreshTokenTTL
}
