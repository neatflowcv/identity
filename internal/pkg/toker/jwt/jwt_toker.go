package jwt

import (
	"errors"
	"time"

	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/toker/core"
)

var _ core.Toker = (*Toker)(nil)

type Toker struct {
	publicVault  *Vault
	privateVault *Vault
}

func NewToker(publicKey []byte, privateKey []byte) *Toker {
	return &Toker{
		publicVault:  NewVault(publicKey),
		privateVault: NewVault(privateKey),
	}
}

func (t *Toker) CreateToken(now time.Time, user *domain.User, policy *domain.TokenPolicy) *domain.Token {
	accessTokenString, err := t.publicVault.Encrypt(now, now.Add(policy.AccessTokenTTL()), user)
	if err != nil {
		panic(err)
	}

	refreshTokenString, err := t.privateVault.Encrypt(now, now.Add(policy.RefreshTokenTTL()), user)
	if err != nil {
		panic(err)
	}

	payload := domain.NewPayload(user.Username())
	token := domain.NewToken(
		domain.TokenTypeBearer,
		accessTokenString,
		refreshTokenString,
		policy.AccessTokenTTL(),
		payload,
	)

	return token
}

func (t *Toker) ParseToken(now time.Time, spec *domain.TokenSpec) (domain.Username, error) {
	refreshTokenUsername, err := t.privateVault.Decrypt(now, spec.RefreshToken())
	if err == nil {
		return domain.Username(refreshTokenUsername), nil
	}

	totalErr := err

	accessTokenUsername, err := t.publicVault.Decrypt(now, spec.AccessToken())
	if err == nil {
		return domain.Username(accessTokenUsername), nil
	}

	totalErr = errors.Join(totalErr, err)

	return "", totalErr
}
