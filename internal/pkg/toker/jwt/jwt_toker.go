package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/toker/core"
)

var _ core.Toker = (*Toker)(nil)

type Toker struct {
	publicVault  *Vault
	privateVault *Vault
}

const identifierSize = 32

func NewToker(publicKey []byte, privateKey []byte) *Toker {
	return &Toker{
		publicVault:  NewVault(publicKey),
		privateVault: NewVault(privateKey),
	}
}

func (t *Toker) CreateToken(now time.Time, user *domain.User, policy *domain.TokenPolicy) *domain.Token {
	return t.CreateTokenWithFamily(now, user, policy, newIdentifier())
}

func (t *Toker) CreateTokenWithFamily(
	now time.Time,
	user *domain.User,
	policy *domain.TokenPolicy,
	familyID string,
) *domain.Token {
	accessTokenString, err := t.publicVault.Encrypt(now, now.Add(policy.AccessTokenTTL()), user)
	if err != nil {
		panic(err)
	}

	refreshTokenString, err := t.privateVault.EncryptRefresh(
		now,
		now.Add(policy.RefreshTokenTTL()),
		user,
		newIdentifier(),
		familyID,
	)
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
	claims, err := t.ParseRefreshToken(now, spec)
	if err != nil {
		return "", err
	}

	return claims.Username, nil
}

func (t *Toker) ParseRefreshToken(
	now time.Time,
	spec *domain.TokenSpec,
) (*core.RefreshTokenClaims, error) {
	claims, err := t.privateVault.DecryptRefresh(now, spec.RefreshToken())
	if err != nil {
		return nil, err
	}

	return &core.RefreshTokenClaims{
		Username: domain.Username(claims.Username),
		TokenID:  claims.ID,
		FamilyID: claims.FamilyID,
	}, nil
}

func newIdentifier() string {
	identifier := make([]byte, identifierSize)

	_, err := rand.Read(identifier)
	if err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(identifier)
}
