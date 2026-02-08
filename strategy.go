package oauth2

import (
	"context"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	fositeoauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/pkg/errors"
	"github.com/pocketbase/pocketbase/core"
)

type PocketBaseStrategy struct {
	App    core.App
	Config interface {
		fosite.AccessTokenIssuerProvider
		fosite.JWTScopeFieldProvider
	}
	HMACSHAStrategy fositeoauth2.CoreStrategy
}

func NewPocketBaseStrategy(app core.App, config fosite.Configurator) *PocketBaseStrategy {
	return &PocketBaseStrategy{
		App:             app,
		Config:          config,
		HMACSHAStrategy: compose.NewOAuth2HMACStrategy(config),
	}
}

// ACCESS TOKEN

// AccessTokenSignature implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) AccessTokenSignature(ctx context.Context, token string) string {
	split := strings.Split(token, ".")
	if len(split) != 3 {
		return ""
	}
	return split[2]
}

// GenerateAccessToken implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) GenerateAccessToken(ctx context.Context, requester fosite.Requester) (token string, signature string, err error) {
	session, ok := requester.GetSession().(*Session)
	if !ok {
		return "", "", errors.Errorf("Session must be of type oauth2.Session but got type: %T", requester.GetSession())
	}
	user, err := s.App.FindRecordById(session.CollectionId, session.Subject)
	if err != nil {
		return "", "", errors.Wrap(err, "Failed to get auth record for session")
	}
	token, err = user.NewAuthToken()
	if err != nil {
		return "", "", errors.Wrap(err, "Failed to generate new auth token")
	}
	return token, s.AccessTokenSignature(ctx, token), nil
}

// ValidateAccessToken implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) ValidateAccessToken(ctx context.Context, requester fosite.Requester, token string) error {
	_, err := s.App.FindAuthRecordByToken(token, core.TokenTypeAuth)
	return err
}

// REFRESH TOKEN

// RefreshTokenSignature implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) RefreshTokenSignature(ctx context.Context, token string) string {
	return s.HMACSHAStrategy.RefreshTokenSignature(ctx, token)
}

// GenerateRefreshToken implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) GenerateRefreshToken(ctx context.Context, requester fosite.Requester) (token string, signature string, err error) {
	return s.HMACSHAStrategy.GenerateRefreshToken(ctx, requester)
}

// ValidateRefreshToken implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) ValidateRefreshToken(ctx context.Context, requester fosite.Requester, token string) (err error) {
	return s.HMACSHAStrategy.ValidateRefreshToken(ctx, requester, token)
}

// AUTHORIZATION CODE

// AuthorizeCodeSignature implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) AuthorizeCodeSignature(ctx context.Context, token string) string {
	return s.HMACSHAStrategy.AuthorizeCodeSignature(ctx, token)
}

// GenerateAuthorizeCode implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) GenerateAuthorizeCode(ctx context.Context, requester fosite.Requester) (token string, signature string, err error) {
	return s.HMACSHAStrategy.GenerateAuthorizeCode(ctx, requester)
}

// ValidateAuthorizeCode implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) ValidateAuthorizeCode(ctx context.Context, requester fosite.Requester, token string) (err error) {
	return s.HMACSHAStrategy.ValidateAuthorizeCode(ctx, requester, token)
}

var _ fositeoauth2.CoreStrategy = (*PocketBaseStrategy)(nil)
