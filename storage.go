package oauth2

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ory/fosite"
	fositeoauth2 "github.com/ory/fosite/handler/oauth2"
	fositeopenid "github.com/ory/fosite/handler/openid"
	fositepkce "github.com/ory/fosite/handler/pkce"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/plugins/oauth2/consts"
)

//

type OAuth2Store struct {
	app core.App
}

func NewOAuth2Store(app core.App) *OAuth2Store {
	return &OAuth2Store{
		app: app,
	}
}

// https://github.com/ory/hydra/blob/master/persistence/sql/persister_oauth2.go#L571

// GetClient implements [fosite.ClientManager].
func (s *OAuth2Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	m := &ClientModel{}
	c, err := s.app.FindCachedCollectionByNameOrId(consts.ClientCollectionName)
	if err != nil {
		c = core.NewBaseCollection("@__invalid__")
	}
	err = s.app.RecordQuery(c).
		AndWhere(dbx.HashExp{"client_id": id}).
		One(m)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	return m.ToClient()
}

// RegisterClient implements [RFC7591ClientStorage].
func (s *OAuth2Store) RegisterClient(ctx context.Context, client *RFC7591ClientMetadataRequest) (fosite.Client, string, error) {
	return NewClientFromRFC7591Metadata(s.app, client)
}

// ClientAssertionJWTValid implements [fosite.ClientManager].
func (s *OAuth2Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	panic("unimplemented")
}

// SetClientAssertionJWT implements [fosite.ClientManager].
func (s *OAuth2Store) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	panic("unimplemented")
}

// CreateAuthorizeCodeSession implements [oauth2.AuthorizeCodeStorage].
func (s *OAuth2Store) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) (err error) {
	m := newSessionModel(s.app, &AuthCodeModel{})
	m.SetSignature(code)
	m.SetRequester(request)

	return s.app.Save(m)
}

// GetAuthorizeCodeSession implements [oauth2.AuthorizeCodeStorage].
func (s *OAuth2Store) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (request fosite.Requester, err error) {
	m, err := findSessionModelBySignature(s.app, &AuthCodeModel{}, code)
	if err != nil {
		return nil, err
	}

	return m.ToRequest(ctx, s, session)
}

// InvalidateAuthorizeCodeSession implements [oauth2.AuthorizeCodeStorage].
func (s *OAuth2Store) InvalidateAuthorizeCodeSession(ctx context.Context, code string) (err error) {
	return deleteSessionModelBySignature(s.app, &AuthCodeModel{}, code)
}

// CreateAccessTokenSession implements [oauth2.AccessTokenStorage].
func (s *OAuth2Store) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error) {
	m := newSessionModel(s.app, &AccessTokenModel{})
	m.SetSignature(signature)
	m.SetRequester(request)

	return s.app.Save(m)
}

// CreateRefreshTokenSession implements [oauth2.RefreshTokenStorage].
func (s *OAuth2Store) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) (err error) {
	m := newSessionModel(s.app, &RefreshTokenModel{})
	m.SetSignature(signature)
	m.SetRequester(request)

	return s.app.Save(m)
}

// DeleteAccessTokenSession implements [oauth2.AccessTokenStorage].
func (s *OAuth2Store) DeleteAccessTokenSession(ctx context.Context, signature string) (err error) {
	return deleteSessionModelBySignature(s.app, &AccessTokenModel{}, signature)
}

// DeleteRefreshTokenSession implements [oauth2.RefreshTokenStorage].
func (s *OAuth2Store) DeleteRefreshTokenSession(ctx context.Context, signature string) (err error) {
	return deleteSessionModelBySignature(s.app, &RefreshTokenModel{}, signature)
}

// GetAccessTokenSession implements [oauth2.AccessTokenStorage].
func (s *OAuth2Store) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	m, err := findSessionModelBySignature(s.app, &AccessTokenModel{}, signature)
	if err != nil {
		return nil, err
	}

	return m.ToRequest(ctx, s, session)
}

// GetRefreshTokenSession implements [oauth2.RefreshTokenStorage].
func (s *OAuth2Store) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	m, err := findSessionModelBySignature(s.app, &RefreshTokenModel{}, signature)
	if err != nil {
		return nil, err
	}

	return m.ToRequest(ctx, s, session)
}

// RevokeAccessToken implements [oauth2.AccessTokenStorage].
func (s *OAuth2Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	return deleteSessionModelByRequestID(s.app, &AccessTokenModel{}, requestID)
}

// RevokeRefreshToken implements [oauth2.RefreshTokenStorage].
func (s *OAuth2Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return deleteSessionModelByRequestID(s.app, &RefreshTokenModel{}, requestID)
}

// RotateRefreshToken implements [oauth2.RefreshTokenStorage].
func (s *OAuth2Store) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) (err error) {
	// TODO: Is this a 1-1? If not we might need to delete some more sessions here.
	deleteSessionModelBySignature(s.app, &RefreshTokenModel{}, refreshTokenSignature)
	deleteSessionModelByRequestID(s.app, &AccessTokenModel{}, requestID)
	return nil
}

// CreatePKCERequestSession implements [pkce.PKCERequestStorage].
func (s *OAuth2Store) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	m := newSessionModel(s.app, &PKCEModel{})
	m.SetSignature(signature)
	m.SetRequester(requester)

	return s.app.Save(m)
}

// DeletePKCERequestSession implements [pkce.PKCERequestStorage].
func (s *OAuth2Store) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return deleteSessionModelBySignature(s.app, &PKCEModel{}, signature)
}

// GetPKCERequestSession implements [pkce.PKCERequestStorage].
func (s *OAuth2Store) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	m, err := findSessionModelBySignature(s.app, &PKCEModel{}, signature)
	if err != nil {
		return nil, err
	}

	return m.ToRequest(ctx, s, session)
}

// CreateOpenIDConnectSession implements [openid.OpenIDConnectRequestStorage].
func (s *OAuth2Store) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	m := newSessionModel(s.app, &OpenIDConnectSessionModel{})
	m.SetSignature(authorizeCode)
	m.SetRequester(requester)

	return s.app.Save(m)
}

// DeleteOpenIDConnectSession implements [openid.OpenIDConnectRequestStorage].
func (s *OAuth2Store) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return deleteSessionModelBySignature(s.app, &OpenIDConnectSessionModel{}, authorizeCode)
}

// GetOpenIDConnectSession implements [openid.OpenIDConnectRequestStorage].
func (s *OAuth2Store) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	m, err := findSessionModelBySignature(s.app, &OpenIDConnectSessionModel{}, authorizeCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fositeopenid.ErrNoSessionFound
		}
		return nil, err
	}

	return m.ToRequest(ctx, s, requester.GetSession())
}

var _ fosite.Storage = (*OAuth2Store)(nil)
var _ fositeoauth2.AuthorizeCodeStorage = (*OAuth2Store)(nil)
var _ fositeoauth2.AccessTokenStorage = (*OAuth2Store)(nil)
var _ fositeoauth2.RefreshTokenStorage = (*OAuth2Store)(nil)
var _ fositeoauth2.TokenRevocationStorage = (*OAuth2Store)(nil)
var _ fositepkce.PKCERequestStorage = (*OAuth2Store)(nil)
var _ fositeopenid.OpenIDConnectRequestStorage = (*OAuth2Store)(nil)
var _ RFC7591ClientStorage = (*OAuth2Store)(nil)

// HELPER FUNCTIONS

func newSessionModel[T SessionModel](app core.App, m T) T {
	c, err := app.FindCachedCollectionByNameOrId(m.GetCollectionName())
	if err != nil {
		c = core.NewBaseCollection("@__invalid__")
	}
	m.SetProxyRecord(core.NewRecord(c))
	return m
}

func findSessionModelBySignature[T SessionModel](app core.App, m T, signature string) (T, error) {
	c, err := app.FindCachedCollectionByNameOrId(m.GetCollectionName())
	if err != nil {
		c = core.NewBaseCollection("@__invalid__")
	}
	err = app.RecordQuery(c).
		AndWhere(dbx.HashExp{"signature": signature}).
		One(m)
	return m, err
}

func findSessionModelByRequestID[T SessionModel](app core.App, m T, requestID string) (T, error) {
	c, err := app.FindCachedCollectionByNameOrId(m.GetCollectionName())
	if err != nil {
		c = core.NewBaseCollection("@__invalid__")
	}
	err = app.RecordQuery(c).
		AndWhere(dbx.HashExp{"request_id": requestID}).
		One(m)
	return m, err
}

func deleteSessionModelBySignature[T SessionModel](app core.App, m T, signature string) error {
	m, err := findSessionModelBySignature(app, m, signature)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil // if the session is not found, we can consider it already deleted and return no error
		} else {
			return err
		}
	}
	return app.Delete(m.ProxyRecord())
}

func deleteSessionModelByRequestID[T SessionModel](app core.App, m T, requestID string) error {
	m, err := findSessionModelByRequestID(app, m, requestID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil // if the session is not found, we can consider it already deleted and return no error
		} else {
			return err
		}
	}
	return app.Delete(m.ProxyRecord())
}
