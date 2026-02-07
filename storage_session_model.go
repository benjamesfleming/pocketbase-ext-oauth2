package oauth2

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"
)

type SessionModel interface {
	core.RecordProxy

	GetCollectionName() string
}

type BaseSessionModel struct {
	core.BaseRecordProxy
}

func (m BaseSessionModel) SetSignature(signature string) {
	m.Set("signature", signature)
}

func (m BaseSessionModel) SetRequester(requester fosite.Requester) error {
	session := requester.GetSession()
	subject := ""
	if session == nil {
		// p.l.Debugf("Got an empty session in sqlSchemaFromRequest")
	} else {
		subject = session.GetSubject()
	}
	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return err
	}

	// TODO: Encrypt session data

	m.Set("client_id", requester.GetClient().GetID())
	m.Set("request_id", requester.GetID())
	m.Set("requested_at", requester.GetRequestedAt().Unix())
	m.Set("expires_at", nil)
	m.Set("scopes", strings.Join(requester.GetRequestedScopes(), "|"))
	m.Set("granted_scopes", strings.Join(requester.GetGrantedScopes(), "|"))
	m.Set("requested_audience", strings.Join(requester.GetRequestedAudience(), "|"))
	m.Set("granted_audience", strings.Join(requester.GetGrantedAudience(), "|"))
	m.Set("form_data", requester.GetRequestForm().Encode())
	m.Set("session_data", sessionBytes)
	m.Set("subject", subject)

	return nil
}

func (m BaseSessionModel) ToRequest(ctx context.Context, s *OAuth2Store, session fosite.Session) (*fosite.Request, error) {
	if session != nil {
		// TODO: Decrypt session data

		if err := json.Unmarshal(m.GetSessionData(), session); err != nil {
			return nil, err
		}
	} else {
		// p.l.Debugf("Got an empty session in toRequest")
	}

	c, err := s.GetClient(ctx, m.GetClientID())
	if err != nil {
		return nil, err
	}

	val, err := url.ParseQuery(m.GetFormData())
	if err != nil {
		return nil, err
	}

	return &fosite.Request{
		ID:          m.GetRequestID(),
		RequestedAt: m.GetRequestedAt(),
		// ExpiresAt does not need to be populated as we get the expiry time from the session.
		Client:            c,
		RequestedScope:    m.GetScopes(),
		GrantedScope:      m.GetGrantedScopes(),
		RequestedAudience: m.GetRequestedAudience(),
		GrantedAudience:   m.GetGrantedAudience(),
		Form:              val,
		Session:           session,
	}, nil
}

func (m BaseSessionModel) GetID() string {
	return m.GetString("id")
}

func (m BaseSessionModel) GetClientID() string {
	return m.GetString("client_id")
}

func (m BaseSessionModel) GetRequestID() string {
	return m.GetString("request_id")
}

func (m BaseSessionModel) GetRequestedAt() time.Time {
	return time.Unix(int64(m.GetInt("requested_at")), 0)
}

func (m BaseSessionModel) GetExpiresAt() *time.Time {
	if m.Get("expires_at") == nil {
		return nil
	}
	t := time.Unix(int64(m.GetInt("expires_at")), 0)
	return &t
}

func (m BaseSessionModel) GetScopes() []string {
	return strings.Split(m.GetString("scopes"), "|")
}

func (m BaseSessionModel) GetGrantedScopes() []string {
	return strings.Split(m.GetString("granted_scopes"), "|")
}

func (m BaseSessionModel) GetRequestedAudience() []string {
	return strings.Split(m.GetString("requested_audience"), "|")
}

func (m BaseSessionModel) GetGrantedAudience() []string {
	return strings.Split(m.GetString("granted_audience"), "|")
}

func (m BaseSessionModel) GetFormData() string {
	return m.GetString("form_data")
}

func (m BaseSessionModel) GetSessionData() []byte {
	return []byte(m.GetString("session_data"))
}

func (m BaseSessionModel) GetSubject() string {
	return m.GetString("subject")
}

//

const (
	AuthCodeCollectionName = "_oauth2AuthCode"
	AccessCollectionName   = "_oauth2Access"
	RefreshCollectionName  = "_oauth2Refresh"
	PKCECollectionName     = "_oauth2PKCE"
)

// AuthCode

type AuthCodeModel struct {
	BaseSessionModel
}

func (p *AuthCodeModel) GetCollectionName() string {
	return AuthCodeCollectionName
}

// AccessToken

type AccessTokenModel struct {
	BaseSessionModel
}

func (p *AccessTokenModel) GetCollectionName() string {
	return AccessCollectionName
}

// RefreshToken

type RefreshTokenModel struct {
	BaseSessionModel
}

func (p *RefreshTokenModel) GetCollectionName() string {
	return RefreshCollectionName
}

// PKCE

type PKCEModel struct {
	BaseSessionModel
}

func (p *PKCEModel) GetCollectionName() string {
	return PKCECollectionName
}

var _ SessionModel = (*AuthCodeModel)(nil)
var _ SessionModel = (*AccessTokenModel)(nil)
var _ SessionModel = (*RefreshTokenModel)(nil)
var _ SessionModel = (*PKCEModel)(nil)
