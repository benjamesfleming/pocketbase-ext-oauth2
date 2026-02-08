package oauth2

import (
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/plugins/oauth2/client"
	"github.com/pocketbase/pocketbase/plugins/oauth2/consts"
)

type ClientModel struct {
	core.BaseRecordProxy
}

func NewClientModel(app core.App) *ClientModel {
	m := &ClientModel{}
	c, err := app.FindCachedCollectionByNameOrId(consts.ClientCollectionName)
	if err != nil {
		c = core.NewBaseCollection("@__invalid__")
	}
	m.Record = core.NewRecord(c)
	return m
}

func NewClientFromRFC7591Metadata(app core.App, md *RFC7591ClientMetadataRequest) (*client.Client, string, error) {
	m := NewClientModel(app)

	clientID := uuid.New().String()
	clientSecret := uuid.New().String()

	md.TokenEndpointAuthMethod = "client_secret_post"
	md.ResponseTypes = []string{"code"}
	md.GrantTypes = []string{"authorization_code", "refresh_token"}

	if len(md.Scope) == 0 {
		// Default Scopes
		md.Scope = "openid profile mcp:read mcp:write"
	}

	if md.Contacts == nil {
		md.Contacts = []string{}
	}

	m.Set("client_id", clientID)
	m.Set("client_name", md.ClientName)
	m.Set("client_secret", clientSecret) // N.b. This will be hashed in the OnModelCreate hook before saving to the database.
	m.Set("client_secret_expires_at", 0)
	m.Set("redirect_uris", md.RedirectURIs)
	m.Set("grant_types", md.GrantTypes)
	m.Set("response_types", md.ResponseTypes)
	m.Set("scope", md.Scope)
	m.Set("audience", []string{})
	m.Set("owner", "")
	m.Set("policy_uri", md.PolicyURI)
	m.Set("tos_uri", md.TermsOfServiceURI)
	m.Set("client_uri", md.ClientURI)
	m.Set("logo_uri", md.LogoURI)
	m.Set("contacts", md.Contacts)
	m.Set("allowed_cors_origins", []string{})
	m.Set("subject_type", "public")
	m.Set("sector_identifier_uri", "")
	m.Set("jwks_uri", md.JwksURI)
	m.Set("jwks", md.Jwks)
	m.Set("request_uris", []string{})
	m.Set("token_endpoint_auth_method", md.TokenEndpointAuthMethod)
	m.Set("token_endpoint_auth_signing_alg", "")
	m.Set("request_object_signing_alg", "")
	m.Set("userinfo_signed_response_alg", "")
	m.Set("metadata", md)
	m.Set("access_token_strategy", "opaque")

	if err := app.Save(m); err != nil {
		return nil, "", errors.Wrap(err, "failed to save client metadata")
	}

	c, _ := m.ToClient()
	return c, clientSecret, nil
}

func (m *ClientModel) ToClient() (*client.Client, error) {
	c := &client.Client{}
	c.ID = m.GetString("client_id")
	c.Name = m.GetString("client_name")
	c.Secret = m.GetString("client_secret")
	c.SecretExpiresAt = m.GetInt("client_secret_expires_at")
	c.RedirectURIs = m.GetStringSlice("redirect_uris")
	c.GrantTypes = m.GetStringSlice("grant_types")
	c.ResponseTypes = m.GetStringSlice("response_types")
	c.Scope = m.GetString("scope")
	c.Audience = m.GetStringSlice("audience")
	c.Owner = m.GetString("owner")
	c.PolicyURI = m.GetString("policy_uri")
	c.TermsOfServiceURI = m.GetString("tos_uri")
	c.ClientURI = m.GetString("client_uri")
	c.LogoURI = m.GetString("logo_uri")
	c.Contacts = m.GetStringSlice("contacts")
	c.AllowedCORSOrigins = m.GetStringSlice("allowed_cors_origins")
	c.SubjectType = m.GetString("subject_type")
	c.SectorIdentifierURI = m.GetString("sector_identifier_uri")
	c.JSONWebKeysURI = m.GetString("jwks_uri")
	if err := m.UnmarshalJSONField("jwks", &c.JSONWebKeys); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal jwks")
	}
	c.RequestURIs = m.GetStringSlice("request_uris")
	c.TokenEndpointAuthMethod = m.GetString("token_endpoint_auth_method")
	c.TokenEndpointAuthSigningAlgorithm = m.GetString("token_endpoint_auth_signing_alg")
	c.RequestObjectSigningAlgorithm = m.GetString("request_object_signing_alg")
	c.UserinfoSignedResponseAlgorithm = m.GetString("userinfo_signed_response_alg")
	if err := m.UnmarshalJSONField("metadata", &c.Metadata); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal metadata")
	}
	c.AccessTokenStrategy = m.GetString("access_token_strategy")
	return c, nil
}
