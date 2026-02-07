package oauth2

import (
	"context"

	"github.com/ory/fosite"
	"github.com/pkg/errors"
	"github.com/pocketbase/pocketbase/core"
)

const (
	ClientCollectionName = "_oauth2Clients"
)

type RFC7591ClientMetadataModel struct {
	core.BaseRecordProxy
}

func NewRFC7591ClientMetadataModel(app core.App) *RFC7591ClientMetadataModel {
	m := &RFC7591ClientMetadataModel{}
	c, err := app.FindCachedCollectionByNameOrId(ClientCollectionName)
	if err != nil {
		c = core.NewBaseCollection("@__invalid__")
	}
	m.Record = core.NewRecord(c)
	return m
}

//

func (m *RFC7591ClientMetadataModel) ToHashedMetadata() (*RFC7591ClientMetadata, error) {
	md := &RFC7591ClientMetadata{}
	md.ClientID = m.GetString("client_id")
	md.ClientSecret = m.GetString("client_secret")
	md.ClientSecretExpiresAt = int64(m.GetInt("client_secret_expires_at"))
	md.Scope = m.GetString("scope")
	md.RedirectURIs = m.GetStringSlice("redirect_uris")
	md.TokenEndpointAuthMethod = m.GetString("token_endpoint_auth_method")
	md.GrantTypes = m.GetStringSlice("grant_types")
	md.ResponseTypes = m.GetStringSlice("response_types")
	md.Contacts = m.GetStringSlice("contacts")
	md.ClientName = m.GetString("client_name")
	md.ClientURI = m.GetString("client_uri")
	md.LogoURI = m.GetString("logo_uri")
	md.TermsOfServiceURI = m.GetString("tos_uri")
	md.PolicyURI = m.GetString("policy_uri")
	md.JwksURI = m.GetString("jwks_uri")
	if err := m.UnmarshalJSONField("jwks", &md.Jwks); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal jwks")
	}
	md.SoftwareID = m.GetString("software_id")
	md.SoftwareVersion = m.GetString("software_version")
	return md, nil
}

func (m *RFC7591ClientMetadataModel) SetMetadata(md *RFC7591ClientMetadata, hasher fosite.Hasher) error {
	secretHash, err := hasher.Hash(context.Background(), []byte(md.ClientSecret))
	if err != nil {
		return errors.Wrap(err, "failed to hash client_secret")
	}
	m.Set("client_id", md.ClientID)
	m.Set("client_secret", secretHash)
	m.Set("client_secret_expires_at", md.ClientSecretExpiresAt)
	m.Set("scope", md.Scope)
	m.Set("redirect_uris", md.RedirectURIs)
	m.Set("token_endpoint_auth_method", md.TokenEndpointAuthMethod)
	m.Set("grant_types", md.GrantTypes)
	m.Set("response_types", md.ResponseTypes)
	m.Set("contacts", md.Contacts)
	m.Set("client_name", md.ClientName)
	m.Set("client_uri", md.ClientURI)
	m.Set("logo_uri", md.LogoURI)
	m.Set("tos_uri", md.TermsOfServiceURI)
	m.Set("policy_uri", md.PolicyURI)
	m.Set("jwks_uri", md.JwksURI)
	m.Set("jwks", md.Jwks)
	m.Set("software_id", md.SoftwareID)
	m.Set("software_version", md.SoftwareVersion)
	return nil
}
