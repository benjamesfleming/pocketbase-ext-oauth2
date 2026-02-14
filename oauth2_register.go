package oauth2

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"
)

type RFC7591ClientStorage interface {
	// RegisterClient registers a new client with the given metadata
	// and returns the created client or an error if the registration failed.
	RegisterClient(ctx context.Context, client *RFC7591ClientMetadataRequest) (fosite.Client, string, error)
}

type RFC7591ClientMetadataRequest struct {
	Scope                   string              `json:"scope"`
	RedirectURIs            []string            `json:"redirect_uris"`
	TokenEndpointAuthMethod string              `json:"token_endpoint_auth_method"`
	GrantTypes              []string            `json:"grant_types"`
	ResponseTypes           []string            `json:"response_types"`
	Contacts                []string            `json:"contacts,omitempty"`
	ClientName              string              `json:"client_name"`
	ClientURI               string              `json:"client_uri,omitempty"`
	LogoURI                 string              `json:"logo_uri,omitempty"`
	TermsOfServiceURI       string              `json:"tos_uri,omitempty"`
	PolicyURI               string              `json:"policy_uri,omitempty"`
	JwksURI                 string              `json:"jwks_uri,omitempty"`
	Jwks                    *jose.JSONWebKeySet `json:"jwks,omitempty"`
	SoftwareID              string              `json:"software_id,omitempty"`
	SoftwareVersion         string              `json:"software_version,omitempty"`

	// The following fields are not part of the RFC7591 but are required for OpenID Connect client registration.
	// @ref https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.6.2
	RequestURIs []string `json:"request_uris,omitempty"`
}

type RFC7591ClientMetadata struct {
	RFC7591ClientMetadataRequest
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret"`
	ClientSecretExpiresAt int64  `json:"client_secret_expires_at"`
}

// @ref https://datatracker.ietf.org/doc/html/rfc7591#section-3
func api_OAuth2Register(e *core.RequestEvent) error {
	r := e.Request
	w := e.Response

	if r.Method != http.MethodPost {
		return e.Error(http.StatusMethodNotAllowed, "", nil)
	}

	var md RFC7591ClientMetadataRequest

	if err := json.NewDecoder(r.Body).Decode(&md); err != nil {
		return e.BadRequestError(err.Error(), err)
	}

	if len(md.RedirectURIs) == 0 {
		return e.BadRequestError("redirect_uris is required", nil)
	}

	//

	c, clientSecret, err := GetOAuth2Store().RegisterClient(r.Context(), &md)
	if err != nil {
		return e.InternalServerError("", err)
	}

	//

	resp := &RFC7591ClientMetadata{
		RFC7591ClientMetadataRequest: md,
		ClientID:                     c.GetID(),
		ClientSecret:                 clientSecret,
		ClientSecretExpiresAt:        0,
	}

	//

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return e.InternalServerError("", err)
	}
	return nil
}
