package client

import (
	"encoding/json"
	"strings"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
)

var (
	_ fosite.OpenIDConnectClient = (*Client)(nil)
	_ fosite.ResponseModeClient  = (*Client)(nil)
	_ fosite.Client              = (*Client)(nil)
)

// OAuth 2.0 Client
//
// OAuth 2.0 Clients are used to perform OAuth 2.0 and OpenID Connect flows. Usually, OAuth 2.0 clients are
// generated for applications which want to consume your OAuth 2.0 or OpenID Connect capabilities.
type Client struct {
	// OAuth 2.0 Client ID
	//
	// The ID is immutable. If no ID is provided, a UUID4 will be generated.
	ID string `json:"client_id"`

	// OAuth 2.0 Client Name
	//
	// The human-readable name of the client to be presented to the
	// end-user during authorization.
	Name string `json:"client_name"`

	// OAuth 2.0 Client Secret
	//
	// The secret will be included in the create request as cleartext, and then
	// never again. The secret is kept in hashed format and is not recoverable once lost.
	Secret string `json:"client_secret,omitempty"`

	// OAuth 2.0 Client Redirect URIs
	//
	// RedirectURIs is an array of allowed redirect urls for the client.
	//
	// Example: http://mydomain/oauth/callback
	RedirectURIs []string `json:"redirect_uris"`

	// OAuth 2.0 Client Grant Types
	//
	// An array of OAuth 2.0 grant types the client is allowed to use. Can be one
	// of:
	//
	// - Client Credentials Grant: `client_credentials`
	// - Authorization Code Grant: `authorization_code`
	// - OpenID Connect Implicit Grant (deprecated!): `implicit`
	// - Refresh Token Grant: `refresh_token`
	// - OAuth 2.0 Token Exchange: `urn:ietf:params:oauth:grant-type:jwt-bearer`
	// - OAuth 2.0 Device Code Grant: `urn:ietf:params:oauth:grant-type:device_code`
	GrantTypes []string `json:"grant_types"`

	// OAuth 2.0 Client Response Types
	//
	// An array of the OAuth 2.0 response type strings that the client can
	// use at the authorization endpoint. Can be one of:
	//
	// - Needed for OpenID Connect Implicit Grant:
	//   - Returns ID Token to redirect URI: `id_token`
	//   - Returns Access token redirect URI: `token`
	// - Needed for Authorization Code Grant: `code`
	ResponseTypes []string `json:"response_types"`

	// OAuth 2.0 Client Scope
	//
	// Scope is a string containing a space-separated list of scope values (as
	// described in Section 3.3 of OAuth 2.0 [RFC6749]) that the client
	// can use when requesting access tokens.
	//
	// Example: scope1 scope-2 scope.3 scope:4
	Scope string `json:"scope"`

	// OAuth 2.0 Client Audience
	//
	// An allow-list defining the audiences this client is allowed to request tokens for. An audience limits
	// the applicability of an OAuth 2.0 Access Token to, for example, certain API endpoints. The value is a list
	// of URLs. URLs MUST NOT contain whitespaces.
	//
	// Example: https://mydomain.com/api/users, https://mydomain.com/api/posts
	Audience []string `json:"audience"`

	// OAuth 2.0 Client Owner
	//
	// Owner is a string identifying the owner of the OAuth 2.0 Client.
	Owner string `json:"owner"`

	// OAuth 2.0 Client Policy URI
	//
	// PolicyURI is a URL string that points to a human-readable privacy policy document
	// that describes how the deployment organization collects, uses,
	// retains, and discloses personal data.
	PolicyURI string `json:"policy_uri"`

	// OAuth 2.0 Client Allowed CORS Origins
	//
	// One or more URLs (scheme://host[:port]) which are allowed to make CORS requests
	// to the /oauth/token endpoint. If this array is empty, the server's CORS origin configuration (`CORS_ALLOWED_ORIGINS`)
	// will be used instead. If this array is set, the allowed origins are appended to the server's CORS origin configuration.
	// Be aware that environment variable `CORS_ENABLED` MUST be set to `true` for this to work.
	AllowedCORSOrigins []string `json:"allowed_cors_origins"`

	// OAuth 2.0 Client Terms of Service URI
	//
	// A URL string pointing to a human-readable terms of service
	// document for the client that describes a contractual relationship
	// between the end-user and the client that the end-user accepts when
	// authorizing the client.
	TermsOfServiceURI string `json:"tos_uri"`

	// OAuth 2.0 Client URI
	//
	// ClientURI is a URL string of a web page providing information about the client.
	// If present, the server SHOULD display this URL to the end-user in
	// a clickable fashion.
	ClientURI string `json:"client_uri"`

	// OAuth 2.0 Client Logo URI
	//
	// A URL string referencing the client's logo.
	LogoURI string `json:"logo_uri"`

	// OAuth 2.0 Client Contact
	//
	// An array of strings representing ways to contact people responsible
	// for this client, typically email addresses.
	//
	// Example: help@example.org
	Contacts []string `json:"contacts"`

	// OAuth 2.0 Client Secret Expires At
	//
	// The field is currently not supported and its value is always 0.
	SecretExpiresAt int `json:"client_secret_expires_at"`

	// OpenID Connect Subject Type
	//
	// The `subject_types_supported` Discovery parameter contains a
	// list of the supported subject_type values for this server. Valid types include `pairwise` and `public`.
	SubjectType string `json:"subject_type"`

	// OpenID Connect Sector Identifier URI
	//
	// URL using the https scheme to be used in calculating Pseudonymous Identifiers by the OP. The URL references a
	// file with a single JSON array of redirect_uri values.
	SectorIdentifierURI string `json:"sector_identifier_uri,omitempty"`

	// OAuth 2.0 Client JSON Web Key Set URL
	//
	// URL for the Client's JSON Web Key Set [JWK] document. If the Client signs requests to the Server, it contains
	// the signing key(s) the Server uses to validate signatures from the Client. The JWK Set MAY also contain the
	// Client's encryption keys(s), which are used by the Server to encrypt responses to the Client. When both signing
	// and encryption keys are made available, a use (Key Use) parameter value is REQUIRED for all keys in the referenced
	// JWK Set to indicate each key's intended usage. Although some algorithms allow the same key to be used for both
	// signatures and encryption, doing so is NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used
	// to provide X.509 representations of keys provided. When used, the bare key values MUST still be present and MUST
	// match those in the certificate.
	JSONWebKeysURI string `json:"jwks_uri,omitempty"`

	// OAuth 2.0 Client JSON Web Key Set
	//
	// Client's JSON Web Key Set [JWK] document, passed by value. The semantics of the jwks parameter are the same as
	// the jwks_uri parameter, other than that the JWK Set is passed by value, rather than by reference. This parameter
	// is intended only to be used by Clients that, for some reason, are unable to use the jwks_uri parameter, for
	// instance, by native applications that might not have a location to host the contents of the JWK Set. If a Client
	// can use jwks_uri, it MUST NOT use jwks. One significant downside of jwks is that it does not enable key rotation
	// (which jwks_uri does, as described in Section 10 of OpenID Connect Core 1.0 [OpenID.Core]). The jwks_uri and jwks
	// parameters MUST NOT be used together.
	JSONWebKeys *jose.JSONWebKeySet `json:"jwks,omitempty"`

	// OAuth 2.0 Token Endpoint Authentication Method
	//
	// Requested Client Authentication method for the Token Endpoint. The options are:
	//
	// - `client_secret_basic`: (default) Send `client_id` and `client_secret` as `application/x-www-form-urlencoded` encoded in the HTTP Authorization header.
	// - `client_secret_post`: Send `client_id` and `client_secret` as `application/x-www-form-urlencoded` in the HTTP body.
	// - `private_key_jwt`: Use JSON Web Tokens to authenticate the client.
	// - `none`: Used for public clients (native apps, mobile apps) which can not have secrets.
	//
	// default: client_secret_basic
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// OAuth 2.0 Token Endpoint Signing Algorithm
	//
	// Requested Client Authentication signing algorithm for the Token Endpoint.
	TokenEndpointAuthSigningAlgorithm string `json:"token_endpoint_auth_signing_alg,omitempty"`

	// OpenID Connect Request URIs
	//
	// Array of request_uri values that are pre-registered by the RP for use at the OP. Servers MAY cache the
	// contents of the files referenced by these URIs and not retrieve them at the time they are used in a request.
	// OPs can require that request_uri values used be pre-registered with the require_request_uri_registration
	// discovery parameter.
	RequestURIs []string `json:"request_uris,omitempty"`

	// OpenID Connect Request Object Signing Algorithm
	//
	// JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP. All Request Objects
	// from this Client MUST be rejected, if not signed with this algorithm.
	RequestObjectSigningAlgorithm string `json:"request_object_signing_alg,omitempty"`

	// OpenID Connect Request Userinfo Signed Response Algorithm
	//
	// JWS alg algorithm [JWA] REQUIRED for signing UserInfo Responses. If this is specified, the response will be JWT
	// [JWT] serialized, and signed using JWS. The default, if omitted, is for the UserInfo Response to return the Claims
	// as a UTF-8 encoded JSON object using the application/json content-type.
	UserinfoSignedResponseAlgorithm string `json:"userinfo_signed_response_alg,omitempty"`

	// // OpenID Connect Front-Channel Logout URI
	// //
	// // RP URL that will cause the RP to log itself out when rendered in an iframe by the OP. An iss (issuer) query
	// // parameter and a sid (session ID) query parameter MAY be included by the OP to enable the RP to validate the
	// // request and to determine which of the potentially multiple sessions is to be logged out; if either is
	// // included, both MUST be.
	// FrontChannelLogoutURI string `json:"frontchannel_logout_uri,omitempty"`

	// // OpenID Connect Front-Channel Logout Session Required
	// //
	// // Boolean value specifying whether the RP requires that iss (issuer) and sid (session ID) query parameters be
	// // included to identify the RP session with the OP when the frontchannel_logout_uri is used.
	// // If omitted, the default value is false.
	// FrontChannelLogoutSessionRequired bool `json:"frontchannel_logout_session_required,omitempty"`

	// // Allowed Post-Redirect Logout URIs
	// //
	// // Array of URLs supplied by the RP to which it MAY request that the End-User's User Agent be redirected using the
	// // post_logout_redirect_uri parameter after a logout has been performed.
	// PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`

	// // OpenID Connect Back-Channel Logout URI
	// //
	// // RP URL that will cause the RP to log itself out when sent a Logout Token by the OP.
	// BackChannelLogoutURI string `json:"backchannel_logout_uri,omitempty"`

	// // OpenID Connect Back-Channel Logout Session Required
	// //
	// // Boolean value specifying whether the RP requires that a sid (session ID) Claim be included in the Logout
	// // Token to identify the RP session with the OP when the backchannel_logout_uri is used.
	// // If omitted, the default value is false.
	// BackChannelLogoutSessionRequired bool `json:"backchannel_logout_session_required,omitempty"`

	// OAuth 2.0 Client Metadata
	//
	// Use this field to store arbitrary data about the OAuth 2.0 Client. Can not be modified using OpenID Connect Dynamic Client Registration protocol.
	Metadata json.RawMessage `json:"metadata,omitempty"`

	// OAuth 2.0 Access Token Strategy
	//
	// AccessTokenStrategy is the strategy used to generate access tokens.
	// Valid options are `jwt` and `opaque`. `jwt` is a bad idea, see https://www.ory.sh/docs/oauth2-oidc/jwt-access-token
	// Setting the strategy here overrides the global setting in `strategies.access_token`.
	AccessTokenStrategy string `json:"access_token_strategy,omitempty"`
}

// GetAudience implements [fosite.Client].
func (c *Client) GetAudience() fosite.Arguments {
	return c.Audience
}

// GetGrantTypes implements [fosite.Client].
func (c *Client) GetGrantTypes() fosite.Arguments {
	return c.GrantTypes
}

// GetHashedSecret implements [fosite.Client].
func (c *Client) GetHashedSecret() []byte {
	return []byte(c.Secret)
}

// GetID implements [fosite.Client].
func (c *Client) GetID() string {
	return c.ID
}

// GetRedirectURIs implements [fosite.Client].
func (c *Client) GetRedirectURIs() []string {
	return c.RedirectURIs
}

// GetResponseTypes implements [fosite.Client].
func (c *Client) GetResponseTypes() fosite.Arguments {
	return c.ResponseTypes
}

// GetScopes implements [fosite.Client].
func (c *Client) GetScopes() fosite.Arguments {
	return strings.Split(c.Scope, " ")
}

// IsPublic implements [fosite.Client].
func (c *Client) IsPublic() bool {
	return c.TokenEndpointAuthMethod == "none"
}

// GetJSONWebKeys implements [fosite.OpenIDConnectClient].
func (c *Client) GetJSONWebKeys() *jose.JSONWebKeySet {
	return c.JSONWebKeys
}

// GetJSONWebKeysURI implements [fosite.OpenIDConnectClient].
func (c *Client) GetJSONWebKeysURI() string {
	return c.JSONWebKeysURI
}

// GetRequestObjectSigningAlgorithm implements [fosite.OpenIDConnectClient].
func (c *Client) GetRequestObjectSigningAlgorithm() string {
	return c.RequestObjectSigningAlgorithm
}

// GetRequestURIs implements [fosite.OpenIDConnectClient].
func (c *Client) GetRequestURIs() []string {
	return c.RequestURIs
}

// GetTokenEndpointAuthMethod implements [fosite.OpenIDConnectClient].
func (c *Client) GetTokenEndpointAuthMethod() string {
	return c.TokenEndpointAuthMethod
}

// GetTokenEndpointAuthSigningAlgorithm implements [fosite.OpenIDConnectClient].
func (c *Client) GetTokenEndpointAuthSigningAlgorithm() string {
	return c.TokenEndpointAuthSigningAlgorithm
}

// GetResponseModes implements [fosite.ResponseModeClient].
func (c *Client) GetResponseModes() []fosite.ResponseModeType {
	return []fosite.ResponseModeType{
		fosite.ResponseModeDefault,
		fosite.ResponseModeFragment,
		fosite.ResponseModeFormPost,
		fosite.ResponseModeQuery,
	}
}
