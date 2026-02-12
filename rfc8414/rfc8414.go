package rfc8414

// @ref https://datatracker.ietf.org/doc/html/rfc8414

type AuthorizationServerMetadata struct {
	// Issuer
	// REQUIRED. The authorization server's issuer identifier, which is
	// a URL that uses the "https" scheme and has no query or fragment
	// components.  Authorization server metadata is published at a
	// location that is ".well-known" according to RFC 5785 [RFC5785]
	// derived from this issuer identifier, as described in Section 3.
	// The issuer identifier is used to prevent authorization server mix-
	// up attacks, as described in "OAuth 2.0 Mix-Up Mitigation"
	// [MIX-UP].
	Issuer string `json:"issuer"`

	// Authorization Endpoint
	// URL of the authorization server's authorization endpoint [RFC6749].
	// This is REQUIRED unless no grant types are supported that use the
	// authorization endpoint.
	AuthzEndpoint string `json:"authorization_endpoint"`

	// Token Endpoint
	// URL of the authorization server's token endpoint [RFC6749].  This
	// is REQUIRED unless only the implicit grant type is supported.
	TokenEndpoint string `json:"token_endpoint"`

	// JWKS URI
	// OPTIONAL. URL of the authorization server's JWK Set [JWK]
	// document. The referenced document contains the signing key(s) the
	// client uses to validate signatures from the authorization server.
	// This URL MUST use the "https" scheme.  The JWK Set MAY also
	// contain the server's encryption key or keys, which are used by
	// clients to encrypt requests to the server.  When both signing and
	// encryption keys are made available, a "use" (public key use)
	// parameter value is REQUIRED for all keys in the referenced JWK Set
	// to indicate each key's intended usage.
	JwksURI string `json:"jwks_uri"`

	// Registration Endpoint
	// OPTIONAL. URL of the authorization server's OAuth 2.0 Dynamic
	// Client Registration endpoint [RFC7591].
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// Scopes Supported
	// RECOMMENDED. JSON array containing a list of the OAuth 2.0
	// [RFC6749] "scope" values that this authorization server supports.
	// Servers MAY choose not to advertise some supported scope values
	// even when this parameter is used.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// Response Types Supported
	// REQUIRED. JSON array containing a list of the OAuth 2.0
	// "response_type" values that this authorization server supports.
	// The array values used are the same as those used with the
	// "response_types" parameter defined by "OAuth 2.0 Dynamic Client
	// Registration Protocol" [RFC7591].
	ResponseTypesSupported []string `json:"response_types_supported"`

	// Response Modes Supported
	// OPTIONAL. JSON array containing a list of the OAuth 2.0
	// "response_mode" values that this authorization server supports, as
	// specified in "OAuth 2.0 Multiple Response Type Encoding Practices"
	// [OAuth.Responses].  If omitted, the default is "["query",
	// "fragment"]".  The response mode value "form_post" is also defined
	// in "OAuth 2.0 Form Post Response Mode" [OAuth.Post].
	ResponseModesSupported []string `json:"response_modes_supported"`

	// Grant Types Supported
	// OPTIONAL. JSON array containing a list of the OAuth 2.0 grant
	// type values that this authorization server supports.  The array
	// values used are the same as those used with the "grant_types"
	// parameter defined by "OAuth 2.0 Dynamic Client Registration
	// Protocol" [RFC7591].  If omitted, the default value is
	// "["authorization_code", "implicit"]".
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// Token Endpoint Authentication Methods Supported
	// OPTIONAL. JSON array containing a list of client authentication
	// methods supported by this token endpoint.  Client authentication
	// method values are used in the "token_endpoint_auth_method"
	// parameter defined in Section 2 of [RFC7591].  If omitted, the
	// default is "client_secret_basic" -- the HTTP Basic Authentication
	// Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// Token Endpoint Authentication Signing Algorithms Supported
	// OPTIONAL. JSON array containing a list of the JWS signing
	// algorithms ("alg" values) supported by the token endpoint for the
	// signature on the JWT [JWT] used to authenticate the client at the
	// token endpoint for the "private_key_jwt" and "client_secret_jwt"
	// authentication methods.  This metadata entry MUST be present if
	// either of these authentication methods are specified in the
	// "token_endpoint_auth_methods_supported" entry.  No default
	// algorithms are implied if this entry is omitted.  Servers SHOULD
	// support "RS256".  The value "none" MUST NOT be used.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	// Service Documentation
	// OPTIONAL. URL of a page containing human-readable information
	// that developers might want or need to know when using the
	// authorization server.  In particular, if the authorization server
	// does not support Dynamic Client Registration, then information on
	// how to register clients needs to be provided in this
	// documentation.
	ServiceDocumentation string `json:"service_documentation,omitempty"`

	// UI Locales Supported
	// OPTIONAL. Languages and scripts supported for the user interface,
	// represented as a JSON array of language tag values from BCP 47
	// [RFC5646].  If omitted, the set of supported languages and scripts
	// is unspecified.
	UILocalesSupported []string `json:"ui_locales_supported,omitempty"`

	// OP Policy URI
	// OPTIONAL. URL that the authorization server provides to the
	// person registering the client to read about the authorization
	// server's requirements on how the client can use the data provided
	// by the authorization server.  The registration process SHOULD
	// display this URL to the person registering the client if it is
	// given.  As described in Section 5, despite the identifier
	// "op_policy_uri" appearing to be OpenID-specific, its usage in this
	// specification is actually referring to a general OAuth 2.0 feature
	// that is not specific to OpenID Connect.
	OPPolicyURI string `json:"op_policy_uri,omitempty"`

	// OP Tos URI
	// OPTIONAL. URL that the authorization server provides to the
	// person registering the client to read about the authorization
	// server's terms of service.  The registration process SHOULD
	// display this URL to the person registering the client if it is
	// given.  As described in Section 5, despite the identifier
	// "op_tos_uri", appearing to be OpenID-specific, its usage in this
	// specification is actually referring to a general OAuth 2.0 feature
	// that is not specific to OpenID Connect.
	OPTosURI string `json:"op_tos_uri,omitempty"`

	// Revocation Endpoint
	// OPTIONAL. URL of the authorization server's OAuth 2.0 revocation
	// endpoint [RFC7009].
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// Revocation Endpoint Authentication Methods Supported
	// OPTIONAL. JSON array containing a list of client authentication
	// methods supported by this revocation endpoint.  The valid client
	// authentication method values are those registered in the IANA
	// "OAuth Token Endpoint Authentication Methods" registry
	// [IANA.OAuth.Parameters].  If omitted, the default is
	// "client_secret_basic" -- the HTTP Basic Authentication Scheme
	// specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`

	// Revocation Endpoint Authentication Signing Algorithms Supported
	// OPTIONAL. JSON array containing a list of the JWS signing
	// algorithms ("alg" values) supported by the revocation endpoint for
	// the signature on the JWT [JWT] used to authenticate the client at
	// the revocation endpoint for the "private_key_jwt" and
	// "client_secret_jwt" authentication methods.  This metadata entry
	// MUST be present if either of these authentication methods are
	// specified in the "revocation_endpoint_auth_methods_supported"
	// entry.  No default algorithms are implied if this entry is
	// omitted.  The value "none" MUST NOT be used.
	RevocationEndpointAuthSigningAlgValuesSupported []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`

	// Introspection Endpoint
	// OPTIONAL. URL of the authorization server's OAuth 2.0
	// introspection endpoint [RFC7662].
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// Introspection Endpoint Authentication Methods Supported
	// OPTIONAL. JSON array containing a list of client authentication
	// methods supported by this introspection endpoint.  The valid
	// client authentication method values are those registered in the
	// IANA "OAuth Token Endpoint Authentication Methods" registry
	// [IANA.OAuth.Parameters] or those registered in the IANA "OAuth
	// Access Token Types" registry [IANA.OAuth.Parameters].  (These
	// values are and will remain distinct, due to Section 7.2.)  If
	// omitted, the set of supported authentication methods MUST be
	// determined by other means.
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`

	// Introspection Endpoint Authentication Signing Algorithms Supported
	// OPTIONAL. JSON array containing a list of the JWS signing
	// algorithms ("alg" values) supported by the introspection endpoint
	// for the signature on the JWT [JWT] used to authenticate the client
	// at the introspection endpoint for the "private_key_jwt" and
	// "client_secret_jwt" authentication methods.  This metadata entry
	// MUST be present if either of these authentication methods are
	// specified in the "introspection_endpoint_auth_methods_supported"
	// entry.  No default algorithms are implied if this entry is
	// omitted.  The value "none" MUST NOT be used.
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`

	// Code Challenge Methods Supported
	// OPTIONAL. JSON array containing a list of Proof Key for Code
	// Exchange (PKCE) [RFC7636] code challenge methods supported by this
	// authorization server.  Code challenge method values are used in
	// the "code_challenge_method" parameter defined in Section 4.3 of
	// [RFC7636].  The valid code challenge method values are those
	// registered in the IANA "PKCE Code Challenge Methods" registry
	// [IANA.OAuth.Parameters].  If omitted, the authorization server
	// does not support PKCE.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
}
