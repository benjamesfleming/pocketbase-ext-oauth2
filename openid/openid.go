package openid

import "github.com/benjamesfleming/pocketbase-ext-oauth2/rfc8414"

// @ref https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata

type OpenIDProviderMetadata struct {
	rfc8414.AuthorizationServerMetadata

	// UserInfo Endpoint
	// RECOMMENDED. URL of the OP's UserInfo Endpoint [OpenID.Core].
	// This URL MUST use the https scheme and MAY contain port, path,
	// and query parameter components.
	UserInfoEndpoint string `json:"userinfo_endpoint"`

	// Acr Values Supported
	// OPTIONAL. JSON array containing a list of the Authentication
	// Context Class References that this OP supports.
	AcrValuesSupported []string `json:"acr_values_supported,omitempty"`

	// Subject Types Supported
	// REQUIRED. JSON array containing a list of the Subject Identifier
	// types that this OP supports. Valid types include pairwise and public.
	SubjectTypesSupported []string `json:"subject_types_supported"`

	// ID Token Signing Algorithms Supported
	// REQUIRED. JSON array containing a list of the JWS signing algorithms
	// (alg values) supported by the OP for the ID Token to encode the Claims
	// in a JWT [JWT]. The algorithm RS256 MUST be included. The value none MAY
	// be supported but MUST NOT be used unless the Response Type used returns
	// no ID Token from the Authorization Endpoint (such as when using the
	// Authorization Code Flow).
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// ID Token Encryption Algorithms Supported
	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms
	// (alg values) supported by the OP for the ID Token to encode the Claims
	// in a JWT [JWT].
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"`

	// ID Token Encryption Encodings Supported
	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms
	// (enc values) supported by the OP for the ID Token to encode the Claims
	// in a JWT [JWT].
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported,omitempty"`

	// UserInfo Signing Algorithms Supported
	// OPTIONAL. JSON array containing a list of the JWS [JWS] signing algorithms
	// (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims
	// in a JWT [JWT]. The value none MAY be included.
	UserInfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported,omitempty"`

	// UserInfo Encryption Algorithms Supported
	// OPTIONAL. JSON array containing a list of the JWE [JWE] encryption algorithms
	// (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims
	// in a JWT [JWT].
	UserInfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`

	// UserInfo Encryption Encodings Supported
	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc
	// values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a
	// JWT [JWT].
	UserInfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"`

	// Request Object Signing Algorithms Supported
	// OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values)
	// supported by the OP for Request Objects, which are described in Section 6.1 of
	// OpenID Connect Core 1.0 [OpenID.Core]. These algorithms are used both when the
	// Request Object is passed by value (using the request parameter) and when it is
	// passed by reference (using the request_uri parameter). Servers SHOULD support
	// none and RS256.
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`

	// Request Object Encryption Algorithms Supported
	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values)
	// supported by the OP for Request Objects. These algorithms are used both when the
	// Request Object is passed by value and when it is passed by reference.
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"`

	// Request Object Encryption Encodings Supported
	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values)
	// supported by the OP for Request Objects. These algorithms are used both when the
	// Request Object is passed by value and when it is passed by reference.
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"`

	// Display Values Supported
	// OPTIONAL. JSON array containing a list of the display parameter values that the OpenID
	// Provider supports. These values are described in Section 3.1.2.1 of OpenID Connect
	// Core 1.0 [OpenID.Core].
	DisplayValuesSupported []string `json:"display_values_supported,omitempty"`

	// Claim Types Supported
	// OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports.
	// These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core].
	// Values defined by this specification are normal, aggregated, and distributed. If omitted,
	// the implementation supports only normal Claims.
	ClaimTypesSupported []string `json:"claim_types_supported,omitempty"`

	// Claims Supported
	// RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID
	// Provider MAY be able to supply values for. Note that for privacy or other reasons, this
	// might not be an exhaustive list.
	ClaimsSupported []string `json:"claims_supported,omitempty"`

	// Claims Locales Supported
	// OPTIONAL. Languages and scripts supported for values in Claims being returned, represented
	// as a JSON array of BCP47 [RFC5646] language tag values. Not all languages and scripts are
	// necessarily supported for all Claim values.
	ClaimsLocalesSupported []string `json:"claims_locales_supported,omitempty"`

	// Claims Parameter Supported
	// OPTIONAL. Boolean value specifying whether the OP supports use of the claims parameter,
	// with true indicating support. If omitted, the default value is false.
	ClaimsParameterSupported bool `json:"claims_parameter_supported,omitempty"`

	// Request Parameter Supported
	// OPTIONAL. Boolean value specifying whether the OP supports use of the request parameter,
	// with true indicating support. If omitted, the default value is false.
	RequestParameterSupported bool `json:"request_parameter_supported,omitempty"`

	// Request URI Parameter Supported
	// OPTIONAL. Boolean value specifying whether the OP supports use of the request_uri parameter,
	// with true indicating support. If omitted, the default value is true.
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported,omitempty"`

	// Require Request URI Registration
	// OPTIONAL. Boolean value specifying whether the OP requires any request_uri values used to be
	// pre-registered using the request_uris registration parameter. Pre-registration is REQUIRED
	// when the value is true. If omitted, the default value is false.
	RequireRequestURIRegistration bool `json:"require_request_uri_registration,omitempty"`
}
