package openid

import "github.com/benjamesfleming/pocketbase-ext-oauth2/rfc8414"

// @ref https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata

type OpenIDProviderMetadata struct {
	rfc8414.AuthorizationServerMetadata

	UserInfoEndpoint string `json:"userinfo_endpoint"`
	JwksURI          string `json:"jwks_uri"`
}
