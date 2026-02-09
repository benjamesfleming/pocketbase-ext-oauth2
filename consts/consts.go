package consts

// This file contains constant values used across the OAuth2 plugin.
// This package is required to prevent circular imports between the storage
// models and migration code, which both need to reference the collection names.

const (
	ClientCollectionName        = "_oauth2Clients"
	AuthCodeCollectionName      = "_oauth2AuthCode"
	AccessCollectionName        = "_oauth2Access"
	RefreshCollectionName       = "_oauth2Refresh"
	PKCECollectionName          = "_oauth2PKCE"
	OpenIDConnectCollectionName = "_oauth2OpenID"

	CleanupExpiredSessionsJobName = "__pbOAuth2Cleanup__"
)
