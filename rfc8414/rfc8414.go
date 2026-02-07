package rfc8414

type AuthorizationServerMetadata struct {
	Issuer                 string   `json:"issuer"`
	AuthzEndpoint          string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	RegistrationEndpoint   string   `json:"registration_endpoint"`
	ResponseTypesSupported []string `json:"response_types_supported"`
}
