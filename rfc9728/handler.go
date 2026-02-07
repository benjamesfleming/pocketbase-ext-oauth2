package rfc9728

import (
	"encoding/json"
	"net/http"

	"github.com/pocketbase/pocketbase/core"
)

type ProtectedResourceMetadata struct {
	Resource                              string   `json:"resource"`
	AuthorizationServers                  []string `json:"authorization_servers,omitempty"`
	JwksURI                               string   `json:"jwks_uri,omitempty"`
	ScopesSupported                       []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported                []string `json:"bearer_methods_supported,omitempty"`
	ResourceSigningAlgValuesSupported     []string `json:"resource_signing_alg_values_supported,omitempty"`
	ResourceName                          string   `json:"resource_name,omitempty"`
	ResourceDocumentation                 string   `json:"resource_documentation,omitempty"`
	ResourcePolicyURI                     string   `json:"resource_policy_uri,omitempty"`
	ResourceTOSURI                        string   `json:"resource_tos_uri,omitempty"`
	TLSClientCertificateBoundAccessTokens bool     `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	AuthorizationDetailsTypesSupported    []string `json:"authorization_details_types_supported,omitempty"`
	DPOPSigningAlgValuesSupported         []string `json:"dpop_signing_alg_values_supported,omitempty"`
	DPOPBoundAccessTokensRequired         bool     `json:"dpop_bound_access_tokens_required,omitempty"`
}

// ProtectedResourceMetadataHandler returns an http.Handler that serves OAuth 2.0
// protected resource metadata (RFC 9728) with CORS support.
//
// This handler allows cross-origin requests from any origin (Access-Control-Allow-Origin: *)
// because OAuth metadata is public information intended for client discovery (RFC 9728 §3.1).
// The metadata contains only non-sensitive configuration data about authorization servers
// and supported scopes.
//
// No validation of metadata fields is performed; ensure metadata accuracy at configuration time.
//
// For more sophisticated CORS policies or to restrict origins, wrap this handler with a
// CORS middleware like github.com/rs/cors or github.com/jub0bs/cors.
func HandleProtectedResourceMetadata(metadata *ProtectedResourceMetadata) func(e *core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		r := e.Request
		w := e.Response
		// Set CORS headers for cross-origin client discovery.
		// OAuth metadata is public information, so allowing any origin is safe.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Handle CORS preflight requests
		if r.Method == http.MethodOptions {
			return e.NoContent(http.StatusNoContent)
		}

		// Only GET allowed for metadata retrieval
		if r.Method != http.MethodGet {
			return e.Error(http.StatusMethodNotAllowed, "", nil)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(metadata); err != nil {
			return e.InternalServerError("", err)
		}

		return nil
	}
}
