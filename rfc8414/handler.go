package rfc8414

import (
	"encoding/json"
	"net/http"

	"github.com/pocketbase/pocketbase/core"
)

type AuthorizationServerMetadata struct {
	Issuer                 string   `json:"issuer"`
	AuthzEndpoint          string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	RegistrationEndpoint   string   `json:"registration_endpoint"`
	ResponseTypesSupported []string `json:"response_types_supported"`
}

func HandleAuthorizationServerMetadata(metadata *AuthorizationServerMetadata) func(e *core.RequestEvent) error {
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
