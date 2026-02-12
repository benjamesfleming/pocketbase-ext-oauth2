package client

import (
	"strings"
	"testing"

	"github.com/ory/fosite"
)

func TestClientImplementsFositeClient(t *testing.T) {
	c := &Client{}
	var _ fosite.Client = c
	var _ fosite.OpenIDConnectClient = c
	var _ fosite.ResponseModeClient = c
}

func TestClientGetID(t *testing.T) {
	c := &Client{ID: "my-client-id"}
	if got := c.GetID(); got != "my-client-id" {
		t.Errorf("GetID() = %q, want %q", got, "my-client-id")
	}
}

func TestClientGetHashedSecret(t *testing.T) {
	c := &Client{Secret: "hashed-secret"}
	got := c.GetHashedSecret()
	if string(got) != "hashed-secret" {
		t.Errorf("GetHashedSecret() = %q, want %q", string(got), "hashed-secret")
	}
}

func TestClientGetScopes(t *testing.T) {
	c := &Client{Scope: "openid profile email"}
	scopes := c.GetScopes()
	if len(scopes) != 3 {
		t.Fatalf("GetScopes() len = %d, want 3", len(scopes))
	}
	expected := []string{"openid", "profile", "email"}
	for i, s := range expected {
		if scopes[i] != s {
			t.Errorf("GetScopes()[%d] = %q, want %q", i, scopes[i], s)
		}
	}
}

func TestClientGetScopes_Empty(t *testing.T) {
	c := &Client{Scope: ""}
	scopes := c.GetScopes()
	// strings.Split("", " ") returns [""] — a single empty string
	if len(scopes) != 1 || scopes[0] != "" {
		t.Errorf("GetScopes() = %v, want [\"\"]", scopes)
	}
}

func TestClientGetGrantTypes(t *testing.T) {
	c := &Client{GrantTypes: []string{"authorization_code", "refresh_token"}}
	gt := c.GetGrantTypes()
	if len(gt) != 2 {
		t.Fatalf("GetGrantTypes() len = %d, want 2", len(gt))
	}
}

func TestClientGetResponseTypes(t *testing.T) {
	c := &Client{ResponseTypes: []string{"code", "token"}}
	rt := c.GetResponseTypes()
	if len(rt) != 2 {
		t.Fatalf("GetResponseTypes() len = %d, want 2", len(rt))
	}
}

func TestClientGetRedirectURIs(t *testing.T) {
	uris := []string{"http://localhost/callback", "http://example.com/cb"}
	c := &Client{RedirectURIs: uris}
	got := c.GetRedirectURIs()
	if len(got) != 2 {
		t.Fatalf("GetRedirectURIs() len = %d, want 2", len(got))
	}
	for i, u := range uris {
		if got[i] != u {
			t.Errorf("GetRedirectURIs()[%d] = %q, want %q", i, got[i], u)
		}
	}
}

func TestClientGetAudience(t *testing.T) {
	c := &Client{Audience: []string{"https://api.example.com"}}
	aud := c.GetAudience()
	if len(aud) != 1 || aud[0] != "https://api.example.com" {
		t.Errorf("GetAudience() = %v, want [https://api.example.com]", aud)
	}
}

func TestClientIsPublic(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   bool
	}{
		{"none is public", "none", true},
		{"client_secret_basic is not public", "client_secret_basic", false},
		{"client_secret_post is not public", "client_secret_post", false},
		{"empty is not public", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{TokenEndpointAuthMethod: tt.method}
			if got := c.IsPublic(); got != tt.want {
				t.Errorf("IsPublic() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClientGetResponseModes(t *testing.T) {
	c := &Client{}
	modes := c.GetResponseModes()
	if len(modes) != 4 {
		t.Fatalf("GetResponseModes() len = %d, want 4", len(modes))
	}
	// Check that default, fragment, form_post, and query are present
	modeSet := make(map[fosite.ResponseModeType]bool)
	for _, m := range modes {
		modeSet[m] = true
	}
	for _, expected := range []fosite.ResponseModeType{
		fosite.ResponseModeDefault,
		fosite.ResponseModeFragment,
		fosite.ResponseModeFormPost,
		fosite.ResponseModeQuery,
	} {
		if !modeSet[expected] {
			t.Errorf("missing response mode %v", expected)
		}
	}
}

func TestClientGetTokenEndpointAuthMethod(t *testing.T) {
	c := &Client{TokenEndpointAuthMethod: "client_secret_post"}
	if got := c.GetTokenEndpointAuthMethod(); got != "client_secret_post" {
		t.Errorf("GetTokenEndpointAuthMethod() = %q, want %q", got, "client_secret_post")
	}
}

func TestClientGetTokenEndpointAuthSigningAlgorithm(t *testing.T) {
	c := &Client{TokenEndpointAuthSigningAlgorithm: "RS256"}
	if got := c.GetTokenEndpointAuthSigningAlgorithm(); got != "RS256" {
		t.Errorf("got %q, want %q", got, "RS256")
	}
}

func TestClientGetRequestObjectSigningAlgorithm(t *testing.T) {
	c := &Client{RequestObjectSigningAlgorithm: "ES256"}
	if got := c.GetRequestObjectSigningAlgorithm(); got != "ES256" {
		t.Errorf("got %q, want %q", got, "ES256")
	}
}

func TestClientGetJSONWebKeysURI(t *testing.T) {
	c := &Client{JSONWebKeysURI: "http://example.com/jwks"}
	if got := c.GetJSONWebKeysURI(); got != "http://example.com/jwks" {
		t.Errorf("got %q, want %q", got, "http://example.com/jwks")
	}
}

func TestClientGetJSONWebKeys_Nil(t *testing.T) {
	c := &Client{}
	if got := c.GetJSONWebKeys(); got != nil {
		t.Errorf("GetJSONWebKeys() = %v, want nil", got)
	}
}

func TestClientGetRequestURIs(t *testing.T) {
	c := &Client{RequestURIs: []string{"http://example.com/request"}}
	got := c.GetRequestURIs()
	if len(got) != 1 || got[0] != "http://example.com/request" {
		t.Errorf("GetRequestURIs() = %v", got)
	}
}

func TestClientScopesSplitBySpace(t *testing.T) {
	c := &Client{Scope: "openid profile email offline_access"}
	scopes := c.GetScopes()
	parts := strings.Split("openid profile email offline_access", " ")
	if len(scopes) != len(parts) {
		t.Fatalf("scopes len = %d, want %d", len(scopes), len(parts))
	}
	for i, p := range parts {
		if scopes[i] != p {
			t.Errorf("scope[%d] = %q, want %q", i, scopes[i], p)
		}
	}
}
