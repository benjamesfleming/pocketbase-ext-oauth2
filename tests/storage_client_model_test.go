package oauth2

import (
	"testing"

	oauth2 "github.com/benjamesfleming/pocketbase-ext-oauth2"
	"github.com/benjamesfleming/pocketbase-ext-oauth2/consts"
	"github.com/pocketbase/pocketbase/core"
)

func TestClientModelToClient(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	c, err := app.FindCollectionByNameOrId(consts.ClientCollectionName)
	if err != nil {
		t.Fatalf("failed to find clients collection: %v", err)
	}

	m := &oauth2.ClientModel{}
	m.Record = core.NewRecord(c)
	m.Set("client_id", "my-client")
	m.Set("client_name", "My App")
	m.Set("client_secret", "hashed_secret")
	m.Set("client_secret_expires_at", 0)
	m.Set("redirect_uris", []string{"http://localhost/cb", "http://localhost/cb2"})
	m.Set("grant_types", []string{"authorization_code", "refresh_token"})
	m.Set("response_types", []string{"code"})
	m.Set("scope", "openid profile email")
	m.Set("audience", []string{"https://api.example.com"})
	m.Set("owner", "owner1")
	m.Set("policy_uri", "http://example.com/policy")
	m.Set("tos_uri", "http://example.com/tos")
	m.Set("client_uri", "http://example.com")
	m.Set("logo_uri", "http://example.com/logo.png")
	m.Set("contacts", []string{"admin@example.com"})
	m.Set("allowed_cors_origins", []string{"http://localhost"})
	m.Set("subject_type", "public")
	m.Set("sector_identifier_uri", "")
	m.Set("jwks_uri", "http://example.com/jwks")
	m.Set("jwks", nil)
	m.Set("request_uris", []string{})
	m.Set("token_endpoint_auth_method", "client_secret_post")
	m.Set("token_endpoint_auth_signing_alg", "RS256")
	m.Set("request_object_signing_alg", "ES256")
	m.Set("userinfo_signed_response_alg", "EdDSA")
	m.Set("metadata", nil)
	m.Set("access_token_strategy", "opaque")

	client, err := m.ToClient()
	if err != nil {
		t.Fatalf("ToClient() failed: %v", err)
	}

	// Verify all fields
	if client.ID != "my-client" {
		t.Errorf("ID = %q, want %q", client.ID, "my-client")
	}
	if client.Name != "My App" {
		t.Errorf("Name = %q, want %q", client.Name, "My App")
	}
	if client.Secret != "hashed_secret" {
		t.Errorf("Secret = %q, want %q", client.Secret, "hashed_secret")
	}
	if len(client.RedirectURIs) != 2 {
		t.Errorf("RedirectURIs len = %d, want 2", len(client.RedirectURIs))
	}
	if len(client.GrantTypes) != 2 || client.GrantTypes[0] != "authorization_code" {
		t.Errorf("GrantTypes = %v, want [authorization_code refresh_token]", client.GrantTypes)
	}
	if len(client.ResponseTypes) != 1 || client.ResponseTypes[0] != "code" {
		t.Errorf("ResponseTypes = %v, want [code]", client.ResponseTypes)
	}
	if client.Scope != "openid profile email" {
		t.Errorf("Scope = %q, want %q", client.Scope, "openid profile email")
	}
	if client.Owner != "owner1" {
		t.Errorf("Owner = %q, want %q", client.Owner, "owner1")
	}
	if client.PolicyURI != "http://example.com/policy" {
		t.Errorf("PolicyURI = %q, want %q", client.PolicyURI, "http://example.com/policy")
	}
	if client.TermsOfServiceURI != "http://example.com/tos" {
		t.Errorf("TermsOfServiceURI = %q, want %q", client.TermsOfServiceURI, "http://example.com/tos")
	}
	if client.ClientURI != "http://example.com" {
		t.Errorf("ClientURI = %q, want %q", client.ClientURI, "http://example.com")
	}
	if client.LogoURI != "http://example.com/logo.png" {
		t.Errorf("LogoURI = %q, want %q", client.LogoURI, "http://example.com/logo.png")
	}
	if len(client.Contacts) != 1 || client.Contacts[0] != "admin@example.com" {
		t.Errorf("Contacts = %v, want [admin@example.com]", client.Contacts)
	}
	if client.SubjectType != "public" {
		t.Errorf("SubjectType = %q, want %q", client.SubjectType, "public")
	}
	if client.JSONWebKeysURI != "http://example.com/jwks" {
		t.Errorf("JSONWebKeysURI = %q, want %q", client.JSONWebKeysURI, "http://example.com/jwks")
	}
	if client.TokenEndpointAuthMethod != "client_secret_post" {
		t.Errorf("TokenEndpointAuthMethod = %q, want %q", client.TokenEndpointAuthMethod, "client_secret_post")
	}
	if client.TokenEndpointAuthSigningAlgorithm != "RS256" {
		t.Errorf("TokenEndpointAuthSigningAlg = %q, want %q", client.TokenEndpointAuthSigningAlgorithm, "RS256")
	}
	if client.AccessTokenStrategy != "opaque" {
		t.Errorf("AccessTokenStrategy = %q, want %q", client.AccessTokenStrategy, "opaque")
	}
}

func TestClientModelToClient_EmptyRecord(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	c, err := app.FindCollectionByNameOrId(consts.ClientCollectionName)
	if err != nil {
		t.Fatalf("failed to find clients collection: %v", err)
	}

	m := &oauth2.ClientModel{}
	m.Record = core.NewRecord(c)

	// ToClient with empty record should not panic
	client, err := m.ToClient()
	if err != nil {
		t.Fatalf("ToClient() on empty record failed: %v", err)
	}
	if client.ID != "" {
		t.Errorf("expected empty ID, got %q", client.ID)
	}
	if client.Scope != "" {
		t.Errorf("expected empty Scope, got %q", client.Scope)
	}
}

func TestNewClientModel(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	m := oauth2.NewClientModel(app)
	if m == nil {
		t.Fatal("expected non-nil ClientModel")
	}
	if m.ProxyRecord() == nil {
		t.Fatal("expected non-nil underlying record")
	}
}

func TestNewClientFromRFC7591Metadata(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	md := &oauth2.RFC7591ClientMetadataRequest{
		ClientName:   "Dynamic Client",
		RedirectURIs: []string{"http://localhost/callback"},
		ClientURI:    "http://example.com",
	}

	client, secret, err := oauth2.NewClientFromRFC7591Metadata(app, md)
	if err != nil {
		t.Fatalf("NewClientFromRFC7591Metadata failed: %v", err)
	}

	// Client ID should be a UUID
	if len(client.GetID()) == 0 {
		t.Error("expected non-empty client ID")
	}

	// Secret should be non-empty
	if len(secret) == 0 {
		t.Error("expected non-empty client secret")
	}

	// Defaults should be applied
	if len(client.GetGrantTypes()) == 0 {
		t.Error("expected default grant types to be set")
	}
	if len(client.GetResponseTypes()) == 0 {
		t.Error("expected default response types to be set")
	}

	// Name should match
	if client.Name != "Dynamic Client" {
		t.Errorf("client name = %q, want %q", client.Name, "Dynamic Client")
	}
}

func TestNewClientFromRFC7591Metadata_DefaultScope(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	md := &oauth2.RFC7591ClientMetadataRequest{
		ClientName:   "Scopeless Client",
		RedirectURIs: []string{"http://localhost/callback"},
		// Scope intentionally left empty
	}

	client, _, err := oauth2.NewClientFromRFC7591Metadata(app, md)
	if err != nil {
		t.Fatalf("NewClientFromRFC7591Metadata failed: %v", err)
	}

	// Default scope should be applied
	scopes := client.GetScopes()
	if len(scopes) == 0 {
		t.Error("expected default scopes to be applied")
	}
}
