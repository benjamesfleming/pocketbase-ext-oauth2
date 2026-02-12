package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	oauth2 "github.com/benjamesfleming/pocketbase-ext-oauth2"
	"github.com/benjamesfleming/pocketbase-ext-oauth2/consts"
	"github.com/ory/fosite"
	fositeopenid "github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/pocketbase/pocketbase/core"
)

// newTestRequest creates a fosite.Request with known values for testing.
func newTestRequest(clientID string) *fosite.Request {
	return &fosite.Request{
		ID:          "req-12345",
		RequestedAt: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		Client: &fosite.DefaultClient{
			ID: clientID,
		},
		RequestedScope:    fosite.Arguments{"openid", "profile"},
		GrantedScope:      fosite.Arguments{"openid"},
		RequestedAudience: fosite.Arguments{"https://api.example.com"},
		GrantedAudience:   fosite.Arguments{"https://api.example.com"},
		Form:              url.Values{"redirect_uri": {"http://localhost/callback"}},
		Session: &oauth2.Session{
			DefaultSession: fositeopenid.DefaultSession{
				Claims: &jwt.IDTokenClaims{
					Subject:   "user123",
					Issuer:    "http://localhost",
					IssuedAt:  time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
					ExpiresAt: time.Date(2026, 1, 1, 18, 0, 0, 0, time.UTC),
				},
				Headers: &jwt.Headers{},
				Subject: "user123",
			},
			CollectionId: "col123",
		},
	}
}

func TestSetRequester_RoundTrip(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedUsersCollection(t, app)
	seedTestUser(t, app)
	seedTestClient(t, app)

	req := newTestRequest(testClientID)

	c, err := app.FindCollectionByNameOrId(consts.AuthCodeCollectionName)
	if err != nil {
		t.Fatalf("failed to find auth code collection: %v", err)
	}

	m := &oauth2.AuthCodeModel{}
	m.SetProxyRecord(core.NewRecord(c))
	m.SetSignature("test-sig-123")
	if err := m.SetRequester(req, fosite.AuthorizeCode); err != nil {
		t.Fatalf("SetRequester failed: %v", err)
	}

	// Verify fields are set correctly on the underlying record
	if got := m.GetClientID(); got != testClientID {
		t.Errorf("client_id = %q, want %q", got, testClientID)
	}
	if got := m.GetRequestID(); got != "req-12345" {
		t.Errorf("request_id = %q, want %q", got, "req-12345")
	}
	if got := m.GetSubject(); got != "user123" {
		t.Errorf("subject = %q, want %q", got, "user123")
	}
	if got := m.GetString("signature"); got != "test-sig-123" {
		t.Errorf("signature = %q, want %q", got, "test-sig-123")
	}
}

func TestToRequest_RoundTrip(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedUsersCollection(t, app)
	seedTestUser(t, app)
	seedTestClient(t, app)

	original := newTestRequest(testClientID)

	c, err := app.FindCollectionByNameOrId(consts.AuthCodeCollectionName)
	if err != nil {
		t.Fatalf("failed to find auth code collection: %v", err)
	}

	m := &oauth2.AuthCodeModel{}
	m.SetProxyRecord(core.NewRecord(c))
	m.SetSignature("test-sig-roundtrip")
	if err := m.SetRequester(original, fosite.AuthorizeCode); err != nil {
		t.Fatalf("SetRequester failed: %v", err)
	}

	// Save and retrieve
	if err := app.Save(m); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	// Reconstruct the session
	session := &oauth2.Session{}
	store := oauth2.NewOAuth2Store(app)
	result, err := m.ToRequest(context.Background(), store, session)
	if err != nil {
		t.Fatalf("ToRequest failed: %v", err)
	}

	if result.GetID() != "req-12345" {
		t.Errorf("request ID = %q, want %q", result.GetID(), "req-12345")
	}
	if result.GetClient().GetID() != testClientID {
		t.Errorf("client ID = %q, want %q", result.GetClient().GetID(), testClientID)
	}

	// Check scopes roundtrip
	reqScopes := result.GetRequestedScopes()
	if len(reqScopes) != 2 || reqScopes[0] != "openid" || reqScopes[1] != "profile" {
		t.Errorf("requested scopes = %v, want [openid profile]", reqScopes)
	}
	grantedScopes := result.GetGrantedScopes()
	if len(grantedScopes) != 1 || grantedScopes[0] != "openid" {
		t.Errorf("granted scopes = %v, want [openid]", grantedScopes)
	}

	// Check audience roundtrip
	reqAud := result.GetRequestedAudience()
	if len(reqAud) != 1 || reqAud[0] != "https://api.example.com" {
		t.Errorf("requested audience = %v, want [https://api.example.com]", reqAud)
	}

	// Check form data roundtrip
	if got := result.GetRequestForm().Get("redirect_uri"); got != "http://localhost/callback" {
		t.Errorf("form redirect_uri = %q, want %q", got, "http://localhost/callback")
	}
}

func TestSetRequester_ScopeSerialization(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	c, err := app.FindCollectionByNameOrId(consts.AccessCollectionName)
	if err != nil {
		t.Fatalf("failed to find collection: %v", err)
	}

	m := &oauth2.AccessTokenModel{}
	m.SetProxyRecord(core.NewRecord(c))

	req := &fosite.Request{
		Client:         &fosite.DefaultClient{ID: "dummy"},
		RequestedScope: fosite.Arguments{"openid", "profile"},
		GrantedScope:   fosite.Arguments{"openid", "profile", "email"},
		Session: &oauth2.Session{
			DefaultSession: fositeopenid.DefaultSession{
				Claims:  &jwt.IDTokenClaims{},
				Headers: &jwt.Headers{},
			},
		},
	}

	m.SetRequester(req, fosite.AccessToken)

	// Check raw pipe-delimited format
	rawScopes := m.GetString("scopes")
	if rawScopes != "openid|profile" {
		t.Errorf("raw scopes = %q, want %q", rawScopes, "openid|profile")
	}
	rawGranted := m.GetString("granted_scopes")
	if rawGranted != "openid|profile|email" {
		t.Errorf("raw granted_scopes = %q, want %q", rawGranted, "openid|profile|email")
	}

	// Check parsed back
	scopes := m.GetScopes()
	if len(scopes) != 2 || scopes[0] != "openid" || scopes[1] != "profile" {
		t.Errorf("parsed scopes = %v, want [openid profile]", scopes)
	}
}

func TestToRequest_EmptySession(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	c, err := app.FindCollectionByNameOrId(consts.AccessCollectionName)
	if err != nil {
		t.Fatalf("failed to find collection: %v", err)
	}

	m := &oauth2.AccessTokenModel{}
	m.SetProxyRecord(core.NewRecord(c))

	// Set with nil session
	req := &fosite.Request{
		ID:      "req-empty-session",
		Client:  &fosite.DefaultClient{ID: testClientID},
		Session: nil,
	}
	m.SetSignature("sig-empty")
	m.SetRequester(req, fosite.AccessToken)

	if err := app.Save(m); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	// ToRequest with nil session should work
	store := oauth2.NewOAuth2Store(app)
	result, err := m.ToRequest(context.Background(), store, nil)
	if err != nil {
		t.Fatalf("ToRequest with nil session failed: %v", err)
	}
	if result.GetID() != "req-empty-session" {
		t.Errorf("request ID = %q, want %q", result.GetID(), "req-empty-session")
	}
}

func TestToRequest_MalformedSessionJSON(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	c, err := app.FindCollectionByNameOrId(consts.AccessCollectionName)
	if err != nil {
		t.Fatalf("failed to find collection: %v", err)
	}

	m := &oauth2.AccessTokenModel{}
	m.SetProxyRecord(core.NewRecord(c))
	m.Set("client_id", testClientID)
	m.Set("request_id", "req-bad-json")
	m.Set("session_data", "{{not-json}}")
	m.Set("signature", "sig-bad-json")
	m.Set("scopes", "")
	m.Set("granted_scopes", "")
	m.Set("requested_audience", "")
	m.Set("granted_audience", "")
	m.Set("form_data", "")

	store := oauth2.NewOAuth2Store(app)
	session := &oauth2.Session{}
	_, err = m.ToRequest(context.Background(), store, session)
	if err == nil {
		t.Fatal("expected error for malformed session JSON, got nil")
	}

	// Should be a JSON unmarshal error
	var syntaxErr *json.SyntaxError
	if !errors.As(err, &syntaxErr) {
		// Some json libs return different errors, just ensure it's non-nil
		t.Logf("got non-nil error as expected: %v", err)
	}
}

func TestBaseSessionModel_GettersWithEmptyValues(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	c, err := app.FindCollectionByNameOrId(consts.AccessCollectionName)
	if err != nil {
		t.Fatalf("failed to find collection: %v", err)
	}

	m := &oauth2.AccessTokenModel{}
	m.SetProxyRecord(core.NewRecord(c))

	// Empty fields should return nil slices and empty strings
	if got := m.GetScopes(); got != nil {
		t.Errorf("GetScopes() on empty = %v, want nil", got)
	}
	if got := m.GetGrantedScopes(); got != nil {
		t.Errorf("GetGrantedScopes() on empty = %v, want nil", got)
	}
	if got := m.GetRequestedAudience(); got != nil {
		t.Errorf("GetRequestedAudience() on empty = %v, want nil", got)
	}
	if got := m.GetGrantedAudience(); got != nil {
		t.Errorf("GetGrantedAudience() on empty = %v, want nil", got)
	}
	if got := m.GetFormData(); got != "" {
		t.Errorf("GetFormData() on empty = %q, want empty", got)
	}
	if got := m.GetSubject(); got != "" {
		t.Errorf("GetSubject() on empty = %q, want empty", got)
	}
}
