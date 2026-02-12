package oauth2

import (
	"context"
	"testing"
	"time"

	oauth2 "github.com/benjamesfleming/pocketbase-ext-oauth2"
	"github.com/ory/fosite"
	fositeopenid "github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

func TestStoreGetClient(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	store := oauth2.NewOAuth2Store(app)
	client, err := store.GetClient(context.Background(), testClientID)
	if err != nil {
		t.Fatalf("GetClient failed: %v", err)
	}
	if client.GetID() != testClientID {
		t.Errorf("client ID = %q, want %q", client.GetID(), testClientID)
	}
}

func TestStoreGetClient_NotFound(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	store := oauth2.NewOAuth2Store(app)
	_, err := store.GetClient(context.Background(), "nonexistent-client")
	if err == nil {
		t.Fatal("expected error for nonexistent client, got nil")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("expected fosite.ErrNotFound, got %v", err)
	}
}

func TestStoreAuthorizeCodeSession(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()

	session := &oauth2.Session{
		DefaultSession: fositeopenid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:   "user123",
				ExpiresAt: time.Now().Add(time.Hour),
			},
			Headers: &jwt.Headers{},
			Subject: "user123",
		},
		CollectionId: "col123",
	}

	req := &fosite.Request{
		ID:             "authcode-req-1",
		Client:         &fosite.DefaultClient{ID: testClientID},
		RequestedScope: fosite.Arguments{"openid"},
		GrantedScope:   fosite.Arguments{"openid"},
		Session:        session,
	}

	// Create
	err := store.CreateAuthorizeCodeSession(ctx, "authcode-sig-1", req)
	if err != nil {
		t.Fatalf("CreateAuthorizeCodeSession failed: %v", err)
	}

	// Get
	got, err := store.GetAuthorizeCodeSession(ctx, "authcode-sig-1", &oauth2.Session{})
	if err != nil {
		t.Fatalf("GetAuthorizeCodeSession failed: %v", err)
	}
	if got.GetID() != "authcode-req-1" {
		t.Errorf("request ID = %q, want %q", got.GetID(), "authcode-req-1")
	}

	// Invalidate
	err = store.InvalidateAuthorizeCodeSession(ctx, "authcode-sig-1")
	if err != nil {
		t.Fatalf("InvalidateAuthorizeCodeSession failed: %v", err)
	}

	// Get after invalidation should fail
	_, err = store.GetAuthorizeCodeSession(ctx, "authcode-sig-1", &oauth2.Session{})
	if err == nil {
		t.Error("expected error after invalidation, got nil")
	}
}

func TestStoreAccessTokenSession(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()

	session := &oauth2.Session{
		DefaultSession: fositeopenid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:   "user456",
				ExpiresAt: time.Now().Add(time.Hour),
			},
			Headers: &jwt.Headers{},
			Subject: "user456",
		},
	}

	req := &fosite.Request{
		ID:             "access-req-1",
		Client:         &fosite.DefaultClient{ID: testClientID},
		RequestedScope: fosite.Arguments{"openid", "profile"},
		GrantedScope:   fosite.Arguments{"openid"},
		Session:        session,
	}

	// Create
	err := store.CreateAccessTokenSession(ctx, "access-sig-1", req)
	if err != nil {
		t.Fatalf("CreateAccessTokenSession failed: %v", err)
	}

	// Get
	got, err := store.GetAccessTokenSession(ctx, "access-sig-1", &oauth2.Session{})
	if err != nil {
		t.Fatalf("GetAccessTokenSession failed: %v", err)
	}
	if got.GetID() != "access-req-1" {
		t.Errorf("request ID = %q, want %q", got.GetID(), "access-req-1")
	}

	// Delete
	err = store.DeleteAccessTokenSession(ctx, "access-sig-1")
	if err != nil {
		t.Fatalf("DeleteAccessTokenSession failed: %v", err)
	}

	// Get after delete should fail
	_, err = store.GetAccessTokenSession(ctx, "access-sig-1", &oauth2.Session{})
	if err == nil {
		t.Error("expected error after deletion, got nil")
	}
}

func TestStoreRefreshTokenSession(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()

	session := &oauth2.Session{
		DefaultSession: fositeopenid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:   "user789",
				ExpiresAt: time.Now().Add(time.Hour * 24),
			},
			Headers: &jwt.Headers{},
			Subject: "user789",
		},
	}

	req := &fosite.Request{
		ID:             "refresh-req-1",
		Client:         &fosite.DefaultClient{ID: testClientID},
		RequestedScope: fosite.Arguments{"openid"},
		GrantedScope:   fosite.Arguments{"openid"},
		Session:        session,
	}

	// Create
	err := store.CreateRefreshTokenSession(ctx, "refresh-sig-1", "access-sig-ref-1", req)
	if err != nil {
		t.Fatalf("CreateRefreshTokenSession failed: %v", err)
	}

	// Get
	got, err := store.GetRefreshTokenSession(ctx, "refresh-sig-1", &oauth2.Session{})
	if err != nil {
		t.Fatalf("GetRefreshTokenSession failed: %v", err)
	}
	if got.GetID() != "refresh-req-1" {
		t.Errorf("request ID = %q, want %q", got.GetID(), "refresh-req-1")
	}

	// Delete
	err = store.DeleteRefreshTokenSession(ctx, "refresh-sig-1")
	if err != nil {
		t.Fatalf("DeleteRefreshTokenSession failed: %v", err)
	}

	_, err = store.GetRefreshTokenSession(ctx, "refresh-sig-1", &oauth2.Session{})
	if err == nil {
		t.Error("expected error after deletion, got nil")
	}
}

func TestStoreRevokeTokens(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()

	session := &oauth2.Session{
		DefaultSession: fositeopenid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:   "user-revoke",
				ExpiresAt: time.Now().Add(time.Hour),
			},
			Headers: &jwt.Headers{},
			Subject: "user-revoke",
		},
	}

	reqID := "revoke-req-1"

	// Create access and refresh tokens with the same request ID
	accessReq := &fosite.Request{
		ID: reqID, Client: &fosite.DefaultClient{ID: testClientID},
		RequestedScope: fosite.Arguments{"openid"}, GrantedScope: fosite.Arguments{"openid"},
		Session: session,
	}
	refreshReq := &fosite.Request{
		ID: reqID, Client: &fosite.DefaultClient{ID: testClientID},
		RequestedScope: fosite.Arguments{"openid"}, GrantedScope: fosite.Arguments{"openid"},
		Session: session,
	}

	store.CreateAccessTokenSession(ctx, "access-sig-revoke", accessReq)
	store.CreateRefreshTokenSession(ctx, "refresh-sig-revoke", "access-sig-revoke", refreshReq)

	// Revoke access token by request ID
	err := store.RevokeAccessToken(ctx, reqID)
	if err != nil {
		t.Fatalf("RevokeAccessToken failed: %v", err)
	}

	_, err = store.GetAccessTokenSession(ctx, "access-sig-revoke", &oauth2.Session{})
	if err == nil {
		t.Error("expected error after access token revocation")
	}

	// Revoke refresh token by request ID
	err = store.RevokeRefreshToken(ctx, reqID)
	if err != nil {
		t.Fatalf("RevokeRefreshToken failed: %v", err)
	}

	_, err = store.GetRefreshTokenSession(ctx, "refresh-sig-revoke", &oauth2.Session{})
	if err == nil {
		t.Error("expected error after refresh token revocation")
	}
}

func TestStorePKCESession(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()

	session := &oauth2.Session{
		DefaultSession: fositeopenid.DefaultSession{
			Claims:  &jwt.IDTokenClaims{},
			Headers: &jwt.Headers{},
		},
	}

	req := &fosite.Request{
		ID:      "pkce-req-1",
		Client:  &fosite.DefaultClient{ID: testClientID},
		Session: session,
	}

	// Create
	err := store.CreatePKCERequestSession(ctx, "pkce-sig-1", req)
	if err != nil {
		t.Fatalf("CreatePKCERequestSession failed: %v", err)
	}

	// Get
	got, err := store.GetPKCERequestSession(ctx, "pkce-sig-1", &oauth2.Session{})
	if err != nil {
		t.Fatalf("GetPKCERequestSession failed: %v", err)
	}
	if got.GetID() != "pkce-req-1" {
		t.Errorf("request ID = %q, want %q", got.GetID(), "pkce-req-1")
	}

	// Delete
	err = store.DeletePKCERequestSession(ctx, "pkce-sig-1")
	if err != nil {
		t.Fatalf("DeletePKCERequestSession failed: %v", err)
	}

	_, err = store.GetPKCERequestSession(ctx, "pkce-sig-1", &oauth2.Session{})
	if err == nil {
		t.Error("expected error after PKCE deletion")
	}
}

func TestStoreOpenIDConnectSession(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()

	session := &oauth2.Session{
		DefaultSession: fositeopenid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:   "oidc-user",
				ExpiresAt: time.Now().Add(time.Hour),
			},
			Headers: &jwt.Headers{},
			Subject: "oidc-user",
		},
	}

	req := &fosite.Request{
		ID:             "oidc-req-1",
		Client:         &fosite.DefaultClient{ID: testClientID},
		RequestedScope: fosite.Arguments{"openid"},
		GrantedScope:   fosite.Arguments{"openid"},
		Session:        session,
	}

	// Create
	err := store.CreateOpenIDConnectSession(ctx, "oidc-sig-1", req)
	if err != nil {
		t.Fatalf("CreateOpenIDConnectSession failed: %v", err)
	}

	// Get
	got, err := store.GetOpenIDConnectSession(ctx, "oidc-sig-1", req)
	if err != nil {
		t.Fatalf("GetOpenIDConnectSession failed: %v", err)
	}
	if got.GetID() != "oidc-req-1" {
		t.Errorf("request ID = %q, want %q", got.GetID(), "oidc-req-1")
	}

	// Delete
	err = store.DeleteOpenIDConnectSession(ctx, "oidc-sig-1")
	if err != nil {
		t.Fatalf("DeleteOpenIDConnectSession failed: %v", err)
	}
}

func TestStoreOpenIDConnectSession_NotFound(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()

	req := &fosite.Request{
		Client:  &fosite.DefaultClient{ID: testClientID},
		Session: &oauth2.Session{},
	}

	_, err := store.GetOpenIDConnectSession(ctx, "nonexistent", req)
	if err == nil {
		t.Error("expected error for nonexistent OpenID session")
	}
}

func TestStoreClientAssertionJTI(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()

	// Initially should be valid (not known)
	err := store.ClientAssertionJWTValid(ctx, "test-jti-1")
	if err != nil {
		t.Fatalf("expected no error for unknown JTI, got: %v", err)
	}

	// Set the JTI
	err = store.SetClientAssertionJWT(ctx, "test-jti-1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("SetClientAssertionJWT failed: %v", err)
	}

	// Now it should be known
	err = store.ClientAssertionJWTValid(ctx, "test-jti-1")
	if err == nil {
		t.Error("expected error for known JTI, got nil")
	}
	if err != fosite.ErrJTIKnown {
		t.Errorf("expected fosite.ErrJTIKnown, got: %v", err)
	}
}

func TestStoreRotateRefreshToken(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()

	session := &oauth2.Session{
		DefaultSession: fositeopenid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:   "rotate-user",
				ExpiresAt: time.Now().Add(time.Hour),
			},
			Headers: &jwt.Headers{},
			Subject: "rotate-user",
		},
	}

	reqID := "rotate-req-1"

	accessReq := &fosite.Request{
		ID: reqID, Client: &fosite.DefaultClient{ID: testClientID},
		RequestedScope: fosite.Arguments{"openid"}, GrantedScope: fosite.Arguments{"openid"},
		Session: session,
	}
	refreshReq := &fosite.Request{
		ID: reqID, Client: &fosite.DefaultClient{ID: testClientID},
		RequestedScope: fosite.Arguments{"openid"}, GrantedScope: fosite.Arguments{"openid"},
		Session: session,
	}

	store.CreateAccessTokenSession(ctx, "rotate-access-sig", accessReq)
	store.CreateRefreshTokenSession(ctx, "rotate-refresh-sig", "rotate-access-sig", refreshReq)

	// Rotate: deletes old refresh token + old access token by request ID
	err := store.RotateRefreshToken(ctx, reqID, "rotate-refresh-sig")
	if err != nil {
		t.Fatalf("RotateRefreshToken failed: %v", err)
	}

	// Old refresh token should be gone
	_, err = store.GetRefreshTokenSession(ctx, "rotate-refresh-sig", &oauth2.Session{})
	if err == nil {
		t.Error("expected old refresh token to be deleted after rotation")
	}

	// Old access token should also be gone
	_, err = store.GetAccessTokenSession(ctx, "rotate-access-sig", &oauth2.Session{})
	if err == nil {
		t.Error("expected old access token to be deleted after rotation")
	}
}
