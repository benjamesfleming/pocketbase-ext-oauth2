package oauth2

import (
	"context"
	"testing"
	"time"

	oauth2 "github.com/benjamesfleming/pocketbase-ext-oauth2"
	"github.com/ory/fosite"
	fositeoauth2 "github.com/ory/fosite/handler/oauth2"
	fositeopenid "github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

func TestPocketBaseStrategyImplementsInterface(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	strategy := oauth2.NewPocketBaseStrategy(app, oauth2.GetOAuth2Config())
	if strategy == nil {
		t.Fatal("expected non-nil strategy")
	}
	if strategy.App == nil {
		t.Error("expected non-nil App")
	}
	if strategy.HMACSHAStrategy == nil {
		t.Error("expected non-nil HMACSHAStrategy")
	}

	// Compile-time interface check is in strategy.go, but test the var too
	var _ fositeoauth2.CoreStrategy = strategy
}

func makeStrategySession() *oauth2.Session {
	return &oauth2.Session{
		DefaultSession: fositeopenid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				RequestedAt: time.Now(),
				ExpiresAt:   time.Now().Add(time.Hour),
			},
			Headers: &jwt.Headers{},
		},
	}
}

func TestAccessTokenGenerate(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	user := seedTestUser(t, app)
	strategy := oauth2.NewPocketBaseStrategy(app, oauth2.GetOAuth2Config())

	session := &oauth2.Session{
		DefaultSession: fositeopenid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:   user.Id,
				ExpiresAt: time.Now().Add(time.Hour),
			},
			Headers: &jwt.Headers{},
			Subject: user.Id,
		},
		CollectionId: user.Collection().Id,
	}

	req := &fosite.Request{
		Client:  &fosite.DefaultClient{ID: "test"},
		Session: session,
	}

	token, sig, err := strategy.GenerateAccessToken(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty access token")
	}
	if sig == "" {
		t.Error("expected non-empty access token signature")
	}
}

func TestAccessTokenValidate(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	user := seedTestUser(t, app)
	strategy := oauth2.NewPocketBaseStrategy(app, oauth2.GetOAuth2Config())

	session := &oauth2.Session{
		DefaultSession: fositeopenid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:   user.Id,
				ExpiresAt: time.Now().Add(time.Hour),
			},
			Headers: &jwt.Headers{},
			Subject: user.Id,
		},
		CollectionId: user.Collection().Id,
	}

	req := &fosite.Request{
		Client:  &fosite.DefaultClient{ID: "test"},
		Session: session,
	}

	token, _, err := strategy.GenerateAccessToken(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Valid token should pass
	err = strategy.ValidateAccessToken(context.Background(), req, token)
	if err != nil {
		t.Errorf("ValidateAccessToken failed for valid token: %v", err)
	}
}

func TestAccessTokenValidate_Malformed(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	strategy := oauth2.NewPocketBaseStrategy(app, oauth2.GetOAuth2Config())
	req := &fosite.Request{
		Client:      &fosite.DefaultClient{ID: "test"},
		Session:     &oauth2.Session{},
		RequestedAt: time.Now(),
	}

	err := strategy.ValidateAccessToken(context.Background(), req, "not-a-valid-token")
	if err == nil {
		t.Error("expected error for malformed token, got nil")
	}
}

func TestAccessTokenSignature(t *testing.T) {
	strategy := &oauth2.PocketBaseStrategy{}
	// JWT has 3 segments separated by dots
	token := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature_part"
	sig := strategy.AccessTokenSignature(context.Background(), token)
	if sig != "signature_part" {
		t.Errorf("AccessTokenSignature = %q, want %q", sig, "signature_part")
	}
}

func TestAccessTokenSignature_Invalid(t *testing.T) {
	strategy := &oauth2.PocketBaseStrategy{}
	// Non-JWT token should return empty
	sig := strategy.AccessTokenSignature(context.Background(), "no-dots-here")
	if sig != "" {
		t.Errorf("AccessTokenSignature for non-JWT = %q, want empty", sig)
	}
}

func TestRefreshTokenGenerate(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	strategy := oauth2.NewPocketBaseStrategy(app, oauth2.GetOAuth2Config())
	session := makeStrategySession()

	req := &fosite.Request{
		Client:      &fosite.DefaultClient{ID: "test"},
		Session:     session,
		RequestedAt: time.Now(),
	}

	token, sig, err := strategy.GenerateRefreshToken(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty refresh token")
	}
	if sig == "" {
		t.Error("expected non-empty refresh signature")
	}
}

func TestRefreshTokenSignature(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	strategy := oauth2.NewPocketBaseStrategy(app, oauth2.GetOAuth2Config())
	session := makeStrategySession()

	req := &fosite.Request{
		Client:      &fosite.DefaultClient{ID: "test"},
		Session:     session,
		RequestedAt: time.Now(),
	}

	token, _, err := strategy.GenerateRefreshToken(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}

	sig := strategy.RefreshTokenSignature(context.Background(), token)
	if sig == "" {
		t.Error("expected non-empty refresh token signature")
	}
}

func TestAuthorizeCodeGenerate(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	strategy := oauth2.NewPocketBaseStrategy(app, oauth2.GetOAuth2Config())
	session := makeStrategySession()

	req := &fosite.Request{
		Client:      &fosite.DefaultClient{ID: "test"},
		Session:     session,
		RequestedAt: time.Now(),
	}

	code, sig, err := strategy.GenerateAuthorizeCode(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateAuthorizeCode failed: %v", err)
	}
	if code == "" {
		t.Error("expected non-empty authorize code")
	}
	if sig == "" {
		t.Error("expected non-empty authorize code signature")
	}
}

func TestAuthorizeCodeValidate(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	strategy := oauth2.NewPocketBaseStrategy(app, oauth2.GetOAuth2Config())
	session := makeStrategySession()

	req := &fosite.Request{
		Client:      &fosite.DefaultClient{ID: "test"},
		Session:     session,
		RequestedAt: time.Now(),
	}

	code, _, err := strategy.GenerateAuthorizeCode(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateAuthorizeCode failed: %v", err)
	}

	err = strategy.ValidateAuthorizeCode(context.Background(), req, code)
	if err != nil {
		t.Errorf("ValidateAuthorizeCode failed for valid code: [%T] %+v", err, err)
	}
}
