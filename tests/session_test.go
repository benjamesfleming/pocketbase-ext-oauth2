package oauth2

import (
	"testing"
	"time"

	oauth2 "github.com/benjamesfleming/pocketbase-ext-oauth2"
	fositeopenid "github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

func TestNewSession(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedUsersCollection(t, app)
	user := seedTestUser(t, app)

	session := oauth2.NewSession(app, user.Id, user.Collection().Id)
	if session == nil {
		t.Fatal("expected non-nil session")
	}
	if session.CollectionId != user.Collection().Id {
		t.Errorf("CollectionId = %q, want %q", session.CollectionId, user.Collection().Id)
	}
	if session.Subject != user.Id {
		t.Errorf("Subject = %q, want %q", session.Subject, user.Id)
	}
	if session.Claims == nil {
		t.Fatal("expected non-nil Claims")
	}
	if session.Claims.Subject != user.Id {
		t.Errorf("Claims.Subject = %q, want %q", session.Claims.Subject, user.Id)
	}
	if session.Claims.Issuer != app.Settings().Meta.AppURL {
		t.Errorf("Claims.Issuer = %q, want %q", session.Claims.Issuer, app.Settings().Meta.AppURL)
	}
	if session.Headers == nil {
		t.Fatal("expected non-nil Headers")
	}
}

func TestSessionGetJWTClaims(t *testing.T) {
	s := &oauth2.Session{
		DefaultSession: fositeopenid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:   "user123",
				Issuer:    "http://localhost",
				IssuedAt:  time.Now(),
				ExpiresAt: time.Now().Add(time.Hour),
			},
			Headers: &jwt.Headers{},
			Subject: "user123",
		},
		CollectionId: "col_abc",
	}

	claims := s.GetJWTClaims()
	if claims == nil {
		t.Fatal("expected non-nil claims")
	}

	mapClaims := claims.ToMapClaims()
	collectionClaim, ok := mapClaims["collection"]
	if !ok {
		t.Fatal("expected 'collection' claim to be present")
	}
	if collectionClaim != "col_abc" {
		t.Errorf("collection claim = %v, want %q", collectionClaim, "col_abc")
	}
}

func TestSessionClone(t *testing.T) {
	original := &oauth2.Session{
		DefaultSession: fositeopenid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:   "user123",
				Issuer:    "http://localhost",
				IssuedAt:  time.Now(),
				ExpiresAt: time.Now().Add(time.Hour),
			},
			Headers: &jwt.Headers{},
			Subject: "user123",
		},
		CollectionId: "col_abc",
	}

	cloned := original.Clone()
	if cloned == nil {
		t.Fatal("expected non-nil cloned session")
	}

	clonedSession, ok := cloned.(*oauth2.Session)
	if !ok {
		t.Fatalf("expected clone to be *Session, got %T", cloned)
	}

	// Verify values match
	if clonedSession.CollectionId != original.CollectionId {
		t.Errorf("cloned CollectionId = %q, want %q", clonedSession.CollectionId, original.CollectionId)
	}
	if clonedSession.Subject != original.Subject {
		t.Errorf("cloned Subject = %q, want %q", clonedSession.Subject, original.Subject)
	}

	// Verify deep copy — mutating clone shouldn't affect original
	clonedSession.CollectionId = "modified"
	clonedSession.Subject = "modified"
	if original.CollectionId == "modified" {
		t.Error("modifying clone affected original CollectionId")
	}
	if original.Subject == "modified" {
		t.Error("modifying clone affected original Subject")
	}
}

func TestSessionClone_NilReceiver(t *testing.T) {
	var s *oauth2.Session
	cloned := s.Clone()
	if cloned != nil {
		t.Errorf("expected nil clone from nil session, got %v", cloned)
	}
}
