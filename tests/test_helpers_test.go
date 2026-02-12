package oauth2

import (
	"context"
	"os"
	"testing"

	oauth2 "github.com/benjamesfleming/pocketbase-ext-oauth2"
	"github.com/benjamesfleming/pocketbase-ext-oauth2/consts"
	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

const (
	testClientID          = "test-client-id"
	testClientSecret      = "test-client-secret"
	testClientName        = "Test Client"
	testRedirectURI       = "http://localhost:8090/callback"
	testUserEmail         = "testuser@example.com"
	testUserPassword      = "Test1234!"
	testUserCollection    = "users"
	testSuperuserEmail    = "admin@example.com"
	testSuperuserPassword = "Admin1234!"
)

// setupTestApp creates a fresh TestApp with the OAuth2 plugin registered.
// The caller should defer testApp.Cleanup().
func setupTestApp(t testing.TB) *tests.TestApp {
	t.Helper()
	oauth2.ResetGlobalStateForTests()
	tempDir, err := os.MkdirTemp("", "pb_oauth2_test_*")
	if err != nil {
		t.Fatal(err)
	}
	testApp, err := tests.NewTestApp(tempDir)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatal(err)
	}
	err = oauth2.Register(testApp, &oauth2.Config{
		BaseConfig: &fosite.Config{
			ScopeStrategy:            fosite.ExactScopeStrategy,
			AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		},
		PathPrefix:                             "/oauth2",
		UserCollection:                         testUserCollection,
		EnableRFC7591DynamicClientRegistration: true,
		EnableRFC9728ProtectedResourceMetadata: true,
	})
	if err != nil {
		testApp.Cleanup()
		t.Fatal(err)
	}
	return testApp
}

// setupTestAppForScenario is the TestAppFactory variant for ApiScenario tests.
func setupTestAppForScenario(t testing.TB) *tests.TestApp {
	t.Helper()
	return setupTestApp(t)
}

// seedUsersCollection creates a "users" auth collection if it doesn't exist.
func seedUsersCollection(t testing.TB, app core.App) *core.Collection {
	t.Helper()
	c, err := app.FindCollectionByNameOrId(testUserCollection)
	if err == nil {
		return c
	}
	c = core.NewAuthCollection(testUserCollection)
	c.Fields.Add(
		&core.TextField{Name: "name", Max: 100},
	)
	if err := app.Save(c); err != nil {
		t.Fatalf("failed to create users collection: %v", err)
	}
	return c
}

// seedTestUser creates a test user in the users auth collection.
func seedTestUser(t testing.TB, app core.App) *core.Record {
	t.Helper()
	c := seedUsersCollection(t, app)
	record := core.NewRecord(c)
	record.SetEmail(testUserEmail)
	record.SetPassword(testUserPassword)
	record.Set("name", "Test User")
	record.SetVerified(true)
	if err := app.Save(record); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return record
}

// seedTestClient creates a test OAuth2 client in the _oauth2Clients collection.
func seedTestClient(t testing.TB, app core.App) *core.Record {
	t.Helper()
	c, err := app.FindCollectionByNameOrId(consts.ClientCollectionName)
	if err != nil {
		t.Fatalf("failed to find clients collection: %v", err)
	}
	h, _ := oauth2.GetOAuth2Config().GetSecretsHasher(context.Background()).Hash(
		context.Background(),
		[]byte(testClientSecret),
	)
	record := core.NewRecord(c)
	record.Set("client_id", testClientID)
	record.Set("client_name", testClientName)
	record.Set("client_secret", string(h))
	record.Set("client_secret_expires_at", 0)
	record.Set("redirect_uris", []string{testRedirectURI})
	record.Set("grant_types", []string{"authorization_code", "refresh_token"})
	record.Set("response_types", []string{"code"})
	record.Set("scope", "openid profile email")
	record.Set("audience", []string{})
	record.Set("owner", "")
	record.Set("policy_uri", "")
	record.Set("tos_uri", "")
	record.Set("client_uri", "")
	record.Set("logo_uri", "")
	record.Set("contacts", []string{})
	record.Set("allowed_cors_origins", []string{})
	record.Set("subject_type", "public")
	record.Set("sector_identifier_uri", "")
	record.Set("jwks_uri", "")
	record.Set("jwks", nil)
	record.Set("request_uris", []string{})
	record.Set("token_endpoint_auth_method", "client_secret_post")
	record.Set("token_endpoint_auth_signing_alg", "")
	record.Set("request_object_signing_alg", "")
	record.Set("userinfo_signed_response_alg", "")
	record.Set("metadata", nil)
	record.Set("access_token_strategy", "opaque")
	if err := app.SaveNoValidate(record); err != nil {
		t.Fatalf("failed to create test client: %v", err)
	}
	return record
}

// generateTestUserToken generates a PocketBase auth token for the test user.
func generateTestUserToken(t testing.TB, app core.App) string {
	t.Helper()
	record, err := app.FindAuthRecordByEmail(testUserCollection, testUserEmail)
	if err != nil {
		t.Fatalf("failed to find test user: %v", err)
	}
	token, err := record.NewAuthToken()
	if err != nil {
		t.Fatalf("failed to generate user token: %v", err)
	}
	return token
}
