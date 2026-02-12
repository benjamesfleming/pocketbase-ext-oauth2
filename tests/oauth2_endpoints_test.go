package oauth2

import (
	"net/http"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

func TestTokenEndpoint_MissingGrantType(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "token - missing grant_type",
		Method: http.MethodPost,
		URL:    "/oauth2/token",
		Body:   strings.NewReader(""),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		ExpectedStatus:  400,
		ExpectedContent: []string{"invalid_request"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestTokenEndpoint_InvalidClientCredentials(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "token - invalid client credentials",
		Method: http.MethodPost,
		URL:    "/oauth2/token",
		Body:   strings.NewReader("grant_type=authorization_code&code=fakecode&client_id=bad-client&client_secret=bad-secret&redirect_uri=http://localhost/callback"),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		ExpectedStatus:  401,
		ExpectedContent: []string{"invalid_client"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			app := setupTestAppForScenario(t)
			return app
		},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedUsersCollection(t, app)
			seedTestUser(t, app)
			seedTestClient(t, app)
		},
	}
	scenario.Test(t)
}

func TestTokenEndpoint_InvalidCode(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "token - authorization_code grant with invalid code",
		Method: http.MethodPost,
		URL:    "/oauth2/token",
		Body: strings.NewReader(
			"grant_type=authorization_code&code=invalid-code&client_id=" + testClientID +
				"&client_secret=" + testClientSecret +
				"&redirect_uri=" + testRedirectURI,
		),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		ExpectedStatus:  401,
		ExpectedContent: []string{"invalid_client"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedUsersCollection(t, app)
			seedTestUser(t, app)
			seedTestClient(t, app)
		},
	}
	scenario.Test(t)
}

func TestRevokeEndpoint_MissingToken(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "revoke - missing token param",
		Method: http.MethodPost,
		URL:    "/oauth2/revoke",
		Body:   strings.NewReader(""),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		ExpectedStatus:  400,
		ExpectedContent: []string{"invalid_request"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestRevokeEndpoint_InvalidToken(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "revoke - invalid token",
		Method: http.MethodPost,
		URL:    "/oauth2/revoke",
		Body:   strings.NewReader("token=invalid-token-value"),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		ExpectedStatus:  400,
		ExpectedContent: []string{"invalid_request"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestIntrospectEndpoint_MissingToken(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "introspect - missing token param",
		Method: http.MethodPost,
		URL:    "/oauth2/introspect",
		Body:   strings.NewReader(""),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		ExpectedStatus:  400,
		ExpectedContent: []string{"invalid_request"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestIntrospectEndpoint_InvalidToken(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "introspect - expired/invalid token returns inactive",
		Method: http.MethodPost,
		URL:    "/oauth2/introspect",
		Body:   strings.NewReader("token=expired-or-invalid-token"),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		ExpectedStatus:  401,
		ExpectedContent: []string{"request_unauthorized"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestUserInfoEndpoint_NoAuth(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:           "userinfo - no auth returns 401 with WWW-Authenticate",
		Method:         http.MethodGet,
		URL:            "/oauth2/userinfo",
		ExpectedStatus: 401,
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			wwwAuth := res.Header.Get("WWW-Authenticate")
			if wwwAuth == "" {
				t.Error("expected WWW-Authenticate header to be set")
			}
			if !strings.Contains(wwwAuth, "Bearer") {
				t.Errorf("expected WWW-Authenticate to contain 'Bearer', got %q", wwwAuth)
			}
			if !strings.Contains(wwwAuth, "resource_metadata") {
				t.Errorf("expected WWW-Authenticate to contain 'resource_metadata', got %q", wwwAuth)
			}
		},
	}
	scenario.Test(t)
}

func TestUserInfoEndpoint_WithAuth(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:            "userinfo - authenticated returns user info",
		Method:          http.MethodGet,
		URL:             "/oauth2/userinfo",
		ExpectedStatus:  200,
		ExpectedContent: []string{`"sub"`},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedUsersCollection(t, app)
			seedTestUser(t, app)
		},
		Headers: map[string]string{
			// Token will be set dynamically but we need BeforeTestFunc to seed data first.
			// We'll use a different approach — set the token in AfterTestFunc or use a wrapper.
		},
	}

	// We need to generate the token after seeding, so we'll use a custom approach.
	// Override with a closure that captures the token.
	scenario.BeforeTestFunc = func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		seedUsersCollection(t, app)
		user := seedTestUser(t, app)
		token, err := user.NewAuthToken()
		if err != nil {
			t.Fatalf("failed to generate auth token: %v", err)
		}
		scenario.Headers = map[string]string{
			"Authorization": token,
		}
	}

	scenario.Test(t)
}

func TestRegisterEndpoint_ValidMetadata(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "register - valid client metadata (RFC 7591)",
		Method: http.MethodPost,
		URL:    "/oauth2/register",
		Body: strings.NewReader(`{
			"client_name": "New Dynamic Client",
			"redirect_uris": ["http://localhost:3000/callback"]
		}`),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		ExpectedStatus:  201,
		ExpectedContent: []string{`"client_id"`, `"client_secret"`},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestRegisterEndpoint_MissingRedirectURIs(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "register - missing redirect_uris",
		Method: http.MethodPost,
		URL:    "/oauth2/register",
		Body: strings.NewReader(`{
			"client_name": "Bad Client"
		}`),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		ExpectedStatus:  400,
		ExpectedContent: []string{"Redirect_uris is required"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestAuthEndpoint_UnauthenticatedRedirects(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:           "auth - unauthenticated redirects to login",
		Method:         http.MethodGet,
		URL:            "/oauth2/auth?response_type=code&client_id=" + testClientID + "&redirect_uri=" + testRedirectURI + "&scope=openid&state=teststate",
		ExpectedStatus: 307,
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedUsersCollection(t, app)
			seedTestClient(t, app)
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			location := res.Header.Get("Location")
			if location == "" {
				t.Error("expected Location header for redirect")
			}
			if !strings.Contains(location, "oauth2/login") {
				t.Errorf("expected redirect to contain 'oauth2/login', got %q", location)
			}
		},
	}
	scenario.Test(t)
}

func TestAuthEndpoint_MissingClientID(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:            "auth - missing client_id",
		Method:          http.MethodGet,
		URL:             "/oauth2/auth?response_type=code&redirect_uri=" + testRedirectURI + "&scope=openid",
		ExpectedStatus:  401,
		ExpectedContent: []string{""},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestLoginUI_Served(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:            "login UI - serves HTML",
		Method:          http.MethodGet,
		URL:             "/oauth2/login",
		ExpectedStatus:  200,
		ExpectedContent: []string{"<!doctype html>"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}
