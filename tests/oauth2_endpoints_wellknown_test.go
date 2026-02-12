package oauth2

import (
	"net/http"
	"testing"

	"github.com/pocketbase/pocketbase/tests"
)

func TestWellKnown_OAuthAuthorizationServer(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:           "well-known oauth-authorization-server metadata",
		Method:         http.MethodGet,
		URL:            "/.well-known/oauth-authorization-server",
		ExpectedStatus: 200,
		ExpectedContent: []string{
			`"issuer"`,
			`"authorization_endpoint"`,
			`"token_endpoint"`,
			`"response_types_supported"`,
		},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			ct := res.Header.Get("Content-Type")
			if ct != "application/json" {
				t.Errorf("Content-Type = %q, want %q", ct, "application/json")
			}
			cors := res.Header.Get("Access-Control-Allow-Origin")
			if cors != "*" {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", cors, "*")
			}
		},
	}
	scenario.Test(t)
}

func TestWellKnown_OpenIDConfiguration(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:           "well-known openid-configuration",
		Method:         http.MethodGet,
		URL:            "/.well-known/openid-configuration",
		ExpectedStatus: 200,
		ExpectedContent: []string{
			`"issuer"`,
			`"authorization_endpoint"`,
			`"token_endpoint"`,
			`"userinfo_endpoint"`,
			`"jwks_uri"`,
		},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestWellKnown_JWKS(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:           "well-known jwks.json",
		Method:         http.MethodGet,
		URL:            "/.well-known/jwks.json",
		ExpectedStatus: 200,
		ExpectedContent: []string{
			`"keys"`,
		},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			ct := res.Header.Get("Content-Type")
			if ct != "application/json" {
				t.Errorf("Content-Type = %q, want %q", ct, "application/json")
			}
		},
	}
	scenario.Test(t)
}

func TestWellKnown_OAuthAuthorizationServer_CORS_Preflight(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:           "well-known CORS preflight",
		Method:         http.MethodOptions,
		URL:            "/.well-known/oauth-authorization-server",
		ExpectedStatus: 204,
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			if got := res.Header.Get("Access-Control-Allow-Methods"); got != "GET, OPTIONS" {
				t.Errorf("Access-Control-Allow-Methods = %q, want %q", got, "GET, OPTIONS")
			}
		},
	}
	scenario.Test(t)
}

func TestWellKnown_OAuthAuthorizationServer_MethodNotAllowed(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:            "well-known POST not allowed",
		Method:          http.MethodPost,
		URL:             "/.well-known/oauth-authorization-server",
		ExpectedStatus:  405,
		ExpectedContent: []string{"Method Not Allowed"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestWellKnown_ProtectedResource_NotFound(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:            "well-known protected resource - unknown resource",
		Method:          http.MethodGet,
		URL:             "/.well-known/oauth-protected-resource/nonexistent",
		ExpectedStatus:  404,
		ExpectedContent: []string{""},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}
