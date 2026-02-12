# PocketBase OAuth2 Provider Plugin

Turn any [PocketBase](https://pocketbase.io) instance into a fully compliant **OAuth 2.0 Authorization Server** with OpenID Connect support. Built on top of [ory/fosite](https://github.com/ory/fosite), the widely adopted, security-first OAuth 2.0 SDK for Go.

### Features

- **Authorization Code Grant** with PKCE enforcement
- **OpenID Connect** (Implicit, Hybrid, and Refresh flows)
- **OpenID Connect Discovery** ([OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html))
- **Token Revocation** ([RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009))
- **Token Introspection** ([RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662))
- **Dynamic Client Registration** ([RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)) — optional
- **Authorization Server Metadata** ([RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414))
- **Protected Resource Metadata** ([RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728))
- **JWK Public Key Discovery** ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517))


### Requirements

- Go 1.25+
- PocketBase v0.36+

### Installation

```bash
go get github.com/benjamesfleming/pocketbase-ext-oauth2
```

### Quick Start

```go
package main

import (
	"log"
	"os"
	"time"

	oauth2 "github.com/benjamesfleming/pocketbase-ext-oauth2"
	"github.com/pocketbase/pocketbase"
)

func main() {
	app := pocketbase.New()
	app.RootCmd.ParseFlags(os.Args[1:])

	oauth2.MustRegister(app, &oauth2.Config{
		BaseConfig: &oauth2.BaseConfig{
			AccessTokenLifespan:   time.Hour,
			AuthorizeCodeLifespan: time.Minute * 15,
			EnforcePKCE:           true,
			RefreshTokenScopes:    []string{}, // allow all scopes for refresh tokens
		},
		PathPrefix:                             "/oauth2",
		UserCollection:                         "users",
		EnableRFC7591DynamicClientRegistration: true,
		EnableRFC9728ProtectedResourceMetadata: true,
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
```

The plugin will automatically run its database migrations on first boot, creating the required system collections.

### Endpoints

All OAuth2 endpoints are served under the configured `PathPrefix` (default `/oauth2`).

| Method | Path | Description |
|---|---|---|
| GET/POST | `/oauth2/auth` | Authorization endpoint |
| GET/POST | `/oauth2/token` | Token endpoint |
| POST | `/oauth2/revoke` | Token revocation |
| POST | `/oauth2/introspect` | Token introspection |
| GET | `/oauth2/userinfo` | OpenID Connect UserInfo |
| POST | `/oauth2/register` | Dynamic client registration (RFC 7591, optional) |
| GET | `/oauth2/login` | Built-in login/consent UI |

#### Discovery & Metadata

| Method | Path | Description |
|---|---|---|
| GET | `/.well-known/oauth-authorization-server` | Authorization Server Metadata (RFC 8414) |
| GET | `/.well-known/openid-configuration` | OpenID Connect Discovery |
| GET | `/.well-known/jwks.json` | JSON Web Key Set |
| GET | `/.well-known/oauth-protected-resource/{resource}` | Protected Resource Metadata (RFC 9728, optional) |

### How It Works

#### Access Tokens

Access tokens issued by this plugin are **native PocketBase auth tokens**. This means any PocketBase endpoint or middleware that accepts a standard auth token will work out of the box with OAuth2-issued access tokens — no additional configuration needed.

#### Key Management

On first bootstrap the plugin generates an **Ed25519** signing key pair and a **global HMAC secret**, both stored in PocketBase's internal `_params` table. These persist across restarts and are used for signing ID tokens, authorization codes, and refresh tokens respectively.

#### Session Storage

OAuth2 session data (authorization codes, access tokens, refresh tokens, PKCE challenges, and OpenID Connect sessions) is stored in dedicated system collections that are automatically created by the plugin's migration. A cron job runs every hour to clean up expired sessions.

The plugin creates the following **system** collections automatically:

| Collection | Purpose |
|---|---|
| `_oauth2Clients` | Registered OAuth2 client applications |
| `_oauth2AuthCode` | Authorization code sessions |
| `_oauth2Access` | Access token sessions |
| `_oauth2Refresh` | Refresh token sessions |
| `_oauth2PKCE` | PKCE challenge data |
| `_oauth2OpenID` | OpenID Connect sessions |
| `_oauth2JTI` | JWT Token Identifiers (for replay protection) |

#### Custom UserInfo Claims

By default the `/userinfo` endpoint attempt a best-effort extraction of default OpenID claims from the authenticated user's PocketBase auth record. If you have non-standard column names or other requirements, you can customize the claim response by implementing the `UserInfoClaimStrategy` interface and returning any struct or map — it will be JSON-encoded in the `/userinfo` response.

```go
type MyCustomClaims struct {
    Sub   string `json:"sub"`
    Email string `json:"email"`
}

type MyClaimStrategy struct{}

func (s *MyClaimStrategy) GetUserInfoClaims(e *core.RequestEvent, scopes []string) (interface{}, error) {
	// Return any struct or map — it will be JSON-encoded
	// in the /userinfo response.
	return &MyCustomClaims{
        Sub:   e.Auth.ID,
        Email: e.Auth.GetString("email"),
	}, nil
}

oauth2.MustRegister(app, &oauth2.Config{
	// ...
	UserInfoClaimStrategy: &MyClaimStrategy{},
})
```

#### Protected Resource Metadata (RFC 9728)

You can register additional protected resources so clients can discover your resource server metadata:

```go
oauth2.RegisterProtectedResourceMetadata(
	&rfc9728.ProtectedResourceMetadata{
		Resource:               "https://api.example.com/data",
		AuthorizationServers:   []string{"https://auth.example.com"},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{"read", "write"},
	},
)
```

The metadata will be available at `/.well-known/oauth-protected-resource/data`.

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.