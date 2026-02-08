package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/token/jwt"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/plugins/oauth2/consts"
	_ "github.com/pocketbase/pocketbase/plugins/oauth2/migrations"
	"github.com/pocketbase/pocketbase/plugins/oauth2/openid"
	"github.com/pocketbase/pocketbase/plugins/oauth2/rfc8414"
	"github.com/pocketbase/pocketbase/plugins/oauth2/rfc9728"
	"github.com/pocketbase/pocketbase/tools/router"
)

type BaseConfig = fosite.Config

type Config struct {
	*BaseConfig

	PathPrefix                             string
	DefaultUserCollection                  string
	EnableRFC7591DynamicClientRegistration bool
	EnableRFC9728ProtectedResourceMetadata bool
}

var oauth2 fosite.OAuth2Provider
var oauth2GlobalCfg *Config
var oauth2GlobalStore *OAuth2Store
var oauth2ProtectedResourceMetadata = map[string]*rfc9728.ProtectedResourceMetadata{}
var oauth2ProtectedResourceMetadataMu = &sync.RWMutex{}

func GetOAuth2Config() *Config {
	if oauth2GlobalCfg == nil {
		panic("[Plugin/OAuth2] GetOAuth2Config: OAuth2 config is not initialized. You MUST call Register() before using this package.")
	}
	return oauth2GlobalCfg
}

func GetOAuth2Store() *OAuth2Store {
	if oauth2GlobalStore == nil {
		panic("[Plugin/OAuth2] GetOAuth2Store: OAuth2 store is not initialized. You MUST call Register() before using this package.")
	}
	return oauth2GlobalStore
}

//

func MustRegister(app core.App, config *Config) {
	if err := Register(app, config); err != nil {
		panic(fmt.Sprintf("[Plugin/OAuth2] Failed to register OAuth2 plugin: %v", err))
	}
}

func Register(app core.App, config *Config) error {
	// Load or generate the private key
	if err := loadPrivateKeyFromAppStorage(app); err != nil {
		return fmt.Errorf("Failed to load or generate private key: %w", err)
	}
	// Create the OAuth2 config
	oauth2GlobalCfg = config
	if oauth2GlobalCfg.GlobalSecret == nil {
		return fmt.Errorf("Invalid Config: GlobalSecret is required for OAuth2 config")
	}
	// Create the OAuth2 store
	oauth2GlobalStore = NewOAuth2Store(app)
	// Create the OAuth2 provider
	oauth2 = compose.Compose(
		oauth2GlobalCfg.BaseConfig,
		oauth2GlobalStore,
		compose.CommonStrategy{
			CoreStrategy: NewPocketBaseStrategy(app, oauth2GlobalCfg),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(
				func(ctx context.Context) (interface{}, error) {
					return oauth2PrivateKey, nil
				},
				oauth2GlobalCfg,
			),
		},

		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2PKCEFactory,

		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectImplicitFactory,
		compose.OpenIDConnectHybridFactory,
		compose.OpenIDConnectRefreshFactory,
	)

	// Attach HTTP handlers

	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		// route handlers
		bindOAuth2Handlers(oauth2GlobalCfg, se.Router)
		bindOAuth2WellKnownHandlers(
			&openid.OpenIDProviderMetadata{
				AuthorizationServerMetadata: rfc8414.AuthorizationServerMetadata{
					Issuer:                 app.Settings().Meta.AppURL,
					AuthzEndpoint:          app.Settings().Meta.AppURL + config.PathPrefix + "/auth",
					TokenEndpoint:          app.Settings().Meta.AppURL + config.PathPrefix + "/token",
					RegistrationEndpoint:   app.Settings().Meta.AppURL + config.PathPrefix + "/register",
					ResponseTypesSupported: []string{"code", "id_token", "id_token token"},
				},
				UserInfoEndpoint: app.Settings().Meta.AppURL + config.PathPrefix + "/userinfo",
				JwksURI:          app.Settings().Meta.AppURL + "/.well-known/openid-configuration/jwks",
			},
		)(oauth2GlobalCfg, se.Router)
		return se.Next()
	})

	// Attach event listeners

	app.OnRecordCreate(consts.ClientCollectionName).
		BindFunc(func(e *core.RecordEvent) error {
			e.App.Logger().Info(
				"[Plugin/OAuth2] New client registered",
				slog.Any("client_id", e.Record.GetString("client_id")),
				slog.Any("client_name", e.Record.GetString("client_name")),
			)

			h, _ := GetOAuth2Config().GetSecretsHasher(context.Background()).Hash(
				e.Context,
				[]byte(e.Record.GetString("client_secret")),
			)
			e.Record.Set("client_secret", string(h))
			return e.Next()
		})

	//

	return nil
}

func RegisterProtectedResourceMetadata(pattern string, md *rfc9728.ProtectedResourceMetadata) {
	if GetOAuth2Config().EnableRFC9728ProtectedResourceMetadata {
		oauth2ProtectedResourceMetadataMu.Lock()
		oauth2ProtectedResourceMetadata[pattern] = md
		oauth2ProtectedResourceMetadataMu.Unlock()
	}
}

//

func IsRegistered() bool {
	return oauth2 != nil
}

//

func bindOAuth2Handlers(cfg *Config, r *router.Router[*core.RequestEvent]) {
	rg := r.Group(cfg.PathPrefix)
	rg.GET("/auth", api_OAuth2Authorize)
	rg.POST("/auth", api_OAuth2Authorize)
	rg.GET("/token", api_OAuth2Token)
	rg.POST("/token", api_OAuth2Token)
	rg.POST("/revoke", api_OAuth2Revoke)
	rg.POST("/introspect", api_OAuth2Introspect)
	// rfc7591
	// Dynamic Client Registration
	// @ref https://datatracker.ietf.org/doc/html/rfc7591
	if cfg.EnableRFC7591DynamicClientRegistration {
		rg.POST("/register", api_OAuth2Register)
	}
}

func bindOAuth2WellKnownHandlers(md1 *openid.OpenIDProviderMetadata) func(cfg *Config, r *router.Router[*core.RequestEvent]) {
	return func(cfg *Config, r *router.Router[*core.RequestEvent]) {
		// rfc8414
		// Authorization Server Metadata
		// @ref https://datatracker.ietf.org/doc/html/rfc8414
		// @ref https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
		if md1 != nil {
			r.GET("/.well-known/oauth-authorization-server", handleJSON(md1.AuthorizationServerMetadata))
			r.GET("/.well-known/openid-configuration", handleJSON(md1))
		}
		// rfc9728
		// Protected Resource Metadata
		// @ref https://datatracker.ietf.org/doc/html/rfc9728
		if cfg.EnableRFC9728ProtectedResourceMetadata {
			r.GET("/.well-known/oauth-protected-resource/{resource}", func(e *core.RequestEvent) error {
				oauth2ProtectedResourceMetadataMu.RLock()
				defer oauth2ProtectedResourceMetadataMu.RUnlock()

				// The resource identifier is expected to be in the path. For example, if the
				// resource is "https://api.example.com/resource", the client would request
				// "https://api.example.com/.well-known/oauth-protected-resource/resource".
				key := "/" + strings.Trim(e.Request.PathValue("resource"), "/")

				if md, ok := oauth2ProtectedResourceMetadata[key]; ok {
					return handleJSON(md)(e)
				} else {
					return e.NotFoundError("Unknown Protected Resource", nil)
				}
			})
		}
	}
}

func handleJSON(data any) func(e *core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		r := e.Request
		w := e.Response
		// Set CORS headers for cross-origin client discovery.
		// OAuth metadata is public information, so allowing any origin is safe.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		// Handle CORS preflight requests
		if r.Method == http.MethodOptions {
			return e.NoContent(http.StatusNoContent)
		}
		// Only GET allowed for metadata retrieval
		if r.Method != http.MethodGet {
			return e.Error(http.StatusMethodNotAllowed, "", nil)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(data); err != nil {
			return e.InternalServerError("", err)
		}
		return nil
	}
}

//

func ParseJWTToken(ctx context.Context, tokenString string) (*jwt.Token, *jwt.JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != "RS256" {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		if oauth2PrivateKey == nil {
			panic("[Plugin/OAuth2] ParseJWTToken: OAuth2 config is not initialized. You MUST call Register() before using this package.")
		}
		return &oauth2PrivateKey.PublicKey, nil
	})
	if err != nil {
		return nil, nil, err
	}
	if !token.Valid() {
		return nil, nil, fmt.Errorf("invalid token")
	}
	claims := &jwt.JWTClaims{}
	claims.FromMapClaims(token.Claims)
	return token, claims, nil
}
