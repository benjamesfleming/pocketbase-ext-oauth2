package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"

	"github.com/benjamesfleming/pocketbase-ext-oauth2/consts"
	_ "github.com/benjamesfleming/pocketbase-ext-oauth2/migrations"
	"github.com/benjamesfleming/pocketbase-ext-oauth2/openid"
	"github.com/benjamesfleming/pocketbase-ext-oauth2/rfc8414"
	"github.com/benjamesfleming/pocketbase-ext-oauth2/rfc9728"
	"github.com/benjamesfleming/pocketbase-ext-oauth2/ui"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

type BaseConfig = fosite.Config

type Config struct {
	*BaseConfig

	PathPrefix                             string
	UserCollection                         string
	UserInfoClaimStrategy                  UserInfoClaimStrategy
	EnableRFC7591DynamicClientRegistration bool
	EnableRFC9728ProtectedResourceMetadata bool
}

var oauth2 fosite.OAuth2Provider
var oauth2GlobalCfg *Config
var oauth2GlobalStore *OAuth2Store
var oauth2PrivateKey *jose.JSONWebKey
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
	// Create the OAuth2 config
	oauth2GlobalCfg = config
	if oauth2GlobalCfg.PathPrefix == "" {
		oauth2GlobalCfg.PathPrefix = "/oauth2"
	}
	if oauth2GlobalCfg.UserInfoClaimStrategy == nil {
		oauth2GlobalCfg.UserInfoClaimStrategy = &DefaultUserInfoClaimStrategy{}
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
					if oauth2PrivateKey == nil {
						panic("[Plugin/OAuth2] Private key is not initialized!! This should never happen because we load it during app bootstrap.")
					}
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

	// Attach bootstrap handler

	app.OnBootstrap().BindFunc(func(e *core.BootstrapEvent) error {
		err := e.Next()
		if err != nil {
			return err
		}
		oauth2PrivateKey, err = loadPrivateKeyFromAppStorage(e.App)
		if err != nil {
			return fmt.Errorf("Plugin/OAuth2: Failed to load or generate private key: %w", err)
		}
		oauth2GlobalCfg.GlobalSecret, err = loadGlobalSecretFromAppStorage(e.App)
		if err != nil {
			return fmt.Errorf("Plugin/OAuth2: Failed to load or generate global secret: %w", err)
		}
		return nil
	})

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
				JwksURI:          app.Settings().Meta.AppURL + "/.well-known/jwks.json",
			},
		)(oauth2GlobalCfg, se.Router)
		// rfc9728 middleware for protected resource endpoints
		RegisterProtectedResourceMetadata(
			&rfc9728.ProtectedResourceMetadata{
				Resource: app.Settings().Meta.AppURL + config.PathPrefix + "/userinfo",
				AuthorizationServers: []string{
					app.Settings().Meta.AppURL,
				},
				BearerMethodsSupported: []string{"header"},
				ScopesSupported:        []string{"openid", "profile", "email"},
			},
		)
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

	// Attach cron jobs

	app.Cron().MustAdd(consts.CleanupExpiredSessionsJobName, "0 * * * *", func() {
		for _, collection := range []string{
			consts.AuthCodeCollectionName,
			consts.AccessCollectionName,
			consts.RefreshCollectionName,
			consts.PKCECollectionName,
			consts.OpenIDConnectCollectionName,
			consts.JTICollectionName,
		} {
			records, err := app.FindAllRecords(
				collection,
				dbx.NewExp("expires_at < {:now}", dbx.Params{"now": time.Now().Unix()}),
			)
			if err != nil {
				app.Logger().Error(
					"[Plugin/OAuth2] Failed to query expired sessions for cleanup",
					slog.Any("collection", collection),
					slog.Any("error", err),
				)
				continue
			}
			for _, record := range records {
				if err := app.Delete(record); err != nil {
					app.Logger().Error(
						"[Plugin/OAuth2] Failed to delete expired session during cleanup",
						slog.Any("collection", collection),
						slog.Any("record_id", record.Id),
						slog.Any("error", err),
					)
				}
			}
		}
	})

	//

	return nil
}

func RegisterProtectedResourceMetadata(md *rfc9728.ProtectedResourceMetadata) {
	if GetOAuth2Config().EnableRFC9728ProtectedResourceMetadata {
		url, _ := url.Parse(md.Resource)
		key := strings.Trim(url.Path, "/")

		oauth2ProtectedResourceMetadataMu.Lock()
		oauth2ProtectedResourceMetadata[key] = md
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
	rg.GET("/userinfo", api_OAuth2UserInfo).Bind(rfc9728.RequireAuthRFC9728WWWAuthenticateResponse())
	// rfc7591
	// Dynamic Client Registration
	// @ref https://datatracker.ietf.org/doc/html/rfc7591
	if cfg.EnableRFC7591DynamicClientRegistration {
		rg.POST("/register", api_OAuth2Register)
	}
	// ui
	r.GET("/oauth2/login", func(e *core.RequestEvent) error {
		return e.FileFS(ui.DistDirFS, "login.alpinejs.html")
	})
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
			// rfc7517
			// JSON Web Key (JWK)
			// @ref https://datatracker.ietf.org/doc/html/rfc7517
			rfc7517KeySet := &jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{oauth2PrivateKey.Public()},
			}
			r.GET("/.well-known/jwks.json", handleJSON(rfc7517KeySet))
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
				key := strings.Trim(e.Request.PathValue("resource"), "/")

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
