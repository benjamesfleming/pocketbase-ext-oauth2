package plugin

import (
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbuilds/xpb"

	oauth2 "github.com/benjamesfleming/pocketbase-ext-oauth2"
)

// This variable will automatically be set at build time by xpb
var version string

func init() {
	xpb.Register(&Plugin{
		PathPrefix:     "/oauth2",
		UserCollection: "users",
		EnableRFC7591:  true,
		EnableRFC9728:  true,
		EnforcePKCE:    "none",
	})
}

//

type Plugin struct {
	PathPrefix     string `json:"prefix"`
	UserCollection string `json:"user_collection"`
	EnableRFC7591  bool   `json:"enable_rfc7591"`
	EnableRFC9728  bool   `json:"enable_rfc9728"`
	EnforcePKCE    string `json:"enforce_pkce"` // "all", "public", "none"
}

// Validate implements validation.Validatable.
func (p *Plugin) Validate() error {
	return validation.ValidateStruct(p,
		validation.Field(&p.EnforcePKCE,
			validation.Required,
			validation.In("all", "public", "none"),
		),
		validation.Field(&p.PathPrefix,
			validation.Required,
			validation.NewStringRule(
				func(s string) bool {
					return s == "" || s[0] == '/'
				},
				"path prefix must start with a slash",
			),
		),
		validation.Field(&p.UserCollection,
			validation.Required,
			is.Alphanumeric,
		),
	)
}

// Name implements xpb.Plugin.
func (p *Plugin) Name() string {
	return "pocketbase-ext-oauth2"
}

// Version implements xpb.Plugin.
func (p *Plugin) Version() string {
	return version
}

// Description implements xpb.Plugin.
func (p *Plugin) Description() string {
	return "PocketBase OAuth2/OpenID Connect Provider Plugin"
}

// Init implements xpb.Plugin.
func (p *Plugin) Init(app core.App) error {
	return oauth2.Register(
		app,
		&oauth2.Config{
			BaseConfig: &oauth2.BaseConfig{
				AccessTokenLifespan:         time.Hour,
				AuthorizeCodeLifespan:       time.Minute * 15,
				EnforcePKCE:                 (p.EnforcePKCE == "all"),
				EnforcePKCEForPublicClients: (p.EnforcePKCE == "public"),
				RefreshTokenScopes:          []string{}, // All scopes are allowed for refresh tokens
			},
			PathPrefix:                             p.PathPrefix,
			UserCollection:                         p.UserCollection,
			EnableRFC7591DynamicClientRegistration: p.EnableRFC7591,
			EnableRFC9728ProtectedResourceMetadata: p.EnableRFC9728,
		},
	)
}
