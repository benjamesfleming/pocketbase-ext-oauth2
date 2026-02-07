package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/plugins/oauth2"
)

var sessionCollections = []string{
	oauth2.AccessCollectionName,
	oauth2.RefreshCollectionName,
	oauth2.AuthCodeCollectionName,
	oauth2.PKCECollectionName,
}

func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {

		// OAuth2 Session Collections

		for _, name := range sessionCollections {
			if err := createSessionCollection(txApp, name); err != nil {
				return err
			}
		}

		// RFC 7591 Client Metadata Collection

		collection := core.NewBaseCollection(oauth2.ClientCollectionName)
		collection.System = true
		collection.Fields.Add(
			&core.TextField{Name: "client_id"},
			&core.TextField{Name: "client_secret"},
			&core.NumberField{Name: "client_secret_expires_at"},
			&core.TextField{Name: "scope"},
			&core.JSONField{Name: "redirect_uris"},
			&core.TextField{Name: "token_endpoint_auth_method"},
			&core.JSONField{Name: "grant_types"},
			&core.JSONField{Name: "response_types"},
			&core.JSONField{Name: "contacts"},
			&core.TextField{Name: "client_name"},
			&core.TextField{Name: "client_uri"},
			&core.TextField{Name: "logo_uri"},
			&core.TextField{Name: "tos_uri"},
			&core.TextField{Name: "policy_uri"},
			&core.TextField{Name: "jwks_uri"},
			&core.JSONField{Name: "jwks"},
			&core.TextField{Name: "software_id"},
			&core.TextField{Name: "software_version"},
		)
		return txApp.Save(collection)
	}, func(txApp core.App) error {
		for _, name := range sessionCollections {
			if collection, err := txApp.FindCollectionByNameOrId(name); err == nil {
				_ = txApp.Delete(collection)
			}
		}
		if collection, err := txApp.FindCollectionByNameOrId(oauth2.ClientCollectionName); err == nil {
			_ = txApp.Delete(collection)
		}
		return nil
	})
}

func createSessionCollection(txApp core.App, name string) error {
	collection := core.NewBaseCollection(name)
	collection.System = true

	collection.Fields.Add(
		&core.TextField{Name: "signature"},
		&core.TextField{Name: "client_id"},
		&core.TextField{Name: "request_id"},
		&core.NumberField{Name: "requested_at"},
		&core.NumberField{Name: "expires_at"},
		&core.TextField{Name: "scopes"},
		&core.TextField{Name: "granted_scopes"},
		&core.TextField{Name: "requested_audience"},
		&core.TextField{Name: "granted_audience"},
		&core.TextField{Name: "form_data"},
		&core.TextField{Name: "session_data"},
		&core.TextField{Name: "subject"},
	)

	return txApp.Save(collection)
}
