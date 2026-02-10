package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/plugins/oauth2/consts"
)

var sessionCollections = []string{
	consts.AccessCollectionName,
	consts.RefreshCollectionName,
	consts.AuthCodeCollectionName,
	consts.PKCECollectionName,
	consts.OpenIDConnectCollectionName,
}

func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {

		// OAuth2 Session Collections

		for _, name := range sessionCollections {
			if err := createSessionCollection(txApp, name); err != nil {
				return err
			}
		}

		// JTI Collection

		collection := core.NewBaseCollection(consts.JTICollectionName)
		collection.System = true
		collection.Fields.Add(
			&core.TextField{Name: "jti"},
			&core.NumberField{Name: "expires_at"},
		)
		if err := txApp.Save(collection); err != nil {
			return err
		}

		// RFC 7591 Client Metadata Collection

		collection = core.NewBaseCollection(consts.ClientCollectionName)
		collection.System = true
		collection.Fields.Add(
			&core.TextField{Name: "client_id"},
			&core.TextField{Name: "client_name"},
			&core.TextField{Name: "client_secret"},
			&core.NumberField{Name: "client_secret_expires_at"},
			&core.JSONField{Name: "redirect_uris"},
			&core.JSONField{Name: "grant_types"},
			&core.JSONField{Name: "response_types"},
			&core.TextField{Name: "scope"},
			&core.JSONField{Name: "audience"},
			&core.TextField{Name: "owner"},
			&core.TextField{Name: "policy_uri"},
			&core.TextField{Name: "tos_uri"},
			&core.TextField{Name: "client_uri"},
			&core.TextField{Name: "logo_uri"},
			&core.JSONField{Name: "contacts"},
			&core.JSONField{Name: "allowed_cors_origins"},
			&core.TextField{Name: "subject_type"},
			&core.TextField{Name: "sector_identifier_uri"},
			&core.TextField{Name: "jwks_uri"},
			&core.JSONField{Name: "jwks"},
			&core.JSONField{Name: "request_uris"},
			&core.TextField{Name: "token_endpoint_auth_method"},
			&core.TextField{Name: "token_endpoint_auth_signing_alg"},
			&core.TextField{Name: "request_object_signing_alg"},
			&core.TextField{Name: "userinfo_signed_response_alg"},
			&core.JSONField{Name: "metadata"},
			&core.TextField{Name: "access_token_strategy"},
		)
		return txApp.Save(collection)
	}, func(txApp core.App) error {
		for _, name := range sessionCollections {
			if collection, err := txApp.FindCollectionByNameOrId(name); err == nil {
				_ = txApp.Delete(collection)
			}
		}
		if collection, err := txApp.FindCollectionByNameOrId(consts.JTICollectionName); err == nil {
			_ = txApp.Delete(collection)
		}
		if collection, err := txApp.FindCollectionByNameOrId(consts.ClientCollectionName); err == nil {
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
