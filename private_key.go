package oauth2

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"

	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/pocketbase/pocketbase/core"
)

const (
	paramsKeyOAuth2OpenIDKey = "oauth2_openid_key"
)

var oauth2PrivateKey *jose.JSONWebKey

//

// loadPrivateKeyFromAppStorage loads the private JSON-Web-Key from the app storage or generates
// a new one if it doesn't exist. The key is used for signing the OpenID Connect ID tokens and
// other related operations. The key is stored in the internal app _params table to ensure it
// persists across application restarts.
func loadPrivateKeyFromAppStorage(app core.App) error {
	param := &core.Param{}
	err := app.ModelQuery(param).Model(paramsKeyOAuth2OpenIDKey, param)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return errors.Wrap(err, "failed to query db")
		}
		// No existing key found, generate a new Ed25519 key
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return errors.Wrap(err, "failed to generate new ed25519 key")
		}
		// Build the JWK from the generated private key
		oauth2PrivateKey = &jose.JSONWebKey{
			Key:       privateKey,
			KeyID:     uuid.NewString(),
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}
		// Store the keys in the app storage for future use
		newParam := &core.Param{}
		newParam.Id = paramsKeyOAuth2OpenIDKey
		newParam.Value, err = oauth2PrivateKey.MarshalJSON()
		if err != nil {
			return errors.Wrap(err, "failed to marshal ed25519 key")
		}
		if err := app.Save(newParam); err != nil {
			return errors.Wrap(err, "failed to save ed25519 key")
		}
		return nil
	}
	// Key found, decode it
	if err := json.Unmarshal(param.Value, &oauth2PrivateKey); err != nil {
		return errors.Wrap(err, "failed to unmarshal ed25519 key")
	}
	return nil
}
