package oauth2

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/hex"
	"encoding/json"

	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
)

const (
	paramsKeyOAuth2RSAKey       = "oauth2_rsa_key"
	paramsKeyOAuth2GlobalSecret = "oauth2_global_secret"
)

// loadPrivateKeyFromAppStorage loads the private JSON-Web-Key from the app storage or generates
// a new one if it doesn't exist. The key is used for signing the OpenID Connect ID tokens and
// other related operations. The key is stored in the internal app _params table to ensure it
// persists across application restarts.
func loadPrivateKeyFromAppStorage(app core.App) (*jose.JSONWebKey, error) {
	return loadParamFromAppStorage(app, paramsKeyOAuth2RSAKey, &jose.JSONWebKey{}, func() (*jose.JSONWebKey, error) {
		// No existing key found, generate a new one
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate new RSA key")
		}
		// Build the JWK from the generated private key
		return &jose.JSONWebKey{
			Key:       privateKey,
			KeyID:     uuid.NewString(),
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}, nil
	})
}

// loadGlobalSecretFromAppStorage loads the global secret from the app storage or generates
// a new one if it doesn't exist. The global secret is used for various cryptographic operations
// within the OAuth2 plugin, such as signing tokens, etc.
func loadGlobalSecretFromAppStorage(app core.App) ([]byte, error) {
	return loadParamFromAppStorage(app, paramsKeyOAuth2GlobalSecret, []byte{}, func() ([]byte, error) {
		// No existing secret found, generate a new one
		ret := make([]byte, 32)
		rand.Read(ret)
		return ret, nil
	})
}

//

// loadParamFromAppStorage is a generic helper function that loads a parameter of any
// type from the app storage or generates and stores a new one if it doesn't exist.
// Byte slices are treated as a special case and are hex-encoded before storing to avoid
// unnecessary JSON encoding overhead. All other types are marshaled to JSON before storing
// and unmarshaled after loading.
func loadParamFromAppStorage[T any](app core.App, paramId string, value T, generator func() (T, error)) (T, error) {
	var zero T
	param := &core.Param{}
	err := app.ModelQuery(param).Model(paramId, param)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return zero, errors.Wrap(err, "failed to query db")
		}
		// No existing value, generate a new one
		newValue, err := generator()
		if err != nil {
			return zero, errors.Wrap(err, "failed to generate new value")
		}
		// Store the value in the app storage for future use
		// We marshal the value to JSON before storing it, except for
		// byte slices which we store directly to avoid unnecessary
		// encoding overhead.
		newParam := &core.Param{}
		newParam.Id = paramId
		newParam.Created = types.NowDateTime()
		newParam.Updated = newParam.Created
		switch v := any(newValue).(type) {
		case []byte:
			newParam.Value = hex.AppendEncode([]byte{}, v)
		default:
			newParam.Value, err = json.Marshal(newValue)
			if err != nil {
				return zero, errors.Wrap(err, "failed to marshal value")
			}
		}
		if err := app.Save(newParam); err != nil {
			return zero, errors.Wrap(err, "failed to save value")
		}
		return newValue, nil
	}
	// Existing value found, unmarshal if necessary.
	switch any(value).(type) {
	case []byte:
		if valueStr, err := hex.DecodeString(param.Value.String()); err != nil {
			return zero, errors.Wrap(err, "failed to decode value")
		} else {
			value = any(valueStr).(T)
		}
		return value, nil
	default:
		if err := json.Unmarshal(param.Value, &value); err != nil {
			return zero, errors.Wrap(err, "failed to unmarshal value")
		}
		return value, nil
	}
}
