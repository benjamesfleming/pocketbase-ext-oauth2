package oauth2

// import (
// 	"crypto/ed25519"
// 	"testing"

// 	oauth2 "github.com/benjamesfleming/pocketbase-ext-oauth2"
// 	"github.com/go-jose/go-jose/v3"
// )

// func TestLoadPrivateKey_GeneratesOnFirstUse(t *testing.T) {
// 	app := setupTestApp(t)
// 	defer app.Cleanup()

// 	key, err := loadPrivateKeyFromAppStorage(app)
// 	if err != nil {
// 		t.Fatalf("loadPrivateKeyFromAppStorage failed: %v", err)
// 	}
// 	if key == nil {
// 		t.Fatal("expected non-nil JWK")
// 	}
// 	if key.KeyID == "" {
// 		t.Error("expected non-empty KeyID")
// 	}
// 	if key.Algorithm != string(jose.EdDSA) {
// 		t.Errorf("Algorithm = %q, want %q", key.Algorithm, string(jose.EdDSA))
// 	}
// 	if key.Use != "sig" {
// 		t.Errorf("Use = %q, want %q", key.Use, "sig")
// 	}
// 	if _, ok := key.Key.(ed25519.PrivateKey); !ok {
// 		t.Errorf("Key type = %T, want ed25519.PrivateKey", key.Key)
// 	}
// }

// func TestLoadPrivateKey_ReloadsExisting(t *testing.T) {
// 	app := setupTestApp(t)
// 	defer app.Cleanup()

// 	key1, err := loadPrivateKeyFromAppStorage(app)
// 	if err != nil {
// 		t.Fatalf("first load failed: %v", err)
// 	}

// 	key2, err := loadPrivateKeyFromAppStorage(app)
// 	if err != nil {
// 		t.Fatalf("second load failed: %v", err)
// 	}

// 	if key1.KeyID != key2.KeyID {
// 		t.Errorf("KeyID mismatch: %q vs %q", key1.KeyID, key2.KeyID)
// 	}

// 	priv1, ok1 := key1.Key.(ed25519.PrivateKey)
// 	priv2, ok2 := key2.Key.(ed25519.PrivateKey)
// 	if !ok1 || !ok2 {
// 		t.Fatal("expected ed25519.PrivateKey for both keys")
// 	}
// 	if !priv1.Equal(priv2) {
// 		t.Error("expected same private key on reload")
// 	}
// }

// func TestLoadGlobalSecret_GeneratesOnFirstUse(t *testing.T) {
// 	app := setupTestApp(t)
// 	defer app.Cleanup()

// 	secret, err := loadGlobalSecretFromAppStorage(app)
// 	if err != nil {
// 		t.Fatalf("loadGlobalSecretFromAppStorage failed: %v", err)
// 	}
// 	if len(secret) != 32 {
// 		t.Errorf("secret length = %d, want 32", len(secret))
// 	}
// }

// func TestLoadGlobalSecret_ReloadsExisting(t *testing.T) {
// 	app := setupTestApp(t)
// 	defer app.Cleanup()

// 	secret1, err := loadGlobalSecretFromAppStorage(app)
// 	if err != nil {
// 		t.Fatalf("first load failed: %v", err)
// 	}

// 	secret2, err := loadGlobalSecretFromAppStorage(app)
// 	if err != nil {
// 		t.Fatalf("second load failed: %v", err)
// 	}

// 	if len(secret1) != len(secret2) {
// 		t.Fatalf("secret lengths differ: %d vs %d", len(secret1), len(secret2))
// 	}
// 	for i := range secret1 {
// 		if secret1[i] != secret2[i] {
// 			t.Error("expected same secret on reload")
// 			break
// 		}
// 	}
// }
