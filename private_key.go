package oauth2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/pocketbase/pocketbase/core"
)

const (
	PrivateKeyFileName = "_internal/oauth2_private_key.pem"
)

var oauth2PrivateKey *rsa.PrivateKey

//

func loadPrivateKeyFromAppStorage(app core.App) error {
	fs, err := app.NewFilesystem()
	if err != nil {
		return fmt.Errorf("failed to create filesystem: %w", err)
	}
	defer fs.Close()

	exists, err := fs.Exists(PrivateKeyFileName)
	if err != nil {
		return fmt.Errorf("failed to check if private key file exists: %w", err)
	}

	if !exists {
		// Generate a new private key
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate new private key: %w", err)
		}
		oauth2PrivateKey = privateKey
		// Marshal the private key to DER format (PKCS#8 is a modern standard)
		// Save the private key to the filesystem
		keyBytes, err := encodePrivateKeyToPEMBytes(privateKey)
		if err != nil {
			return fmt.Errorf("failed to encode private key: %w", err)
		}
		if err = fs.Upload(keyBytes, PrivateKeyFileName); err != nil {
			return fmt.Errorf("failed to save private key: %w", err)
		}

	} else {
		r, err := fs.GetReader(PrivateKeyFileName)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %w", err)
		}
		defer r.Close()
		privateKeyBytes, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("failed to read private key: %w", err)
		}
		privateKey, err := decodePEMBytesToPrivateKey(privateKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to decode private key: %w", err)
		}
		oauth2PrivateKey = privateKey
	}

	return nil
}

func encodePrivateKeyToPEMBytes(key *rsa.PrivateKey) ([]byte, error) {
	// Marshal the private key to DER format (PKCS#8 is a modern standard)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	// Create a PEM block
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

func decodePEMBytesToPrivateKey(keyBytes []byte) (*rsa.PrivateKey, error) {
	// Decode the PEM block
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	// Parse the DER-encoded private key
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fallback to PKCS#1 if PKCS#8 fails (for older formats)
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}
	// Assert the private key to the correct type
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key type asserted from file: got %T, expected *rsa.PrivateKey", privateKey)
	}
	return rsaKey, nil
}
