// Copyright The Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcpkms

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"sync"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// Decrypter implements crypto.Decrypter.
var _ crypto.Decrypter = (*Decrypter)(nil)

// Decrypter implements crypto.Decrypter for Google Cloud KMS keys.
type Decrypter struct {
	ctx     context.Context
	ctxLock sync.RWMutex

	client       *kms.KeyManagementClient
	keyID        string
	keyAlgorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	publicKey    crypto.PublicKey
}

// NewDecrypter creates a new decrypter. The cryptoKeyVersionID must be in the
// format projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/v.
func NewDecrypter(ctx context.Context, client *kms.KeyManagementClient, cryptoKeyVersionID string) (*Decrypter, error) {
	if client == nil {
		return nil, fmt.Errorf("kms client cannot be nil")
	}

	// Get the key information
	ckv, err := client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{
		Name: cryptoKeyVersionID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to lookup key: %w", err)
	}

	// Verify it's a key used for decryption
	switch ckv.Algorithm {
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512:
	default:
		return nil, fmt.Errorf("unknown decryption algorithm %s", ckv.Algorithm.String())
	}

	// Get the public key PEM
	pk, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: ckv.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key: %w", err)
	}

	// Parse the public key
	publicKey, err := parsePublicKey([]byte(pk.Pem))
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &Decrypter{
		client:       client,
		keyID:        cryptoKeyVersionID,
		keyAlgorithm: ckv.Algorithm,
		publicKey:    publicKey,
	}, nil
}

// WithContext adds the given context to the decrypter. Normally this would be
// passed as the first argument to Decrypt, but the current interface does not
// accept a context.
func (d *Decrypter) WithContext(ctx context.Context) *Decrypter {
	d.ctxLock.Lock()
	defer d.ctxLock.Unlock()

	d.ctx = ctx
	return d
}

// Public returns the public key for the decrypter.
func (d *Decrypter) Public() crypto.PublicKey {
	return d.publicKey
}

// Decrypt decrypts the given message.
func (d *Decrypter) Decrypt(_ io.Reader, msg []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	ctx := d.context()
	resp, err := d.client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
		Name:       d.keyID,
		Ciphertext: msg,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}
	return resp.Plaintext, nil
}

// context returns the context for this decrypter.
func (d *Decrypter) context() context.Context {
	d.ctxLock.RLock()
	defer d.ctxLock.RUnlock()

	ctx := d.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	return ctx
}
