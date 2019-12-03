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

// Signer implements crypto.Signer.
var _ crypto.Signer = (*Signer)(nil)

// Signer implements crypto.Signer for Google Cloud KMS keys.
type Signer struct {
	ctx     context.Context
	ctxLock sync.RWMutex

	client       *kms.KeyManagementClient
	keyID        string
	keyAlgorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	publicKey    crypto.PublicKey
}

// NewSigner creates a new signer. The keyID must be in the format
// projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/v.
func NewSigner(ctx context.Context, client *kms.KeyManagementClient, keyID string) (*Signer, error) {
	if client == nil {
		return nil, fmt.Errorf("kms client cannot be nil")
	}

	// Get the public key
	pk, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key: %w", err)
	}

	// Verify it's a key used for signing
	switch pk.Algorithm {
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,
		kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
	default:
		return nil, fmt.Errorf("unknown signing algorithm %s", pk.Algorithm.String())
	}

	// Parse the public key
	publicKey, err := parsePublicKey([]byte(pk.Pem))
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &Signer{
		client:       client,
		keyID:        keyID,
		keyAlgorithm: pk.Algorithm,
		publicKey:    publicKey,
	}, nil
}

// Public returns the public key for the signer.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// WithContext adds the given context to the signer. Normally this would be
// passed as the first argument to Sign, but the current interface does not
// accept a context.
func (s *Signer) WithContext(ctx context.Context) *Signer {
	s.ctxLock.Lock()
	defer s.ctxLock.Unlock()

	s.ctx = ctx
	return s
}

// Sign signs the given digest. Both the io.Reader and crypto.SignerOpts are
// unused.
func (s *Signer) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	ctx := s.context()

	// Calculate the correct digest based on the key's algorithm
	var dig *kmspb.Digest
	switch s.keyAlgorithm {
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		dig = &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest,
			},
		}
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		dig = &kmspb.Digest{
			Digest: &kmspb.Digest_Sha384{
				Sha384: digest,
			},
		}
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		dig = &kmspb.Digest{
			Digest: &kmspb.Digest_Sha512{
				Sha512: digest,
			},
		}
	default:
		return nil, fmt.Errorf("unknown signing algorithm %s", s.keyAlgorithm.String())
	}

	// Sign the digest
	resp, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name:   s.keyID,
		Digest: dig,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return resp.Signature, nil
}

// context returns the context for this signer or
func (s *Signer) context() context.Context {
	s.ctxLock.RLock()
	defer s.ctxLock.RUnlock()

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	return ctx
}
