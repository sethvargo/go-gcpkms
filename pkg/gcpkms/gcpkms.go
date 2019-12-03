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
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// parsePublicKey extracts the pem-encoded contents and parses it as a public
// key.
func parsePublicKey(p []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, fmt.Errorf("pem is invalid")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	switch t := pub.(type) {
	case *rsa.PublicKey:
		return t, nil
	case *dsa.PublicKey:
		return t, nil
	case *ecdsa.PublicKey:
		return t, nil
	case ed25519.PublicKey:
		return t, nil
	default:
		return nil, fmt.Errorf("unknown key type %T", t)
	}
}
