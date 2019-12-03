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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"strings"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
)

func TestNewDecrypter(t *testing.T) {
	t.Parallel()

	client, ctx := testClient(t)

	cases := []struct {
		name   string
		client *kms.KeyManagementClient
		ckv    string
		err    string
	}{
		{
			name:   "nil client",
			client: nil,
			ckv:    "",
			err:    "cannot be nil",
		},
		{
			name:   "bad key",
			client: client,
			ckv:    "nope nope nope",
			err:    "failed to lookup key",
		},
		{
			name:   "ok",
			client: client,
			ckv:    testDecrypterKey,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewDecrypter(ctx, tc.client, tc.ckv); err != nil {
				if tc.err != "" {
					if !strings.Contains(err.Error(), tc.err) {
						t.Errorf("expected %q to contain %q", err.Error(), tc.err)
					}
				} else {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestDecrypter_WithContext(t *testing.T) {
	t.Parallel()

	d := new(Decrypter)
	ctx := context.Background()
	d = d.WithContext(ctx)

	if ctx != d.ctx {
		t.Fatalf("expected %#v to be %#v", ctx, d.ctx)
	}
}

func TestDecrypter_Public(t *testing.T) {
	t.Parallel()

	client, ctx := testClient(t)
	decrypter, err := NewDecrypter(ctx, client, testDecrypterKey)
	if err != nil {
		t.Fatal(err)
	}

	if p := decrypter.Public(); p == nil {
		t.Errorf("expected public key")
	}
}

func TestDecrypter_Decrypt(t *testing.T) {
	t.Parallel()

	client, ctx := testClient(t)
	decrypter, err := NewDecrypter(ctx, client, testDecrypterKey)
	if err != nil {
		t.Fatal(err)
	}

	// Get the public key to encrypt the data
	pub, ok := decrypter.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected %T to be *rsa.PublicKey", decrypter.Public())
	}

	msg := []byte("my message to encrypt")
	hsh := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hsh, rand.Reader, pub, msg, nil)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := decrypter.Decrypt(nil, ciphertext[:], nil)
	if err != nil {
		t.Fatal(err)
	}

	if p, m := string(plaintext), string(msg); p != m {
		t.Errorf("expected %q to be %q", p, m)
	}
}
