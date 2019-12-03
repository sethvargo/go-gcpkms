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
	"crypto/sha512"
	"strings"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
)

func TestNewSigner(t *testing.T) {
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
			ckv:    testSignerKey,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewSigner(ctx, tc.client, tc.ckv); err != nil {
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

func TestSigner_WithContext(t *testing.T) {
	t.Parallel()

	s := new(Signer)
	ctx := context.Background()
	s = s.WithContext(ctx)

	if ctx != s.ctx {
		t.Fatalf("expected %#v to be %#v", ctx, s.ctx)
	}
}

func TestSigner_Public(t *testing.T) {
	t.Parallel()

	client, ctx := testClient(t)
	signer, err := NewSigner(ctx, client, testSignerKey)
	if err != nil {
		t.Fatal(err)
	}

	if p := signer.Public(); p == nil {
		t.Errorf("expected public key")
	}
}

func TestSigner_Sign(t *testing.T) {
	t.Parallel()

	client, ctx := testClient(t)
	signer, err := NewSigner(ctx, client, testSignerKey)
	if err != nil {
		t.Fatal(err)
	}

	msg := "my message to sign"
	dig := sha512.Sum512([]byte(msg))

	sig, err := signer.Sign(nil, dig[:], nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(sig) < 10 {
		t.Errorf("invalid signature: %s", sig)
	}
}
