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

package gcpkms_test

import (
	"context"
	"crypto/sha512"
	"fmt"
	"log"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/sethvargo/go-gcpkms/pkg/gcpkms"
)

var (
	ctx          = context.Background()
	kmsClient, _ = kms.NewKeyManagementClient(ctx)
)

func ExampleSigner_Sign() {
	// Key is the full resource name
	keyID := "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

	// Create the signer
	signer, err := gcpkms.NewSigner(ctx, kmsClient, keyID)
	if err != nil {
		log.Fatal(err)
	}

	// Message to sign
	msg := []byte("my message to sign")

	// Hash the message - this hash must correspond to the KMS key type
	dig := sha512.Sum512(msg)

	// Sign the hash
	sig, err := signer.Sign(nil, dig[:], nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(sig))
}

func ExampleDecrypter_Decrypt() {
	// Key is the full resource name
	keyID := "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

	// Create the decrypter
	decrypter, err := gcpkms.NewDecrypter(ctx, kmsClient, keyID)
	if err != nil {
		log.Fatal(err)
	}

	// Ciphertext to decrypt - this ciphertext would have been encrypted with the
	// public key
	ciphertext := []byte("...")

	// Decrypt the ciphertext
	plaintext, err := decrypter.Decrypt(nil, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(plaintext))
}
