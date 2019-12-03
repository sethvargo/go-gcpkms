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
	"fmt"
	"os"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
)

var (
	testDecrypterKey string
	testSignerKey    string
)

func testClient(tb testing.TB) (*kms.KeyManagementClient, context.Context) {
	tb.Helper()

	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		tb.Fatal(err)
	}
	return client, ctx
}

func TestMain(m *testing.M) {
	setFromEnv(&testDecrypterKey, "TEST_DECRYPTER_KEY")
	setFromEnv(&testSignerKey, "TEST_SIGNER_KEY")

	os.Exit(m.Run())
}

func setFromEnv(s *string, k string) {
	v := os.Getenv(k)
	if v == "" {
		fmt.Fprintf(os.Stderr, "missing %s\n", k)
		os.Exit(1)
	}
	*s = v
}
