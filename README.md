# Google Cloud KMS - Golang Crypto Interface

[![Godoc Reference](https://img.shields.io/badge/godoc-Reference-brightgreen.svg?style=flat-square)][godoc]

This package wraps the [Google Cloud KMS][cloud-kms] Go library to implement
Go's [crypto.Decrypter][crypto.decrypter] and [crypto.Signer][crypto.signer]
interfaces. It only works with Google Cloud KMS asymmetric keys.

## Usage

```go
package main

import (
  kms "cloud.google.com/go/kms/apiv1"
  "github.com/sethvargo/gcpkms/pkg/gcpkms"
)

func main() {
  ctx := context.Background()
  kmsClient, err := kms.NewKeyManagementClient(ctx)
  if err != nil {
    log.Fatal(err)
  }

  keyID := "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
  signer, err := gcpkms.NewSigner(ctx, kmsClient, keyID)
  if err != nil {
    log.Fatal(err)
  }

  sig, err := signer.Sign(nil, digest, nil)
  if err != nil {
    log.Fatal(err)
  }
}
```

For more examples, please see the [package godoc][godoc].

[cloud-kms]: https://cloud.google.com/kms
[crypto.decrypter]: https://golang.org/pkg/crypto/#Decrypter
[crypto.signer]: https://golang.org/pkg/crypto/#Signer
[godoc]: https://godoc.org/github.com/sethvargo/go-gcpkms/pkg/gcpkms
