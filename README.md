# go-crypto [![Build Status](https://travis-ci.org/phylake/go-crypto.svg?branch=master)](https://travis-ci.org/phylake/go-crypto)

Go utilities for common tasks asked about around the internet

## Examples

### Encrypt a large file with a public key

```golang
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "fmt"
    "github.com/phylake/go-crypto/pki"
)

func main() {
    rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
    if err != nil {
        panic(err)
    }

    pubS3FS := pki.PublicKey(rsaKey.PublicKey)

    superLargeFile := []byte("super large file contents")
    encBlock, err := pubS3FS.EncryptCBC(superLargeFile)
    if err != nil {
        panic(err)
    }

    // a randomly generated key (K) that's been that's been encrypted with your
    // and base64-encoded
    fmt.Println(encBlock.EncryptedSymmetricKey)

    // your data encrypted using a randomly generated key as input to the
    // AES-256 block cipher in CBC mode
    fmt.Println(encBlock.EncryptedBlob)
}
```
