# go-crypto [![Build Status](https://travis-ci.org/phylake/go-crypto.svg?branch=master)](https://travis-ci.org/phylake/go-crypto)

Go utilities for common cryptography tasks

## Examples

### Encrypt a large file with a public key and AES-256-CBC

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

    privateKey := pki.PrivateKey(*rsaKey)
    publicKey := pki.PublicKey(rsaKey.PublicKey)

    superLargeFile := []byte("super large file contents")
    encBlock, err := publicKey.EncryptCBC(superLargeFile)
    if err != nil {
        panic(err)
    }

    // a randomly generated key (K) that's been that's been encrypted with your
    // and base64-encoded
    fmt.Println(encBlock.EncryptedSymmetricKey)

    // your data encrypted using a randomly generated key as input to the
    // AES-256 block cipher in CBC mode
    fmt.Println(encBlock.EncryptedBlob)

    // decrypt and print the original file
    superLargeFile2, err := privateKey.DecryptCBC(encBlock)
    if err != nil {
        panic(err)
    }

    fmt.Println(string(superLargeFile2))
}

```

## Notable implementation details
- The only cipher used is 256 bit AES.
- The CBC block cipher mode is OpenSSL (aes-256-cbc) compatible. Both use SHA1 as the hash function.
