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
    // use your own private key
    rsaKey, _ := pki.ParsePrivateKey([]byte(my768BitPrivateKey))
    
    // or generate one
    // rsaKey := generateKey()

    privateKey := pki.PrivateKey(*rsaKey)
    publicKey := pki.PublicKey(rsaKey.PublicKey)

    superLargeFile := []byte("super large file contents")
    encBlock, err := publicKey.EncryptCBC(superLargeFile)
    if err != nil {
        panic(err)
    }

    // a randomly generated key (K) that's been encrypted with your public key
    // and base64-encoded
    fmt.Println(encBlock.EncryptedSymmetricKey)

    // your data encrypted using the key K
    fmt.Println(encBlock.EncryptedBlob)

    // decrypt and print the original file
    superLargeFile2, err := privateKey.DecryptCBC(encBlock)
    if err != nil {
        panic(err)
    }

    fmt.Println(string(superLargeFile2))
}

func generateKey() *rsa.PrivateKey {
    rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
    if err != nil {
        panic(err)
    }
    return rsaKey
}

// checkout https://gist.github.com/phylake/7392335 for relevant OpenSSL commands
var my768BitPrivateKey string = `-----BEGIN RSA PRIVATE KEY-----
MIIBywIBAAJhAMWE5scMDOpfDvgkKKSkstniJG0YaNNbP2GpsS9342JA9Y1GuJl2
rl1OptLwPnzzbz29uXmJxLGYFhL0aT3IEKKKVuoBvxJTbkied7E8cxxF13ywXmqo
sD7pEL4pKv3MQQIDAQABAmEApvlExjvPp0mYs/iNSzHX6A0eUgNyikn2+K6lFMW6
uVLEwhto7oK/wC0/Jc7mZGa8w4T0dU1jtxmjct3Q/0rk0IaqZYGZuA+K/bElZS8J
u8SMHJhuXXAGJ5EoaVLJSYfhAjEA9zhWMG4XAMTOIvcRoYF2JQkMX5kgrDZCBqnG
7qeo2i8oKFSQ1wIBz+rkVxjZwKrNAjEAzIiyR/Z+u3AGN/A9BHTKzscPgUAUZX+I
9o2t4AztB8Xuze24+lwc/fZ09KqXxM9FAjEAxW8tjiHtpwSFp/DvGK+enfc69YIC
UOZIFrAyGli1hgIRLRxUTBHjRpxN3a0QAkmlAjBRX8lebCl7tVQkCUadcUIHBpea
mr4Cq7z4KuIUk8/yGcOq1nuTz/YQ7G8XsI91U+kCMAqV1ex5pJyLaBYyNsdyUOZn
eGf4LKiCsykmr8pdheWPFApbhp1Wi2MmeqGTgpjWsg==
-----END RSA PRIVATE KEY-----`
```

## Notable implementation details
- The only cipher used is 256 bit AES.
- The CBC block cipher mode is OpenSSL (aes-256-cbc) compatible. Both use SHA1 as the hash function.
