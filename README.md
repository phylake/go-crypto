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
    rsaKey := generateKey()
    // or use your own
    // rsaKey, _ := pki.ParsePrivateKey([]byte(my1024BitPrivateKey))

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

func generateKey() *rsa.PrivateKey {
    rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
    if err != nil {
        panic(err)
    }
    return rsaKey
}

// checkout https://gist.github.com/phylake/7392335 for relevant OpenSSL commands
var my1024BitPrivateKey string = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC9LZm1sJyNhzngpksZANJlctbX1pyuTiBYGCilexQjNBkXIF5W
qfsTFdxj/8dJ4vMZ+eJd1QONJQTdmSZL6+0BvcbLnrzNVMck+tBS4tYOQ2qUMsh7
MjmXbq2sjTCz0zF8vsu6YCtJukmRNfrw82mX5YcY6aNU52TZpHd3SXljMQIDAQAB
AoGAOWz8OfEQtM2VviH8rexX8b+4g/B7w1Wn79X1kLYZ2M3Zx/Flcb1Ln/GE4z4j
isQ/s2TtWDpvR4szPOlefLFzUgunoaKXln1f3j2lWsoPBcMTjye7CfCy4fOpt27T
2zxvBmZ1+RJFOrGjGAvPr2+7WHJcuiUr9w1RQqE76gFLrAECQQD0bzr1qm/zihqE
/YaUvSC0Parn8Ult3OfG0OAO8P6xQFZyAu9fH5ev14SwoRnuGNHmV4ZUQabyLJEV
x1JUWP0RAkEAxiEQhBk481BL8J30pD1SUObuWIelvRgDV+3zbOLMXmtPQM/m+fbc
wIiFV3dlHnMuQj1i8l2i0sE6PdfQX0SEIQJAOa4ZwqjyfAzFz0YoQOcUVZQLxWnp
wvQS+ZaGmOADqf4dqA/LPq4s1EDOPgP2I3pV5b4Xo8BOTe14WyRK6D6LkQJBALzt
OI+OcZTqg49tP6QBaWYF30+CAdP/eui02UOCPPjoAMm/tfOzp6rcQ7I1ArJ3iKvX
V2vfR+0KHlxsV6EQd6ECQDwV4RnZ8VI02XIpWfBABsQyXDyEcTOe+OvGmEUaTA3Z
RDAdfMAPcBg1kMCDBFRue0oET9BTNQjoVuOSgt/W5vQ=
-----END RSA PRIVATE KEY-----`

```

## Notable implementation details
- The only cipher used is 256 bit AES.
- The CBC block cipher mode is OpenSSL (aes-256-cbc) compatible. Both use SHA1 as the hash function.
