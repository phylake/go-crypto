package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
)

// Produce a base64-encoded RSA-OAEP compatible with OpenSSL
func (recv *PublicKey) EncryptOAEP(inBytes []byte) (string, error) {
	key := rsa.PublicKey(*recv)
	oaepBytes, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key, inBytes, []byte(""))
	if err != nil {
		return "", err
	}

	outString := base64.StdEncoding.EncodeToString(oaepBytes)
	return outString, nil
}

func (recv *PrivateKey) DecryptOAEP(inString string) ([]byte, error) {
	oaepBytes, err := base64.StdEncoding.DecodeString(inString)
	if err != nil {
		return nil, err
	}

	key := rsa.PrivateKey(*recv)
	outBytes, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, &key, oaepBytes, []byte(""))
	if err != nil {
		return nil, err
	}

	return []byte(outBytes), nil
}
