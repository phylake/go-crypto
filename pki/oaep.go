package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
)

// Produce a base64-encoded RSA-OAEP compatible with OpenSSL
func (recv *PublicKey) Base64EncryptOAEP(inBytes []byte) (string, error) {
	oaepBytes, err := recv.EncryptOAEP(inBytes)
	if err != nil {
		return "", err
	}

	outString := base64.StdEncoding.EncodeToString(oaepBytes)
	return outString, nil
}

// Produce a RSA-OAEP compatible with OpenSSL
func (recv *PublicKey) EncryptOAEP(inBytes []byte) ([]byte, error) {
	key := rsa.PublicKey(*recv)
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, &key, inBytes, []byte(""))
}

func (recv *PrivateKey) Base64DecryptOAEP(inString string) ([]byte, error) {
	oaepBytes, err := base64.StdEncoding.DecodeString(inString)
	if err != nil {
		return nil, err
	}

	return recv.DecryptOAEP(oaepBytes)
}

func (recv *PrivateKey) DecryptOAEP(oaepBytes []byte) ([]byte, error) {
	key := rsa.PrivateKey(*recv.key)
	outBytes, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, &key, oaepBytes, []byte(""))
	if err != nil {
		return nil, err
	}

	return outBytes, nil
}
