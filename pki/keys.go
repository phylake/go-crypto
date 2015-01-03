package pki

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type PublicKey rsa.PublicKey
type PrivateKey rsa.PrivateKey

func ParsePrivateKey(bytes []byte) (*PrivateKey, error) {
	pemBlock, _ := pem.Decode(bytes)
	if pemBlock == nil {
		return nil, ErrNotPEM
	}

	block, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	key := PrivateKey(*block)
	return &key, nil
}
