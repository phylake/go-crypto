package pki

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/phylake/go-crypto"
)

type PublicKey rsa.PublicKey
type PrivateKey struct {
	key       *rsa.PrivateKey
	PublicKey *PublicKey
}

func ParsePrivateKey(bytes []byte) (*PrivateKey, error) {
	pemBlock, _ := pem.Decode(bytes)
	if pemBlock == nil {
		return nil, crypto.ErrNotPEM
	}

	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return NewPrivateKey(*rsaPrivateKey), nil
}

func NewPrivateKey(rsaPrivateKey rsa.PrivateKey) *PrivateKey {
	publicKey := PublicKey(rsaPrivateKey.PublicKey)

	privateKey := &PrivateKey{
		key:       &rsaPrivateKey,
		PublicKey: &publicKey,
	}
	return privateKey
}
