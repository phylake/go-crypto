package pki

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
)

type PublicKey rsa.PublicKey
type PrivateKey rsa.PrivateKey

type EncryptionBlock struct {
	encryptedSymmetricKey string
	blob                  []byte
}

type EncryptionStream struct {
	encryptedSymmetricKey string

	fileLocal  io.ReadCloser
	fileRemote io.Reader
	xforms     []io.ReadWriteCloser
}

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

func (recv *EncryptionStream) Read(p []byte) (n int, err error) {
	return 0, nil
}

func (recv *EncryptionStream) Close() error {
	var err error
	err = recv.fileLocal.Close()
	if err != nil {
		return err
	}

	return nil
}
