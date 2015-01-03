package pki

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_CBC_Bijection(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.Nil(t, err)

	privateKey := PrivateKey(*rsaKey)
	publicKey := PublicKey(rsaKey.PublicKey)

	var blobIn []byte
	var blobOut []byte
	var encryptionBlock EncryptionBlock

	// NO PADDING
	blobIn = make([]byte, 96)
	_, err = rand.Reader.Read(blobIn)
	assert.Nil(t, err)

	encryptionBlock, err = publicKey.EncryptCBC(blobIn)
	assert.Nil(t, err)

	blobOut, err = privateKey.DecryptCBC(encryptionBlock)
	assert.Nil(t, err)

	assert.Equal(t, blobIn, blobOut)

	// SOME PADDING
	blobIn = make([]byte, 97)
	_, err = rand.Reader.Read(blobIn)
	assert.Nil(t, err)

	encryptionBlock, err = publicKey.EncryptCBC(blobIn)
	assert.Nil(t, err)

	blobOut, err = privateKey.DecryptCBC(encryptionBlock)
	assert.Nil(t, err)

	assert.Equal(t, blobIn, blobOut)

	// < aes.BlockSize
	blobIn = make([]byte, aes.BlockSize-2)
	_, err = rand.Reader.Read(blobIn)
	assert.Nil(t, err)

	encryptionBlock, err = publicKey.EncryptCBC(blobIn)
	assert.Nil(t, err)

	blobOut, err = privateKey.DecryptCBC(encryptionBlock)
	assert.Nil(t, err)

	assert.Equal(t, blobIn, blobOut)
}
