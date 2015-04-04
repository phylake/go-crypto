package cipher

import (
	"crypto/aes"
	"crypto/rand"
	"github.com/phylake/go-crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_CBC_Bijection(t *testing.T) {
	t.Parallel()

	var blobIn []byte
	var blobOut []byte
	var blobEnc []byte
	var err error

	randomKey, err := crypto.RandomAES256Key()
	assert.Nil(t, err)

	// NO PADDING
	blobIn = make([]byte, 96)
	_, err = rand.Reader.Read(blobIn)
	assert.Nil(t, err)

	blobEnc, err = EncryptCBC(randomKey, blobIn)
	assert.Nil(t, err)

	blobOut, err = DecryptCBC(randomKey, blobEnc)
	assert.Nil(t, err)

	assert.Equal(t, blobOut, blobIn)

	// SOME PADDING
	blobIn = make([]byte, 97)
	_, err = rand.Reader.Read(blobIn)
	assert.Nil(t, err)

	blobEnc, err = EncryptCBC(randomKey, blobIn)
	assert.Nil(t, err)

	blobOut, err = DecryptCBC(randomKey, blobEnc)
	assert.Nil(t, err)

	assert.Equal(t, blobOut, blobIn)

	// < aes.BlockSize
	blobIn = make([]byte, aes.BlockSize-2)
	_, err = rand.Reader.Read(blobIn)
	assert.Nil(t, err)

	blobEnc, err = EncryptCBC(randomKey, blobIn)
	assert.Nil(t, err)

	blobOut, err = DecryptCBC(randomKey, blobEnc)
	assert.Nil(t, err)

	assert.Equal(t, blobOut, blobIn)
}
