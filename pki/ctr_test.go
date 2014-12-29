package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"io"
	"math"
	"testing"
)

func TestCTRExample(t *testing.T) {
	t.Parallel()

	key := []byte("example key 1234")
	plaintext := []byte("some plaintext")

	block, err := aes.NewCipher(key)
	assert.Nil(t, err)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	assert.Nil(t, err)

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	plaintext2 := make([]byte, len(plaintext))
	stream = cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext2, ciphertext[aes.BlockSize:])

	assert.Equal(t, plaintext, plaintext2)
}

// the reason to use CTR instead of CBC is it's stream-based so I don't need in
// memory the entire message to be encrypted, making it more suitable for large
// files and easier to fit with an io.Reader pipeline.
func TestIncrementalCTR(t *testing.T) {
	t.Parallel()

	key := []byte("example key 1234")
	plainTextSngl := []byte("some text that's longer than aes.BlockSize and not a multiple of aes.BlockSize")
	plainTextIncr := []byte("some text that's longer than aes.BlockSize and not a multiple of aes.BlockSize")

	blockSngl, _ := aes.NewCipher(key)
	blockIncr, _ := aes.NewCipher(key)
	assert.Equal(t, blockIncr, blockSngl)

	ciphertextSngl := make([]byte, aes.BlockSize+len(plainTextSngl))
	ivSngl := ciphertextSngl[:aes.BlockSize]
	io.ReadFull(rand.Reader, ivSngl)
	ivIncr := dup(ivSngl)

	streamSngl := cipher.NewCTR(blockSngl, ivSngl)
	streamSngl.XORKeyStream(ciphertextSngl[aes.BlockSize:], plainTextSngl)

	streamIncr := cipher.NewCTR(blockIncr, ivIncr)

	ciphertextIncr := make([]byte, 0)
	ciphertextIncr = append(ivIncr, ciphertextIncr...)

	pLen := float64(len(plainTextIncr))
	blocks := int(math.Ceil(pLen / float64(aes.BlockSize)))
	assert.Equal(t, 5, blocks)

	for i := 0; i < blocks; i++ {
		beg := int(math.Min(pLen, float64(aes.BlockSize*(i+0))))
		end := int(math.Min(pLen, float64(aes.BlockSize*(i+1))))
		dst := make([]byte, end-beg)
		src := plainTextIncr[beg:end] // will be a io.Reader.Read(src)

		streamIncr.XORKeyStream(dst, src)
		ciphertextIncr = append(ciphertextIncr, dst...)
	}

	assert.Equal(t, ciphertextSngl, ciphertextIncr)
}

func dup(p []byte) []byte {
	q := make([]byte, len(p))
	copy(q, p)
	return q
}
