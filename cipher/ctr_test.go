package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/phylake/go-crypto"
	"github.com/stretchr/testify/assert"
	"io"
	"io/ioutil"
	"math"
	"testing"
)

func Test_CTR_Bijection_Random_Bits(t *testing.T) {
	t.Parallel()

	plaintextIn := make([]byte, 123)
	_, err := io.ReadFull(rand.Reader, plaintextIn)
	assert.Nil(t, err)

	plaintextOut := make([]byte, 123)
	assert.NotEqual(t, plaintextOut, plaintextIn)

	randomKey, err := crypto.RandomAES256Key()
	assert.Nil(t, err)

	var ciphertext bytes.Buffer
	ctrWriter := NewCTRWriter(randomKey, &ciphertext)
	ctrWriter.Write(plaintextIn)

	ctrReader, err := NewCTRReader(randomKey, &ciphertext)
	assert.Nil(t, err)

	ctrReader.Read(plaintextOut)

	assert.Equal(t, plaintextOut, plaintextIn)
}

func Test_CTR_Bijection_Short_Key(t *testing.T) {
	t.Parallel()

	plaintextIn := make([]byte, 123)
	_, err := io.ReadFull(rand.Reader, plaintextIn)
	assert.Nil(t, err)

	plaintextOut := make([]byte, 123)
	assert.NotEqual(t, plaintextOut, plaintextIn)

	key := []byte("example key 1234")

	var ciphertext bytes.Buffer
	ctrWriter := NewCTRWriter(key, &ciphertext)
	ctrWriter.Write(plaintextIn)

	ctrReader, err := NewCTRReader(key, &ciphertext)
	assert.Nil(t, err)

	ctrReader.Read(plaintextOut)

	assert.Equal(t, plaintextOut, plaintextIn)
}

func Test_CTR_Bijection_Multiple_Writes_And_ReadAll(t *testing.T) {
	t.Parallel()

	plaintextIn1 := make([]byte, 50)
	plaintextIn2 := make([]byte, 50)
	_, err := io.ReadFull(rand.Reader, plaintextIn1)
	assert.Nil(t, err)
	_, err = io.ReadFull(rand.Reader, plaintextIn2)
	assert.Nil(t, err)

	key := []byte("example key 1234")

	var ciphertext bytes.Buffer
	ctrWriter := NewCTRWriter(key, &ciphertext)
	ctrWriter.Write(plaintextIn1)
	ctrWriter.Write(plaintextIn2)

	ctrReader, err := NewCTRReader(key, &ciphertext)
	assert.Nil(t, err)

	plaintextOut, err := ioutil.ReadAll(ctrReader)
	assert.Nil(t, err)

	plaintextIn := append(plaintextIn1, plaintextIn2...)
	assert.Equal(t, plaintextOut, plaintextIn)
}

func TestCTRExampleAndCTRReaderProduceSameResult(t *testing.T) {
	t.Parallel()

	key := []byte("example key 1234")
	plaintext := []byte("some plaintext")

	block, err := aes.NewCipher(key)
	assert.Nil(t, err)

	ciphertext1 := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext1[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	assert.Nil(t, err)

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext1[aes.BlockSize:], plaintext)

	var ciphertext2 bytes.Buffer
	ctrWriter := newCTRWriterWithVector(key, &ciphertext2, iv)
	_, err = ctrWriter.Write(plaintext)
	assert.Nil(t, err)
	assert.Equal(t, ciphertext2.Bytes(), ciphertext1)
}

//------------------------------------------------------------------------------
// Testing assumptions about CTR below this line
//------------------------------------------------------------------------------

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

	assert.Equal(t, plaintext2, plaintext)
}

// I wasn't sure if multiple calls to XORKeyStream where
// len(dst) < aes.BlockSize would work
func TestCTRHandlesMultipleByteSlicesSmallerThanAESBlockSize(t *testing.T) {
	t.Parallel()

	key := []byte("example key 1234")
	plaintext := []byte("some plaintext")

	block, _ := aes.NewCipher(key)

	ciphertext1 := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext1[:aes.BlockSize]
	io.ReadFull(rand.Reader, iv)
	ciphertext2 := dup(ciphertext1)

	stream1 := cipher.NewCTR(block, iv)
	stream1.XORKeyStream(ciphertext1[aes.BlockSize:], plaintext)

	mid := 6
	stream2 := cipher.NewCTR(block, iv)
	stream2.XORKeyStream(ciphertext2[aes.BlockSize:aes.BlockSize+mid], plaintext[:mid])
	stream2.XORKeyStream(ciphertext2[aes.BlockSize+mid:], plaintext[mid:])

	assert.Equal(t, ciphertext2, ciphertext1)
}

// the reason to use CTR instead of CBC is it's stream-based so you don't need
// in memory the entire message to be encrypted, making it more suitable for
// large files and easier to fit with an io.Reader pipeline.
func TestIncrementalCTR(t *testing.T) {
	t.Parallel()

	key := []byte("example key 1234")
	plainTextSngl := []byte("some text that's longer than aes.BlockSize and not a multiple of aes.BlockSize")
	plainTextIncr := []byte("some text that's longer than aes.BlockSize and not a multiple of aes.BlockSize")

	blockSngl, _ := aes.NewCipher(key)
	blockIncr, _ := aes.NewCipher(key)
	assert.Equal(t, blockSngl, blockIncr)

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
	assert.Equal(t, blocks, 5)

	for i := 0; i < blocks; i++ {
		beg := int(math.Min(pLen, float64(aes.BlockSize*(i+0))))
		end := int(math.Min(pLen, float64(aes.BlockSize*(i+1))))
		dst := make([]byte, end-beg)
		src := plainTextIncr[beg:end] // will be a io.Reader.Read(src)

		// the point of the test: to see if multiple calls to XORKeyStream
		// work the same as a single call
		streamIncr.XORKeyStream(dst, src)
		ciphertextIncr = append(ciphertextIncr, dst...)
	}

	assert.Equal(t, ciphertextIncr, ciphertextSngl)
}

func dup(p []byte) []byte {
	q := make([]byte, len(p))
	copy(q, p)
	return q
}
