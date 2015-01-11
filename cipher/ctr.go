package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type ctrWriter struct {
	symmetricKey []byte

	stream cipher.Stream

	writer io.Writer
}

type ctrReader struct {
	iv []byte

	stream cipher.Stream

	reader io.Reader
}

func NewCTRWriter(symmetricKey []byte, encryptedData io.Writer) io.Writer {
	ret := &ctrWriter{}
	ret.symmetricKey = symmetricKey
	ret.writer = encryptedData
	return ret
}

func NewCTRReader(symmetricKey []byte, unencryptedData io.Reader) (io.Reader, error) {
	iv := make([]byte, aes.BlockSize)
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}

	return newCTRReaderWithVector(symmetricKey, unencryptedData, iv)
}

func newCTRReaderWithVector(symmetricKey []byte, unencryptedData io.Reader, iv []byte) (io.Reader, error) {
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	ret := &ctrReader{}
	ret.iv = iv
	ret.stream = cipher.NewCTR(block, iv)
	ret.reader = unencryptedData
	return ret, nil
}

// Decrypt p and Write into the underlying io.Writer
func (recv *ctrWriter) Write(p []byte) (n int, err error) {
	if recv.stream == nil {
		if len(p) < aes.BlockSize {
			return 0, io.ErrShortBuffer
		}

		block, err := aes.NewCipher(recv.symmetricKey)
		if err != nil {
			return 0, err
		}

		iv := p[:aes.BlockSize]
		recv.stream = cipher.NewCTR(block, iv)
		n += aes.BlockSize
	}

	p2 := make([]byte, len(p)-n)
	recv.stream.XORKeyStream(p2, p[n:])
	n2, err := recv.writer.Write(p2)
	if err != nil {
		return n2, err
	}

	return n + n2, nil
}

// Read from the underlying io.Reader and encrypt the bytes into p
func (recv *ctrReader) Read(p []byte) (n int, err error) {
	if recv.iv != nil {
		if len(p) < aes.BlockSize {
			return 0, io.ErrShortBuffer
		}
		copy(p, recv.iv)
		n += aes.BlockSize
		recv.iv = nil
	}

	p2 := make([]byte, len(p)-n)
	n2, err := recv.reader.Read(p2)
	if err != nil {
		return n2, err
	}

	recv.stream.XORKeyStream(p[n:], p2)
	return n + n2, nil
}
