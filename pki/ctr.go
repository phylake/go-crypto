package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type ctrWriter struct {
	unencryptedKey []byte

	stream cipher.Stream

	writer io.Writer
}

type ctrReader struct {
	iv []byte

	stream cipher.Stream

	reader io.Reader
}

func NewCTRWriter(unencryptedKey []byte, encryptedData io.Writer) io.Writer {
	ret := &ctrWriter{}
	ret.unencryptedKey = unencryptedKey
	ret.writer = encryptedData
	return ret
}

func NewCTRReader(unencryptedKey []byte, unencryptedData io.Reader) (io.Reader, error) {
	iv := make([]byte, aes.BlockSize)
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}

	return newCTRReaderWithVector(unencryptedKey, unencryptedData, iv)
}

func newCTRReaderWithVector(unencryptedKey []byte, unencryptedData io.Reader, iv []byte) (io.Reader, error) {
	block, err := aes.NewCipher(unencryptedKey)
	if err != nil {
		return nil, err
	}

	ret := &ctrReader{}
	ret.iv = iv
	ret.stream = cipher.NewCTR(block, iv)
	ret.reader = unencryptedData
	return ret, nil
}

func (recv *ctrWriter) Write(p []byte) (n int, err error) {
	if recv.stream == nil {
		if len(p) < aes.BlockSize {
			return 0, io.ErrShortBuffer
		}

		block, err := aes.NewCipher(recv.unencryptedKey)
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
	n2, err2 := recv.reader.Read(p2)
	if err2 != nil {
		return n2, err2
	}

	recv.stream.XORKeyStream(p[n:], p2)
	return n + n2, nil
}
