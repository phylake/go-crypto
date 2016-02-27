package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type ctr struct {
	symmetricKey []byte

	stream cipher.Stream
}

type ctrWriter struct {
	ctr

	writer io.Writer

	// only exists for testing
	iv []byte
}

type ctrReader struct {
	ctr

	reader io.Reader
}

func NewCTRWriter(symmetricKey []byte, reader io.Writer) io.Writer {
	ret := &ctrWriter{}
	ret.symmetricKey = symmetricKey
	ret.writer = reader
	return ret
}

func newCTRWriterWithVector(symmetricKey []byte, writer io.Writer, iv []byte) io.Writer {
	ret := &ctrWriter{}
	ret.symmetricKey = symmetricKey
	ret.writer = writer
	ret.iv = iv
	return ret
}

func NewCTRReader(symmetricKey []byte, reader io.Reader) io.Reader {
	ret := &ctrReader{}
	ret.symmetricKey = symmetricKey
	ret.reader = reader
	return ret
}

// Read from the underlying io.Reader and decrypt the bytes into p
func (recv *ctrReader) Read(p []byte) (int, error) {
	if recv.stream == nil {
		if len(p) < aes.BlockSize {
			return 0, io.ErrShortBuffer
		}

		iv := make([]byte, aes.BlockSize)
		_, err := recv.reader.Read(iv)
		if err != nil {
			return 0, err
		}

		block, err := aes.NewCipher(recv.symmetricKey)
		if err != nil {
			return 0, err
		}

		recv.stream = cipher.NewCTR(block, iv)
	}

	p2 := make([]byte, len(p))
	n, err := recv.reader.Read(p2)
	if err != nil {
		return n, err
	}

	recv.stream.XORKeyStream(p, p2)

	return n, err
}

// Encrypt p before writing to the underlying io.Writer
func (recv *ctrWriter) Write(p []byte) (int, error) {
	if recv.stream == nil {
		// create initialization vector
		if recv.iv == nil {
			recv.iv = make([]byte, aes.BlockSize)
			_, err := io.ReadFull(rand.Reader, recv.iv)
			if err != nil {
				return 0, err
			}
		}

		// create stream for subsequent Writes
		block, err := aes.NewCipher(recv.symmetricKey)
		if err != nil {
			return 0, err
		}
		recv.stream = cipher.NewCTR(block, recv.iv)

		_, err = recv.writer.Write(recv.iv)
		if err != nil {
			return 0, err
		}
	}

	p2 := make([]byte, len(p))
	recv.stream.XORKeyStream(p2, p)
	return recv.writer.Write(p2)
}
