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

	// only exists for testing
	iv []byte
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

// Encrypt p before writing to the underlying io.Writer
func (recv *ctrWriter) Write(p []byte) (n int, err error) {
	if recv.stream == nil {
		// create initialization vector
		if recv.iv == nil {
			recv.iv = make([]byte, aes.BlockSize)
			_, err = rand.Read(recv.iv)
			if err != nil {
				return
			}
		}

		var block cipher.Block
		// create stream for subsequent Writes
		block, err = aes.NewCipher(recv.symmetricKey)
		if err != nil {
			return
		}
		recv.stream = cipher.NewCTR(block, recv.iv)

		n, err = recv.writer.Write(recv.iv)
		if err != nil {
			return
		}
	}

	p2 := make([]byte, len(p))
	recv.stream.XORKeyStream(p2, p)
	n, err = recv.writer.Write(p2)
	return
}

func NewCTRReader(symmetricKey []byte, inReader io.Reader) (outReader io.Reader, err error) {

	iv := make([]byte, aes.BlockSize)
	_, err = inReader.Read(iv)
	if err != nil {
		return
	}

	var block cipher.Block
	block, err = aes.NewCipher(symmetricKey)
	if err != nil {
		return
	}

	outReader = cipher.StreamReader{
		S: cipher.NewCTR(block, iv),
		R: inReader,
	}

	return
}
