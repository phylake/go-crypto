package pki

import (
	"io"
)

func (recv *PublicKey) EncryptCTR(inReader io.Reader, xforms []io.ReadWriteCloser) (EncryptionStream, error) {
	return EncryptionStream{}, nil
}
