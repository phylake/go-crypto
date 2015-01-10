package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// NOTE: the padding used here is custom meaning only an equivalent
// implementation can decrypt this
func EncryptCBC(symmetricKey []byte, inBytes []byte) ([]byte, error) {
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	padLen := aes.BlockSize - len(inBytes)%aes.BlockSize
	padding := make([]byte, padLen)
	_, err = rand.Reader.Read(padding)
	if err != nil {
		return nil, err
	}
	padding[0] = byte(padLen)
	inBytes = append(padding, inBytes...)
	inBytesLen := len(inBytes)
	if inBytesLen%aes.BlockSize != 0 {
		return nil, ErrCBCPad
	}

	ciphertext := make([]byte, aes.BlockSize+inBytesLen)
	initializationVector := ciphertext[:aes.BlockSize]
	_, err = rand.Reader.Read(initializationVector)
	if err != nil {
		return nil, err
	}

	cfb := cipher.NewCBCEncrypter(block, initializationVector)
	cfb.CryptBlocks(ciphertext[aes.BlockSize:], inBytes)

	return ciphertext, nil
}

func DecryptCBC(symmetricKey []byte, inBytes []byte) ([]byte, error) {
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	initializationVector := inBytes[:aes.BlockSize]
	inBytes = inBytes[aes.BlockSize:]
	cfb := cipher.NewCBCDecrypter(block, initializationVector)
	cfb.CryptBlocks(inBytes, inBytes)
	padLen := uint8(inBytes[0])
	inBytes = inBytes[padLen:]
	return inBytes, nil
}
