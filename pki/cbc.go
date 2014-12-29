package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func (recv *PublicKey) EncryptCBC(inBytes []byte) (EncryptionBlock, error) {
	symmetricKey := make([]byte, AESByteLen)
	_, err := rand.Reader.Read(symmetricKey)
	if err != nil {
		return EncryptionBlock{}, err
	}

	encryptedSymmetricKey, err := recv.EncryptOAEP(symmetricKey)
	if err != nil {
		return EncryptionBlock{}, err
	}

	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return EncryptionBlock{}, err
	}

	padLen := aes.BlockSize - len(inBytes)%aes.BlockSize
	padding := make([]byte, padLen)
	padding[0] = byte(padLen)
	inBytes = append(padding, inBytes...)
	inBytesLen := len(inBytes)
	if inBytesLen%aes.BlockSize != 0 {
		return EncryptionBlock{}, ErrCBCPad
	}

	ciphertext := make([]byte, aes.BlockSize+inBytesLen)
	initializationVector := ciphertext[:aes.BlockSize]
	_, err = rand.Reader.Read(initializationVector)
	if err != nil {
		return EncryptionBlock{}, err
	}

	cfb := cipher.NewCBCEncrypter(block, initializationVector)
	cfb.CryptBlocks(ciphertext[aes.BlockSize:], inBytes)

	result := EncryptionBlock{
		encryptedSymmetricKey: encryptedSymmetricKey,
		blob: ciphertext}
	return result, nil
}

func (recv *PrivateKey) DecryptCBC(bundle EncryptionBlock) ([]byte, error) {
	symmetricKey, err := recv.DecryptOAEP(bundle.encryptedSymmetricKey)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	var blob []byte
	blob = bundle.blob
	initializationVector := blob[:aes.BlockSize]
	blob = blob[aes.BlockSize:]
	cfb := cipher.NewCBCDecrypter(block, initializationVector)
	cfb.CryptBlocks(blob, blob)
	padLen := uint8(blob[0])
	blob = blob[padLen:]
	return blob, nil
}
