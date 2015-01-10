package crypto

import (
	"crypto/rand"
)

func RandomAES256Key() ([]byte, error) {
	randomKey := make([]byte, AES256Bytes)
	_, err := rand.Reader.Read(randomKey)
	if err != nil {
		return nil, err
	}
	return randomKey, nil
}
