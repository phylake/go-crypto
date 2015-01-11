package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
)

// This was easy to misread
//
// "EncryptOAEP encrypts the given message with RSA-OAEP.
//  The message must be no longer than the length of the
//  public modulus less twice the hash length plus 2."
//
// 1024 = length in bits of the public modulus chosen here
// 160 = length in bits of sha1
// max len 86 bytes == 1024/8 - 2 * (160/8 + 2)
func Test_OAEP_Documentation(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.Nil(t, err)

	shouldSucceed := make([]byte, 86)
	shouldFail := make([]byte, 87)

	publicKey := PublicKey(rsaKey.PublicKey)

	_, err = publicKey.EncryptOAEP(shouldSucceed)
	assert.Nil(t, err)

	_, err = publicKey.EncryptOAEP(shouldFail)
	assert.NotNil(t, err)
}

func Test_OAEP_Bijection(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.Nil(t, err)

	msg := []byte("symmetric key")

	privateKey := PrivateKey(*rsaKey)
	publicKey := PublicKey(rsaKey.PublicKey)

	encMsg, err := publicKey.EncryptOAEP(msg)
	assert.Nil(t, err)

	msg2, err := privateKey.DecryptOAEP(encMsg)
	assert.Nil(t, err)
	assert.Equal(t, msg, msg2)
}

func Test_Go_OAEP_OpenSSL_Combatibility(t *testing.T) {
	t.Parallel()

	// -------------------------------------------------------------------------
	// make a private key
	// -------------------------------------------------------------------------
	pk, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.Nil(t, err)

	tmpDir := os.TempDir()

	pemFile, err := ioutil.TempFile(tmpDir, "go-crypto-")
	assert.Nil(t, err)
	defer pemFile.Close()
	defer os.Remove(pemFile.Name())

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk)})

	pemFile.Write(pemBytes)

	// -------------------------------------------------------------------------
	// encrypt a message
	// -------------------------------------------------------------------------
	msg := []byte("symmetric key")
	privateKey := PublicKey(pk.PublicKey)

	encryptedMsg, err := privateKey.Base64EncryptOAEP(msg)
	assert.Nil(t, err)
	assert.NotNil(t, encryptedMsg)

	encryptedMsgFile, err := ioutil.TempFile(tmpDir, "s3fs_")
	assert.Nil(t, err)
	defer encryptedMsgFile.Close()
	defer os.Remove(encryptedMsgFile.Name())
	encryptedMsgFile.Write([]byte(encryptedMsg))

	// -------------------------------------------------------------------------
	// verify encryption with openssl
	// -------------------------------------------------------------------------

	// base64 --decode encrypted_symmetric_key | openssl rsautl -inkey private-key -decrypt -oaep
	cmdBase64 := exec.Command("base64", "--decode", encryptedMsgFile.Name())
	cmdOpenSSL := exec.Command("openssl", "rsautl", "-inkey", pemFile.Name(), "-decrypt", "-oaep")

	var opensslOut bytes.Buffer
	var opensslErr bytes.Buffer
	var base64Err bytes.Buffer

	base64Out, err := cmdBase64.StdoutPipe()
	assert.Nil(t, err)

	cmdBase64.Stderr = &base64Err
	cmdOpenSSL.Stdin = base64Out
	cmdOpenSSL.Stdout = &opensslOut
	cmdOpenSSL.Stderr = &opensslErr

	err = cmdBase64.Start()
	assert.Nil(t, err)

	err = cmdOpenSSL.Start()
	assert.Nil(t, err)

	cmdBase64.Wait()
	assert.Equal(t, "", base64Err.String())

	cmdOpenSSL.Wait()
	assert.Equal(t, "", opensslErr.String())

	// the message encrypted in go can be decrypted in openssl
	assert.Equal(t, msg, opensslOut.String())
}
