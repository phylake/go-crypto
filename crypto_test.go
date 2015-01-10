package crypto

import (
	"crypto/aes"
	"github.com/stretchr/testify/assert"
	"testing"
)

// some logic depends on this value
func TestAESBlockSize(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 16, aes.BlockSize)
}
