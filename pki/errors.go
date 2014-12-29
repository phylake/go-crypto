package pki

import (
	"errors"
)

var ErrCBCPad = errors.New("inBytes not a multiple of aes.BlockSize")
var ErrNotPEM = errors.New("not a PEM")
