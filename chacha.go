// This is free and unencumbered software released into the public domain.

// Package chacha implements the ChaCha stream cipher.
package chacha

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

// avail replaced with nextByte by Ron Charlton, public domain 2022-09-06,
// a 25 percentage point speedup.

// Cipher is an instance of the ChaCha stream cipher. It implements both
// the io.Reader and crypto/cipher.Stream interfaces.
type Cipher struct {
	input    [16]uint32
	output   [64]byte
	nextByte int
	rounds   int
	eof      bool
}

var _ cipher.Stream = (*Cipher)(nil)
var _ io.Reader = (*Cipher)(nil)

// New returns an initialized instance of a new ChaCha cipher. A ChaCha
// key is 32 bytes and a ChaCha IV is 8 bytes, so len(key) must be >= 32
// and len(iv) must be >= 8. Rounds should be one of 8, 12, or 20.
func New(key, iv []byte, rounds int) *Cipher {
	c := new(Cipher)
	c.input[0] = 0x61707865 // "expand 32-byte k"
	c.input[1] = 0x3320646e //
	c.input[2] = 0x79622d32 //
	c.input[3] = 0x6b206574 //
	c.input[4] = binary.LittleEndian.Uint32(key[0:])
	c.input[5] = binary.LittleEndian.Uint32(key[4:])
	c.input[6] = binary.LittleEndian.Uint32(key[8:])
	c.input[7] = binary.LittleEndian.Uint32(key[12:])
	c.input[8] = binary.LittleEndian.Uint32(key[16:])
	c.input[9] = binary.LittleEndian.Uint32(key[20:])
	c.input[10] = binary.LittleEndian.Uint32(key[24:])
	c.input[11] = binary.LittleEndian.Uint32(key[28:])
	c.input[14] = binary.LittleEndian.Uint32(iv[0:])
	c.input[15] = binary.LittleEndian.Uint32(iv[4:])
	c.rounds = rounds
	c.nextByte = len(c.output)
	return c
}

// Fills the output field with the next block and sets avail accordingly.
func (c *Cipher) next() error {
	if c.eof {
		return errors.New("exhausted keystream")
	}

	var x [16]uint32 // work space
	for i := 0; i < 16; i++ {
		x[i] = c.input[i]
	}
	for i := c.rounds; i > 0; i -= 2 {
		// explicit manipulation of x inserted by Ron Charlton, public
		// domain 2022-09-06. 37% speedup.
		x[0] = x[0] + x[4]
		x[12] = ((x[12] ^ x[0]) << 16) | ((x[12] ^ x[0]) >> (32 - 16))
		x[8] = x[8] + x[12]
		x[4] = ((x[4] ^ x[8]) << 12) | ((x[4] ^ x[8]) >> (32 - 12))
		x[0] = x[0] + x[4]
		x[12] = ((x[12] ^ x[0]) << 8) | ((x[12] ^ x[0]) >> (32 - 8))
		x[8] = x[8] + x[12]
		x[4] = ((x[4] ^ x[8]) << 7) | ((x[4] ^ x[8]) >> (32 - 7))

		x[1] = x[1] + x[5]
		x[13] = ((x[13] ^ x[1]) << 16) | ((x[13] ^ x[1]) >> (32 - 16))
		x[9] = x[9] + x[13]
		x[5] = ((x[5] ^ x[9]) << 12) | ((x[5] ^ x[9]) >> (32 - 12))
		x[1] = x[1] + x[5]
		x[13] = ((x[13] ^ x[1]) << 8) | ((x[13] ^ x[1]) >> (32 - 8))
		x[9] = x[9] + x[13]
		x[5] = ((x[5] ^ x[9]) << 7) | ((x[5] ^ x[9]) >> (32 - 7))

		x[2] = x[2] + x[6]
		x[14] = ((x[14] ^ x[2]) << 16) | ((x[14] ^ x[2]) >> (32 - 16))
		x[10] = x[10] + x[14]
		x[6] = ((x[6] ^ x[10]) << 12) | ((x[6] ^ x[10]) >> (32 - 12))
		x[2] = x[2] + x[6]
		x[14] = ((x[14] ^ x[2]) << 8) | ((x[14] ^ x[2]) >> (32 - 8))
		x[10] = x[10] + x[14]
		x[6] = ((x[6] ^ x[10]) << 7) | ((x[6] ^ x[10]) >> (32 - 7))

		x[3] = x[3] + x[7]
		x[15] = ((x[15] ^ x[3]) << 16) | ((x[15] ^ x[3]) >> (32 - 16))
		x[11] = x[11] + x[15]
		x[7] = ((x[7] ^ x[11]) << 12) | ((x[7] ^ x[11]) >> (32 - 12))
		x[3] = x[3] + x[7]
		x[15] = ((x[15] ^ x[3]) << 8) | ((x[15] ^ x[3]) >> (32 - 8))
		x[11] = x[11] + x[15]
		x[7] = ((x[7] ^ x[11]) << 7) | ((x[7] ^ x[11]) >> (32 - 7))

		x[0] = x[0] + x[5]
		x[15] = ((x[15] ^ x[0]) << 16) | ((x[15] ^ x[0]) >> (32 - 16))
		x[10] = x[10] + x[15]
		x[5] = ((x[5] ^ x[10]) << 12) | ((x[5] ^ x[10]) >> (32 - 12))
		x[0] = x[0] + x[5]
		x[15] = ((x[15] ^ x[0]) << 8) | ((x[15] ^ x[0]) >> (32 - 8))
		x[10] = x[10] + x[15]
		x[5] = ((x[5] ^ x[10]) << 7) | ((x[5] ^ x[10]) >> (32 - 7))

		x[1] = x[1] + x[6]
		x[12] = ((x[12] ^ x[1]) << 16) | ((x[12] ^ x[1]) >> (32 - 16))
		x[11] = x[11] + x[12]
		x[6] = ((x[6] ^ x[11]) << 12) | ((x[6] ^ x[11]) >> (32 - 12))
		x[1] = x[1] + x[6]
		x[12] = ((x[12] ^ x[1]) << 8) | ((x[12] ^ x[1]) >> (32 - 8))
		x[11] = x[11] + x[12]
		x[6] = ((x[6] ^ x[11]) << 7) | ((x[6] ^ x[11]) >> (32 - 7))

		x[2] = x[2] + x[7]
		x[13] = ((x[13] ^ x[2]) << 16) | ((x[13] ^ x[2]) >> (32 - 16))
		x[8] = x[8] + x[13]
		x[7] = ((x[7] ^ x[8]) << 12) | ((x[7] ^ x[8]) >> (32 - 12))
		x[2] = x[2] + x[7]
		x[13] = ((x[13] ^ x[2]) << 8) | ((x[13] ^ x[2]) >> (32 - 8))
		x[8] = x[8] + x[13]
		x[7] = ((x[7] ^ x[8]) << 7) | ((x[7] ^ x[8]) >> (32 - 7))

		x[3] = x[3] + x[4]
		x[14] = ((x[14] ^ x[3]) << 16) | ((x[14] ^ x[3]) >> (32 - 16))
		x[9] = x[9] + x[14]
		x[4] = ((x[4] ^ x[9]) << 12) | ((x[4] ^ x[9]) >> (32 - 12))
		x[3] = x[3] + x[4]
		x[14] = ((x[14] ^ x[3]) << 8) | ((x[14] ^ x[3]) >> (32 - 8))
		x[9] = x[9] + x[14]
		x[4] = ((x[4] ^ x[9]) << 7) | ((x[4] ^ x[9]) >> (32 - 7))
	}
	for i := 0; i < 16; i++ {
		x[i] += c.input[i]
		binary.LittleEndian.PutUint32(c.output[i*4:], x[i])
	}

	// Update block counter
	ctr := (uint64(c.input[13])<<32 | uint64(c.input[12])) + 1
	if ctr == 0 {
		c.eof = true
	}
	c.input[12] = uint32(ctr)
	c.input[13] = uint32(ctr >> 32)

	c.nextByte = 0
	return nil
}

// Seek sets the cipher's internal stream position to the nth 64-byte
// block. For example, Seek(0) sets the cipher back to its initial
// state.
func (c *Cipher) Seek(n uint64) {
	c.input[12] = uint32(n)
	c.input[13] = uint32(n >> 32)
	c.eof = false
	c.next() // always succeeds
}

// Read implements io.Reader.Read(). After 2^70 bytes of output the
// keystream will be exhausted and this function will return the io.EOF
// error. There are no other error conditions.
func (c *Cipher) Read(p []byte) (int, error) {
	n := 0
	for ; n < len(p); n++ {
		if c.nextByte >= len(c.output) {
			if err := c.next(); err != nil {
				return n, io.EOF
			}
			c.nextByte = 0
		}
		p[n] = c.output[c.nextByte]
		c.nextByte++
	}
	return n, nil
}

// XORKeyStream implements crypto/cipher.Cipher. It will panic when the
// keystream has been exhausted.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(dst); i++ {
		if c.nextByte >= len(c.output) {
			if err := c.next(); err != nil {
				panic(err)
			}
			c.nextByte = 0
		}
		dst[i] = src[i] ^ c.output[c.nextByte]
		c.nextByte++
	}
}
