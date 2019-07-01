// This is free and unencumbered software released into the public domain.

// Package chacha implements the ChaCha stream cipher.
package chacha

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

var littleEndian = binary.LittleEndian

// Cipher is an instance of the ChaCha stream cipher. It implements both
// the io.Reader and crypto/cipher.Stream interfaces.
type Cipher struct {
	input  [16]uint32
	output [64]byte
	avail  []byte
	rounds int
	eof    bool
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
	c.input[4] = littleEndian.Uint32(key[0:])
	c.input[5] = littleEndian.Uint32(key[4:])
	c.input[6] = littleEndian.Uint32(key[8:])
	c.input[7] = littleEndian.Uint32(key[12:])
	c.input[8] = littleEndian.Uint32(key[16:])
	c.input[9] = littleEndian.Uint32(key[20:])
	c.input[10] = littleEndian.Uint32(key[24:])
	c.input[11] = littleEndian.Uint32(key[28:])
	c.input[14] = littleEndian.Uint32(iv[0:])
	c.input[15] = littleEndian.Uint32(iv[4:])
	c.rounds = rounds
	return c
}

func rotate(v uint32, n uint) uint32 {
	return v<<n | v>>(32-n)
}

func quarterround(x *[16]uint32, a, b, c, d int) {
	x[a] += x[b]
	x[d] = rotate(x[d]^x[a], 16)
	x[c] += x[d]
	x[b] = rotate(x[b]^x[c], 12)
	x[a] += x[b]
	x[d] = rotate(x[d]^x[a], 8)
	x[c] += x[d]
	x[b] = rotate(x[b]^x[c], 7)
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
		quarterround(&x, 0, 4, 8, 12)
		quarterround(&x, 1, 5, 9, 13)
		quarterround(&x, 2, 6, 10, 14)
		quarterround(&x, 3, 7, 11, 15)
		quarterround(&x, 0, 5, 10, 15)
		quarterround(&x, 1, 6, 11, 12)
		quarterround(&x, 2, 7, 8, 13)
		quarterround(&x, 3, 4, 9, 14)
	}
	for i := 0; i < 16; i++ {
		x[i] += c.input[i]
	}
	for i := 0; i < 16; i++ {
		littleEndian.PutUint32(c.output[i*4:], x[i])
	}

	// Update block counter
	ctr := (uint64(c.input[13])<<32 | uint64(c.input[12])) + 1
	if ctr == 0 {
		c.eof = true
	}
	c.input[12] = uint32(ctr)
	c.input[13] = uint32(ctr >> 32)

	c.avail = c.output[:]
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
		if len(c.avail) == 0 {
			if err := c.next(); err != nil {
				return n, io.EOF
			}
		}
		p[n] = c.avail[0]
		c.avail = c.avail[1:] // this is probably slow?
	}
	return n, nil
}

// XORKeyStream implements crypto/cipher.Cipher. It will panic when the
// keystream has been exhausted.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(dst); i++ {
		if len(c.avail) == 0 {
			if err := c.next(); err != nil {
				panic(err)
			}
		}
		dst[i] = src[i] ^ c.avail[0]
		c.avail = c.avail[1:] // this is probably slow?
	}
}
