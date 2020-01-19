# ChaCha in Go

This is an implementation of the ChaCha stream cipher in Go. The Cipher
implements both the `crypto/cipher.Stream` and `io.Reader` interfaces.
It also has a Seek() method for seeking to any part of the keystream in
constant time.

As of Go 1.12, this implementation is about 5x slower than the C version
(GCC and Clang).

## Example

```go
package main

import (
	"io"
	"os"

	"nullprogram.com/x/chacha"
)

func main() {
	var key [32]byte
	var iv [8]byte
        rounds := 20
	c := chacha.New(key[:], iv[:], rounds)
	io.Copy(os.Stdout, c)
}
```
