package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const blocks = 4094
const aesBlockSize = 16
const chunkSize = aesBlockSize * blocks
const nonceSize = 12
const tagSize = 16

// NewWriter wraps w with a writer that encrypts all writes with key using AES-GCM.
func NewWriter(w io.Writer, key Key) *Writer {
	return &Writer{
		w:   w,
		key: key,
	}
}

type Writer struct {
	w   io.Writer
	key Key

	pos   int // pos is the cursor position in the pending chunk
	chunk [chunkSize]byte

	closed bool
}

/*
cases:
write less than chunk size on new chunk
write less than chunk size on existing chunk
write more than chunk size on new chunk
write more than chunk size on existing chunk
write to an exactly full chunk with zero bytes

only call  flush when the chunk is full or the writer is being closed

*/
// Callers must call Close or the final chunk will not be written to w.
func (w *Writer) Write(p []byte) (n int, err error) {

	if w.closed {
		return 0, errors.New("call to write on closed writer")
	}

	for len(p) > 0 {
		nn := copy(w.chunk[w.pos:], p)
		w.pos += nn
		p = p[nn:]
		// if no bytes were nn that means the chunk is full
		if w.pos == len(w.chunk) {
			if err = w.flush(); err != nil {
				return n, err
			}
		}
		// don't increase n until after the chunk has been flushed
		n += nn
	}
	return n, err
}

// func (w *Writer) Seek(offset int64, whence int) (int64, error){}

func (w *Writer) Close() error {
	// The final chunk is likely to be smaller than the chunk size,
	// so more writes would result in decoding errors.
	w.closed = true
	return w.flush()
}

func (w *Writer) flush() error {
	if w.pos == 0 {
		return nil
	}
	defer func() { w.pos = 0 }()

	ciphertext, err := encrypt(w.chunk[:w.pos], w.key)
	if err != nil {
		return err
	}
	written, err := w.w.Write(ciphertext)
	if err != nil {
		return err
	}
	if written != len(ciphertext) {
		// is this redundant?
		return errors.New("write size mismatch")
	}
	return nil
}

// encrypt encrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func encrypt(plaintext []byte, key Key) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}
func NewReader(r io.Reader, key Key) *Reader {
	return &Reader{
		r:   r,
		key: key,
	}
}

type Reader struct {
	r   io.Reader
	key Key

	plaintext []byte

	err error
}

func (r *Reader) Read(p []byte) (n int, err error) {

	if len(r.plaintext) > 0 {
		n = copy(p, r.plaintext)
		r.plaintext = r.plaintext[n:]
		return n, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	tmp := make([]byte, nonceSize+chunkSize+tagSize)
	var nn int
	if nn, err = io.ReadFull(r.r, tmp); errors.Is(err, io.ErrUnexpectedEOF) || err == io.EOF {
		tmp = tmp[:nn]
		r.err = io.EOF
		if nn == 0 {
			return 0, io.EOF
		}
	}
	if r.plaintext, err = decrypt(tmp, r.key); err != nil {
		return 0, err
	}
	n = copy(p, r.plaintext)
	r.plaintext = r.plaintext[n:]
	return n, nil
}

// decrypt decrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func decrypt(ciphertext []byte, key Key) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}

// NewKey generates a new random key using crypto/rand.
// An error from rand.Reader is cause for panic.
func NewKey() (key Key, err error) {
	_, err = io.ReadFull(rand.Reader, key[:])
	return key, err
}

type Key [32]byte

func (key Key) String() string {
	return base64.StdEncoding.EncodeToString(key[:])
}

func KeyFromBase64(s string) (key Key, err error) {
	var k []byte
	k, err = base64.StdEncoding.DecodeString(s)
	if err == nil && len(k) != 32 {
		err = fmt.Errorf("key decode: expected 32 bytes; got %v", len(k))
	}
	copy(key[:], k)
	return key, err
}
