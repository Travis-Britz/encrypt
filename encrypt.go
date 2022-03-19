/*
Package encrypt provides io.Writer and io.Reader implementations useful for symmetric file encryption.

How It Works

This implementation chunks the input into individually-encrypted segments of approximately 64KB in length,
which allows reading and writing to operate on large files or streams without loading the entire file into memory at once.

Each chunk is concatenated with an IV and Message Authentication Code,
which results in encrypted files that are larger than the source data.
For a 10GB file this results in approximately 4.3MB of additional data.

Encryption uses AES-GCM with 256-bit keys.
*/
package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
)

// these values result in sectors of just under 64*1024 bytes
const (
	blocks       = 4094
	aesBlockSize = 16
	chunkSize    = aesBlockSize * blocks
	nonceSize    = 12
	tagSize      = 16
)

// ErrInvalidKeyLength is returned by DecodeBase64Key when a key of the wrong size is decoded.
var ErrInvalidKeyLength = errors.New("expected 32-byte key")

// NewWriter returns a new Writer that encrypts data with key before writing to w.
// Callers must call Close to write the final chunk of data.
func NewWriter(w io.Writer, key Key) *Writer {
	return &Writer{
		w:   w,
		key: key,
	}
}

// Writer is an io.Writer for encrypting data.
type Writer struct {
	w   io.Writer
	key Key

	pos   int // pos is the cursor position in the pending chunk
	chunk [chunkSize]byte

	closed bool
}

// Write writes p to an internal buffer to ensure that encrypted chunks have uniform size.
// The buffer is encrypted and flushed as needed.
//
// Callers must call w.Close to flush the final chunk from the buffer.
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

// Close flushes any remaining data from the buffer to the underlying writer and prevents additional calls to Write.
func (w *Writer) Close() error {
	// The final chunk is likely to be smaller than the chunk size,
	// so more writes would result in decoding errors.
	w.closed = true
	return w.flush()
}

// flush encrypts the current buffer and writes to the underlying writer.
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
		// I think this error path is technically unreachable,
		// since it looks like aes.NewCipher only returns an error for invalid key lengths,
		// which shouldn't be possible since our keys are guaranteed to be 32 bytes.
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		// This error path also looks unreachable as long as the stdlib doesn't suddenly break aes block size constants.
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("encrypt.encrypt: crypto.rand.Reader failed: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// NewReader returns a new Reader for decrypting r,
// where r was encrypted by a Writer using key.
func NewReader(r io.Reader, key Key) *Reader {
	return &Reader{
		r:   r,
		key: key,
	}
}

// Reader is an io.Reader capable of decrypting data that was encrypted by Writer.
type Reader struct {
	r   io.Reader
	key Key

	offset int64 // offset is the current read position, used by Seek for io.SeekCurrent.
	skip   int   // skip are the number of bytes the next decrypted chunk should remove, set by Seek.

	plaintext []byte

	err error
}

// Read implements io.Reader.
func (r *Reader) Read(p []byte) (n int, err error) {
	defer func() { r.offset += int64(n) }()
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
	n = copy(p, r.plaintext[r.skip:])
	r.plaintext = r.plaintext[n+r.skip:]
	r.skip = 0
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

// NewKey generates a new random key for symmetric encryption.
// A non-nil error is cause for panic.
func NewKey() (key Key, err error) {
	_, err = io.ReadFull(rand.Reader, key[:])
	return key, err
}

// Key is a 256-bit key used for AES-GCM encryption and decryption.
type Key [32]byte

// String converts key to a string using standard base64 encoding,
// which is generally more portable between programs than 32 bytes of random binary data.
func (key Key) String() string {
	return base64.StdEncoding.EncodeToString(key[:])
}

// DecodeBase64Key decodes a base64-encoded key.
func DecodeBase64Key(s string) (key Key, err error) {
	var k []byte
	k, err = base64.StdEncoding.DecodeString(s)
	if err == nil && len(k) != 32 {
		err = ErrInvalidKeyLength
	}
	copy(key[:], k)
	return key, err
}

// Seek sets the offset for the next Read,
// partially implementing io.Seeker:
// io.SeekStart means relative to the start of the file,
// io.SeekCurrent means relative to the current offset.
// io.SeekEnd is only supported for specific types.
//
// Seek will return an error if r.r is not an io.Seeker.
func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	var newOffset int64
	var overshot bool
	var lastChunkSize int
	if _, ok := r.r.(io.Seeker); !ok {
		return 0, fmt.Errorf("encrypt.Reader.Seek: seek method not supported by %T", r.r)
	}

	switch whence {
	default:
		newOffset = offset
	// Some implementations of Seek will return an error for an unknown whence value.
	// However, since my fuzzer tests are comparing seek behavior directly to os.File
	// I decided to mimic that implementation instead.
	// 	return 0, errors.New("encrypt.Reader.Seek: invalid whence")
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = offset + r.offset
	case io.SeekEnd:
		var size int64
		if s, ok := r.r.(sizer); ok {
			size = s.Size()
		} else if s, ok := r.r.(statSizer); ok {
			fi, err := s.Stat()
			if err != nil {
				return 0, fmt.Errorf("encrypt.Reader.Seek: unable to determine size: %w", err)
			}
			size = fi.Size()
		} else {
			return 0, fmt.Errorf("encrypt.Reader.Seek: io.SeekEnd is not supported for %T", r.r)
		}
		const sectorSize = nonceSize + chunkSize + tagSize
		lastChunkSize = int(size%sectorSize - (nonceSize + tagSize))
		dataSize := size/sectorSize*chunkSize + int64(lastChunkSize)
		newOffset = dataSize + offset
		if newOffset > dataSize {
			overshot = true
		}
	}

	if newOffset < 0 {
		return 0, errors.New("encrypt.Reader.Seek: negative position")
	}

	sectorStart := getSectorStart(newOffset)

	s := r.r.(io.Seeker)
	n, err := s.Seek(sectorStart, io.SeekStart)
	if err != nil {
		return 0, fmt.Errorf("encrypt.Reader.Seek: %w", err)
	}
	if n != sectorStart {
		return 0, fmt.Errorf("encrypt.Reader.Seek: expected seek position to be %v; got %v", sectorStart, n)
	}

	if overshot {
		// this should place the cursor at exactly the end of the file,
		// to mirror the behavior of os.File when seek is past the end of the file
		r.skip = lastChunkSize
	} else {
		// this should make the next call to Read skip to the correct offset
		// within the next decoded chunk
		r.skip = int(newOffset % chunkSize)
	}
	r.offset = newOffset
	r.plaintext = nil
	return newOffset, nil
}

type statSizer interface {
	Stat() (os.FileInfo, error)
}
type sizer interface {
	Size() int64
}

func getSectorStart(offset int64) int64 {
	const sectorSize = nonceSize + chunkSize + tagSize
	return (offset / chunkSize) * sectorSize
}
