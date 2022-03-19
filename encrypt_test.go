package encrypt_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/Travis-Britz/encrypt"
)

const chunkSize = 65504
const testKey = "VGVzdEtleTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="

func ExampleNewKey() {
	// generate a new key with crypto/rand
	key, err := encrypt.NewKey()
	if err != nil {
		panic(err)
	}

	// save the key somewhere safe
	fmt.Println(key.String())

	// then use the key to encrypt data...
}

func ExampleNewWriter() {
	// load a key that was saved somewhere secure
	key, _ := encrypt.DecodeBase64Key("VGVzdEtleTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
	plaintext := []byte("Hello, world!")

	buf := &bytes.Buffer{}
	encrypter := encrypt.NewWriter(buf, key)
	encrypter.Write(plaintext)
	encrypter.Close() // flushes the final chunk

	fmt.Printf("plaintext:  %v\n", plaintext)
	fmt.Printf("ciphertext: %v\n", buf.Bytes())
}

func TestEncryptDecrypt(t *testing.T) {
	f, err := os.Open("testdata/plaintext.txt")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()
	filedata, err := io.ReadAll(f)
	if err != nil {
		t.Error(err)
	}

	randomKey, _ := encrypt.NewKey()
	tt := []struct {
		name      string
		plaintext []byte
	}{{
		name:      "empty string",
		plaintext: nil,
	}, {
		name:      "zeroes",
		plaintext: make([]byte, 65*1024),
	}, { // AES uses a 16-byte block, so check around those edges
		name:      "15 bytes",
		plaintext: []byte("Hello, world!!!"),
	}, {
		name:      "16 bytes",
		plaintext: []byte("Hello, world!!!!"),
	}, {
		name:      "17 bytes",
		plaintext: []byte("Hello, world!!!!!"),
	}, {
		name:      "multi-chunk file",
		plaintext: filedata,
	}}

	for _, td := range tt {
		t.Run(td.name, func(t *testing.T) {
			if err := encryptValidate(td.plaintext, randomKey); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	key, err := encrypt.DecodeBase64Key(testKey)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := os.Open("testdata/plaintext.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer pt.Close()
	plaintext, err := io.ReadAll(pt)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := os.Open("testdata/ciphertext.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer ct.Close()
	ciphertext, err := io.ReadAll(ct)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := io.ReadAll(encrypt.NewReader(bytes.NewReader(ciphertext), key))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("plaintext does not match")
	}

	ciphertext[0] ^= 0xff
	_, err = io.ReadAll(encrypt.NewReader(bytes.NewReader(ciphertext), key))
	if err == nil {
		t.Fatalf("expected a decryption error")
	}

	if _, err = io.ReadAll(encrypt.NewReader(bytes.NewReader([]byte{'A'}), key)); err.Error() != "malformed ciphertext" {
		t.Errorf("expected a malformed ciphertext error")
	}
}

func TestKeyFromBase64(t *testing.T) {
	if _, err := encrypt.DecodeBase64Key("Bad Key"); err == nil {
		t.Errorf("expected key decode error")
	}

	if _, err := encrypt.DecodeBase64Key(base64.StdEncoding.EncodeToString([]byte("Bad Key"))); !errors.Is(err, encrypt.ErrInvalidKeyLength) {
		t.Errorf("expected ErrInvalidKeyLength")
	}

	if _, err := encrypt.DecodeBase64Key(testKey); err != nil {
		t.Error(err)
	}
}

func TestKey_String(t *testing.T) {
	key := encrypt.Key{}
	copy(key[:], "TestKey0000000000000000000000000")
	if key.String() != testKey {
		t.Errorf("string did not match base64-encoded test key")
	}
}

func TestWriter_Write(t *testing.T) {
	key, _ := encrypt.NewKey()
	w := encrypt.NewWriter(&bytes.Buffer{}, key)
	if _, err := w.Write([]byte("Hello, world!")); err != nil {
		t.Error(err)
	}
	if err := w.Close(); err != nil {
		t.Error(err)
	}
	if err := w.Close(); err != nil {
		// closing more than once shouldn't result in an error
		t.Error(err)
	}
	n, err := w.Write([]byte("Hello, world!"))
	if err == nil {
		t.Errorf("expected an error when writing to a closed writer")
	}
	if n != 0 {
		t.Errorf("expected n to be 0 when writing to a closed writer; got %v", n)
	}

	w = encrypt.NewWriter(&badWriter{failAt: 2}, key)
	m, err := io.Copy(w, bytes.NewReader(plaintextData()))
	if err == nil {
		t.Errorf("expected bad writer to return an error")
	}
	if m != chunkSize {
		t.Errorf("expected number of bytes written to equal the size of the first chunk; got %v", m)
	}

}
func TestReader_Seek_BadSeeker(t *testing.T) {
	key, _ := encrypt.DecodeBase64Key(testKey)
	r := encrypt.NewReader(&bytes.Buffer{}, key)
	if _, err := r.Seek(0, 0); err == nil {
		t.Errorf("expected Seek to return an error because r does not implement io.Seeker; got nil")
	}
	r = encrypt.NewReader(&badSeeker{Reader: &bytes.Buffer{}, err: errors.New("seek failed")}, key)
	if _, err := r.Seek(0, 0); err == nil {
		t.Errorf("expected Seek to return an error from badSeeker; got nil")
	}
	r = encrypt.NewReader(&badSeeker{Reader: &bytes.Buffer{}, n: 1, err: nil}, key)
	if _, err := r.Seek(0, 0); err == nil {
		t.Errorf("expected Seek to return an error from bad seek position; got nil")
	}
	r = encrypt.NewReader(noSizeReadSeeker{}, key)
	if _, err := r.Seek(-1, io.SeekEnd); err == nil {
		t.Errorf("expected Seek to return an error for unknown size; got nil")
	}

	buf := &bytes.Buffer{}
	w := encrypt.NewWriter(buf, key)
	w.Write(make([]byte, chunkSize))
	w.Close()
	r = encrypt.NewReader(bytes.NewReader(buf.Bytes()), key)
	if n, err := r.Seek(-1, io.SeekEnd); n != chunkSize-1 || err != nil {
		t.Errorf("expected %d/nil; got %d/%s", chunkSize-1, n, err)
	}
}

type noSizeReadSeeker struct{}

func (rs noSizeReadSeeker) Read([]byte) (int, error) {
	return 0, io.EOF
}
func (rs noSizeReadSeeker) Seek(n int64, whence int) (int64, error) {
	return n, nil
}

type badSeeker struct {
	io.Reader
	n   int64
	err error
}

func (s badSeeker) Seek(int64, int) (int64, error) {
	return s.n, s.err
}

func FuzzReader_Seek(f *testing.F) {
	key, _ := encrypt.DecodeBase64Key(testKey)
	f.Add(int64(-1), 0, uint(10))
	f.Add(int64(-1), 1, uint(10))
	f.Add(int64(-1), 2, uint(10))
	f.Add(int64(-512), 2, uint(10))
	f.Add(int64(-chunkSize), io.SeekEnd, uint(10))
	f.Add(int64(0), 0, uint(10))
	f.Add(int64(0), 1, uint(10))
	f.Add(int64(0), 2, uint(10))
	f.Add(int64(1), 0, uint(10))
	f.Add(int64(2), 1, uint(10))
	f.Add(int64(3), 2, uint(10))
	f.Add(int64(3), 3, uint(10))
	f.Fuzz(func(t *testing.T, seekOffset int64, whence int, readSize uint) {
		file, err := os.Open("testdata/plaintext.txt")
		if err != nil {
			t.Error(err)
		}
		defer file.Close()
		ct, err := os.Open("testdata/ciphertext.txt")
		if err != nil {
			t.Error(err)
		}
		defer ct.Close()
		decrypter := encrypt.NewReader(ct, key)
		pt1 := make([]byte, readSize)
		pt2 := make([]byte, readSize)
		n1, err1 := file.Seek(seekOffset, whence)
		n2, err2 := decrypter.Seek(seekOffset, whence)
		if whence >= io.SeekStart && whence <= io.SeekEnd {
			if err1 == nil && err2 != nil || err1 != nil && err2 == nil {
				t.Errorf("seek: expected errors to match; got %q and %q", err1, err2)
			}
		}
		if n1 != n2 {
			t.Errorf("seek: expected n1 to match n2; got %v/%q and %v/%q", n1, err1, n2, err2)
		}
		_, err1 = io.ReadFull(file, pt1)
		_, err2 = io.ReadFull(decrypter, pt2)
		if err1 == nil && err2 != nil || err1 != nil && err2 == nil {
			t.Errorf("readfull: expected errors to match; got %q and %q", err1, err2)
		}
		if !bytes.Equal(pt1, pt2) {
			t.Errorf("plaintext did not match: %q and %q", string(pt1), string(pt2))
		}
	})
}

func FuzzEncryptDecrypt(f *testing.F) {
	key, _ := encrypt.NewKey()
	f.Fuzz(func(t *testing.T, plaintext []byte) {
		if err := encryptValidate(plaintext, key); err != nil {
			t.Error(err)
		}
	})
}

func encryptValidate(plaintext []byte, key encrypt.Key) error {
	buf := &bytes.Buffer{}
	w := encrypt.NewWriter(buf, key)
	if _, err := io.Copy(w, bytes.NewReader(plaintext)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	ciphertext, err := io.ReadAll(buf)
	if err != nil {
		return err
	}
	pt, err := io.ReadAll(encrypt.NewReader(bytes.NewReader(ciphertext), key))
	if err != nil {
		return err
	}
	if !bytes.Equal(pt, plaintext) {
		return errors.New("plaintext does not match")
	}
	return nil
}

type badWriter struct {
	failAt int
	n      int
}

func (w *badWriter) Write(p []byte) (n int, err error) {
	w.n++
	if w.n == w.failAt {
		return 0, errors.New("failed write")
	}
	return len(p), nil
}

func plaintextData() []byte {
	f, err := os.Open("testdata/plaintext.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}
	return data
}
