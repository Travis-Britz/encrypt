package encrypt_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/Travis-Britz/encrypt"
)

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
