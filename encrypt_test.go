package encrypt_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/Travis-Britz/encrypt"
)

const testKey = "VGVzdEtleTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="

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
	key, err := encrypt.KeyFromBase64(testKey)
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
}

func TestKeyFromBase64(t *testing.T) {
	if _, err := encrypt.KeyFromBase64("Bad Key"); err == nil {
		t.Errorf("expected key decode error")
	}

	if _, err := encrypt.KeyFromBase64(base64.StdEncoding.EncodeToString([]byte("Bad Key"))); !errors.Is(err, encrypt.ErrInvalidKeyLength) {
		t.Errorf("expected ErrInvalidKeyLength")
	}

	if _, err := encrypt.KeyFromBase64(testKey); err != nil {
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
