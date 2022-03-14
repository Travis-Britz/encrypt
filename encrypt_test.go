package encrypt_test

import (
	"bytes"
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
		name:      "full file (two chunks and a fragment)",
		plaintext: filedata,
	}}

	for _, td := range tt {
		t.Run(td.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			w := encrypt.NewWriter(buf, randomKey)
			if _, err := io.Copy(w, bytes.NewReader(td.plaintext)); err != nil {
				t.Error(err)
			}
			if err := w.Close(); err != nil {
				t.Error(err)
			}
			ciphertext, err := io.ReadAll(buf)
			if err != nil {
				t.Error(err)
			}
			plaintext, err := io.ReadAll(encrypt.NewReader(bytes.NewReader(ciphertext), randomKey))
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(plaintext, td.plaintext) {
				// ff, err := os.Create(fmt.Sprintf("failed-%s.txt", td.name))
				// if err != nil {
				// 	log.Println(err)
				// }
				// defer ff.Close()
				// log.Println(ff.Write(plaintext))
				// ff.Close()
				t.Errorf("plaintext does not match")
			}
		})
	}
}
