[![Go](https://github.com/Travis-Britz/encrypt/actions/workflows/go.yml/badge.svg)](https://github.com/Travis-Britz/encrypt/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Travis-Britz/encrypt)](https://goreportcard.com/report/github.com/Travis-Britz/encrypt)
[![Coverage](https://codecov.io/gh/Travis-Britz/encrypt/branch/master/graphs/badge.svg?branch=master)](https://codecov.io/github/Travis-Britz/encrypt?branch=master)

Go (golang) file encryption reader/writer.

# About

Package `encrypt` provides io.Writer and io.Reader implementations useful for file encryption.

[Documentation](https://pkg.go.dev/github.com/Travis-Britz/encrypt)

## How It Works

This implementation chunks the input into individually-encrypted segments of approximately 64KB in length,
which allows reading and writing to operate on large files or streams without loading the entire file into memory at once.

Each chunk is concatenated with a random 96-bit nonce and 128-bit Message Authentication Code (MAC) to prevent tampering.
As a result the size on disk will be 28*N bytes larger than the input, where N is the number of segments the file was broken into.
For a 10GB file this translates to approximately 4.3MB of overhead.

Encryption uses AES-GCM with 256-bit keys.

The individual chunks are encrypted following the examples from https://github.com/gtank/cryptopasta
(see the Crypto for Go Developers talk for details).

### Relevant Talks:

Crypto for Go Developers: https://www.youtube.com/watch?v=2r_KMzXB74w

End-to-End File Encryption (In Web Browsers): https://www.youtube.com/watch?v=SdePc87Ffik

## Disclaimer

This implementation has not been validated by encryption experts,
nor has it been optimized for performance.
Use at your own risk.

