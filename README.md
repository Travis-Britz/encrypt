Package `encrypt` wraps encryption functions with an io.Reader and io.Writer useful for file encryption.

The writer breaks the stream into chunks to prevent the entire (possibly very large) file from being loaded into memory at once.
Each chunk is concatenated with a random 12-byte nonce and 16-byte message authentication code (MAC).

Encryption uses 256-bit keys with AES-GCM.

This implementation has not been validated by encryption experts, nor has it been benchmarked for performance.

The Reader/Writer wrap the encryption functions from https://github.com/gtank/cryptopasta