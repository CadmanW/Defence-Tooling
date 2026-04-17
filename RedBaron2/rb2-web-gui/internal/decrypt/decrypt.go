package decrypt

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/ulikunitz/xz/lzma"
)

var ageMarker = []byte("age-encryption.org/v1\n")

// LoadSSHIdentity reads an SSH private key file and returns an age Identity.
func LoadSSHIdentity(path string) (age.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file %s: %w", path, err)
	}

	identity, err := agessh.ParseIdentity(data)
	if err != nil {
		return nil, fmt.Errorf("parsing SSH identity: %w", err)
	}

	return identity, nil
}

// SplitAgePayloads splits a buffer that may contain multiple concatenated
// age-encrypted payloads, each starting with the "age-encryption.org/v1\n"
// marker.
func SplitAgePayloads(data []byte) [][]byte {
	var chunks [][]byte
	start := 0

	for start < len(data) {
		nextPos := bytes.Index(data[start+1:], ageMarker)
		if nextPos == -1 {
			chunks = append(chunks, data[start:])
			break
		}
		nextPos += start + 1
		chunks = append(chunks, data[start:nextPos])
		start = nextPos
	}

	return chunks
}

// DecodeChunk decodes one uploaded tty chunk object, handling either raw LZMA
// chunks or age-encrypted LZMA chunks.
func DecodeChunk(key string, raw []byte, identity age.Identity) ([]byte, error) {
	if strings.HasSuffix(key, ".cast.lzma") {
		return decompress(raw)
	}
	if !strings.HasSuffix(key, ".cast.age") {
		return nil, fmt.Errorf("unsupported tty chunk object %s", key)
	}
	if identity == nil {
		return nil, fmt.Errorf("tty chunk %s is encrypted but no SSH identity was configured", key)
	}

	chunks := SplitAgePayloads(raw)
	var result []byte

	for i, chunk := range chunks {
		reader, err := age.Decrypt(bytes.NewReader(chunk), identity)
		if err != nil {
			return nil, fmt.Errorf("chunk %d: age decrypt: %w", i, err)
		}
		decrypted, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("chunk %d: reading decrypted data: %w", i, err)
		}

		decompressed, err := decompress(decrypted)
		if err != nil {
			return nil, fmt.Errorf("chunk %d: %w", i, err)
		}
		result = append(result, decompressed...)
	}

	return result, nil
}

func decompress(raw []byte) ([]byte, error) {
	lzmaReader, err := lzma.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("lzma reader: %w", err)
	}
	decompressed, err := io.ReadAll(lzmaReader)
	if err != nil {
		return nil, fmt.Errorf("lzma decompress: %w", err)
	}
	return decompressed, nil
}
