package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	pbkdf2Iterations = 200000
	pbkdf2SaltBytes  = 16
	pbkdf2KeyBytes   = 32
)

// HashPassword returns a PBKDF2-derived hash string.
// Format: pbkdf2$<iterations>$<base64(salt)>$<base64(hash)>
func HashPassword(password string) (string, error) {
	salt := make([]byte, pbkdf2SaltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	key := pbkdf2Key([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyBytes)
	return fmt.Sprintf(
		"pbkdf2$%d$%s$%s",
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword checks PBKDF2 hashes in constant time.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false, errors.New("invalid hash format")
	}

	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations <= 0 {
		return false, errors.New("invalid iterations")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, errors.New("invalid salt")
	}

	expected, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, errors.New("invalid hash")
	}

	derived := pbkdf2Key([]byte(password), salt, iterations, len(expected))
	if subtle.ConstantTimeCompare(derived, expected) == 1 {
		return true, nil
	}
	return false, nil
}

func pbkdf2Key(password, salt []byte, iter, keyLen int) []byte {
	hLen := sha256.Size
	numBlocks := (keyLen + hLen - 1) / hLen
	var dk []byte

	for block := 1; block <= numBlocks; block++ {
		t := pbkdf2F(password, salt, iter, block)
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func pbkdf2F(password, salt []byte, iter, blockIndex int) []byte {
	block := make([]byte, len(salt)+4)
	copy(block, salt)
	block[len(salt)] = byte(blockIndex >> 24)
	block[len(salt)+1] = byte(blockIndex >> 16)
	block[len(salt)+2] = byte(blockIndex >> 8)
	block[len(salt)+3] = byte(blockIndex)

	u := hmacSHA256(password, block)
	out := make([]byte, len(u))
	copy(out, u)

	for i := 1; i < iter; i++ {
		u = hmacSHA256(password, u)
		for j := 0; j < len(out); j++ {
			out[j] ^= u[j]
		}
	}
	return out
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}
