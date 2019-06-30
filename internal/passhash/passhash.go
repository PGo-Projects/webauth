package passhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Note: This is inspired by https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go

var (
	ErrInvalidHash               = errors.New("Hash is not in the correct format")
	ErrIncompatibleArgon2Version = errors.New("Used incompatible version of Argon2")
)

type Params struct {
	Memory      uint32
	TimeCost    uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultParams = &Params{
	Memory:      64 * 1024, /* base units in kilobytes */
	TimeCost:    3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

func Hash(password string) (string, error) {
	return HashWithParams(password, DefaultParams)
}

func HashWithParams(password string, params *Params) (string, error) {
	salt, err := generateRandomBytes(params.SaltLength)
	if err != nil {
		return "", err
	}

	hash := computeHash(password, params, salt)

	base64EncodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	base64EncodedHash := base64.RawStdEncoding.EncodeToString(hash)
	hashedPassword := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.Memory, params.TimeCost, params.Parallelism,
		base64EncodedSalt, base64EncodedHash,
	)

	return hashedPassword, nil
}

func Verify(password, hashedPassword string) (bool, error) {
	params, salt, hash, err := decodeToComponents(hashedPassword)
	if err != nil {
		return false, err
	}

	computedHash := computeHash(password, params, salt)
	if subtle.ConstantTimeCompare(computedHash, hash) == 1 {
		return true, nil
	}
	return false, nil
}

func computeHash(s string, params *Params, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(s),
		salt,
		params.TimeCost, params.Memory, params.Parallelism, params.KeyLength,
	)
}

func generateRandomBytes(length uint32) ([]byte, error) {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}
	return randomBytes, nil
}

func decodeToComponents(hashedPassword string) (*Params, []byte, []byte, error) {
	vals := strings.Split(hashedPassword, "$")
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}

	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleArgon2Version
	}

	params := &Params{}
	_, err = fmt.Sscanf(
		vals[3],
		"m=%d,t=%d,p=%d",
		&params.Memory, &params.TimeCost, &params.Parallelism,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	params.SaltLength = uint32(len(salt))

	hash, err := base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	params.KeyLength = uint32(len(hash))

	return params, salt, hash, nil
}
