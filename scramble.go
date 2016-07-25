package passwordHash

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"crypto/subtle"

	"golang.org/x/crypto/scrypt"
)

const (
	// DefaultSaltByteLength is the default length (bytes) of a generated secure
	// random salt
	DefaultSaltByteLength = 64

	// DefaultKeyByteLength is the default length (bytes) of the hash that will be
	// generated
	DefaultKeyByteLength = 64

	// DefaultR is the number of rounds of hashing used to generated a hashed
	// password
	DefaultR = 16

	// DefaultN is a CPU/memory cost parameter which must be a power of two
	// greater than 1
	DefaultN = 16384

	roundsIndex       = 0
	costIndex         = 1
	keyLengthIndex    = 2
	saltIndex         = 3
	passwordHashIndex = 4
	seperator         = ":"
)

//GenerateSalt takes a byte size as an int, returns a secure random stirng to
//the size of byteSize.
//
//See: https://golang.org/pkg/crypto/rand/
func GenerateSalt(byteLength int) ([]byte, error) {
	if byteLength == 0 {
		return nil, errors.New("byteSize should not be 0")
	}

	s := make([]byte, byteLength)
	_, err := rand.Read(s)
	return s, err
}

//Hash hashes p1 (password) using r (rounds), n (costParam) and
//a securely generated salt (see GenerateSalt func).
//
//p1 and p2 are compared using ConstantTimeCompare, if no match, err is returned.
//
//A string in the following format is returned r:n:keyLength:salt:hashedPassword
//
//See Validate func for password validation
func Hash(p1 string, p2 string, r int, n int, saltByteLength int, keyByteLength int) (string, error) {

	if subtle.ConstantTimeCompare([]byte(p1), []byte(p2)) == 0 {
		return "", errors.New("passwords do not match")
	}

	salt, err := GenerateSalt(saltByteLength)
	if err != nil {
		return "", errors.New("failed to generate a cryptographic random string")
	}

	// if any value is invalid or out of range scrypt.Key will return the
	// correct error message
	dk, err := scrypt.Key([]byte(p1), salt, n, r, 1, keyByteLength)

	if err != nil {
		return "", err
	}

	return encodeHashPayload(r, n, keyByteLength, salt, dk), nil
}

//HashWithDefaults is the same as Hash, but uses the default settings
//
//default r (rounds) = 16
//default N (cpu/ memory cost) = 16386
//default h (hashByteSize) = 64
//default s (saltByteSize) = 64
//
//returns a string as: r:n:keyLength:salt:hashedPassword
func HashWithDefaults(pw1 string, pw2 string) (string, error) {
	return Hash(pw1, pw2, DefaultR, DefaultN, DefaultSaltByteLength, DefaultKeyByteLength)
}

//Validate compares password against stored hash. password is the password as a
//string, hashPackage is the string that has been generated by HashWithDefaults
//or Hash functions
//
//returns true or false
//
//NOTE: If this func returns any errors, calling func should log there was an
//error decoding said password, dont log the password but just a ref to the user
//in question and investigate accordingly
func Validate(password string, hashPackage string) (bool, error) {

	r, n, keyLength, salt, passwordHash, err := decodeHashPaylaod(hashPackage)

	if err != nil {
		return false, fmt.Errorf("could not decode hashPackage, calling function should log more info, we dont log anything as to not leak data")
	}

	tmpHash, err := scrypt.Key([]byte(password), salt, n, r, 1, keyLength)

	if err != nil {
		return false, fmt.Errorf("error creating hashed password for compare, calling function should log more info, we dont log anything as to not leak data")
	}

	m := subtle.ConstantTimeCompare(tmpHash, passwordHash)

	res := false
	if m == 1 {
		res = true
	}

	return res, nil
}

func encodeHashPayload(rounds, cost, keyLength int, salt, passwordHash []byte) string {
	s := base64.StdEncoding.EncodeToString(salt)
	p := base64.StdEncoding.EncodeToString(passwordHash)

	// TODO use the const seperator when generating the encodedHash
	payload := fmt.Sprintf("%d:%d:%d:%s:%s", rounds, cost, keyLength, s, p)
	return payload
}

func decodeHashPaylaod(payload string) (rounds, cost, keyLength int, salt, passwordHash []byte, err error) {
	split := strings.Split(payload, seperator)

	if len(split) < 5 || len(split) > 5 {
		err = fmt.Errorf("invalid number of sections, expected=4, got=%d, we dont log anything as to not leak data", len(split))
		return
	}

	rounds, err = strconv.Atoi(split[roundsIndex])
	if err != nil {
		return
	}
	cost, err = strconv.Atoi(split[costIndex])
	if err != nil {
		return
	}

	keyLength, err = strconv.Atoi(split[keyLengthIndex])
	if err != nil {
		return
	}

	salt, err = base64.StdEncoding.DecodeString(split[saltIndex])
	if err != nil {
		return
	}
	passwordHash, err = base64.StdEncoding.DecodeString(split[passwordHashIndex])
	if err != nil {
		return
	}
	return
}
