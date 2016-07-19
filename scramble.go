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

const defaultByteLength = 64
const defaultR = 16    //number of rounds
const defaultN = 16384 //is a CPU/memory cost parameter which must be a power of two greater than 1

const roundsIndex = 0
const costIndex = 1
const keyLengthIndex = 2
const saltIndex = 3
const passwordHashIndex = 4
const septChar = ":"
const seperator = ":"

func getN(costParam int) int {
	if costParam == 0 {
		return defaultN
	}
	return costParam
}

func getR(rounds int) int {
	if rounds == 0 {
		return defaultR
	}
	return rounds
}

func getByteLength(byteLength int) (int, error) {
	if byteLength == 0 {
		return defaultByteLength, nil
	}

	var err error
	if byteLength < 32 {
		err = errors.New("Salt should be 32 Bytes minimum")
	}
	return byteLength, err
}

//GenerateSalt takes a byte size as an int, returns a secure random stirng to the size of byteSize
func GenerateSalt(byteLength int) ([]byte, error) {
	if byteLength == 0 {
		return nil, errors.New("byteSize should not be 0")
	}

	s := make([]byte, byteLength)
	_, err := rand.Read(s)
	return s, err
}

//Hash derives a key from the password, rounds, costParam and generated salt and returns formatted string, this is required when the
//password needs to be validated, this func allows the the params to be configured
//returns a string as: r:n:keyLength:salt:hashedPassword
func Hash(p1 string, p2 string, rounds int, costParam int, saltByteLength int, hashByteLength int) (string, error) {

	if subtle.ConstantTimeCompare([]byte(p1), []byte(p2)) == 0 {
		return "", errors.New("passwords do not match")
	}

	saltLength, err := getByteLength(saltByteLength)
	keyLength, err := getByteLength(hashByteLength)
	if err != nil {
		return "", err
	}

	r := getR(rounds)
	n := getN(costParam)

	salt, err := GenerateSalt(saltLength)
	if err != nil {
		return "", errors.New("failed to generate a cryptographic random string")
	}

	dk, err := scrypt.Key([]byte(p1), salt, n, r, 1, keyLength)

	if err != nil {
		return "", err
	}

	return encodeHashPayload(r, n, keyLength, salt, dk), nil
}

//HashWithDefaults is the same as Hash, but uses the default settings
//rounds = 0, costParam = 0
//
//default r (rounds) = 16
//default N (cpu/ memory cost) = 16386
//default h (hashByteSize) = 64
//default s (saltByteSize) = 64
//
//returns a string as: r:n:keyLength:salt:hashedPassword
func HashWithDefaults(pw1 string, pw2 string) (string, error) {
	return Hash(pw1, pw2, 0, 0, 0, 0)
}

//Validate compares password against stored hash
func Validate(password string, hashPackage string) bool {

	r, n, keyLength, salt, passwordHash, _ := decodeHashPaylaod(hashPackage)

	tmpHash, _ := scrypt.Key([]byte(password), salt, n, r, 1, keyLength)

	// res := bytes.Equal(tmpHash, passwordHash)
	m := subtle.ConstantTimeCompare(tmpHash, passwordHash)

	res := false
	if m == 1 {
		res = true
	}

	return res
}

func encodeHashPayload(rounds, cost, keyLength int, salt, passwordHash []byte) string {
	s := base64.StdEncoding.EncodeToString(salt)
	p := base64.StdEncoding.EncodeToString(passwordHash)
	payload := fmt.Sprintf("%d:%d:%d:%s:%s", rounds, cost, keyLength, s, p)
	return payload
}

func decodeHashPaylaod(payload string) (rounds, cost, keyLength int, salt, passwordHash []byte, err error) {
	split := strings.Split(payload, septChar)

	if len(split) < 5 || len(split) > 5 {
		err = fmt.Errorf("invalid number of sections, expected=4, got=%d", len(split))
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
