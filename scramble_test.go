package passwordHash

import (
	"crypto/subtle"
	"fmt"
	"testing"
)

func TestSaltGenerationReturnsErrorWhen0IsPassedIn(t *testing.T) {
	_, err := GenerateSalt(0)
	if err == nil {
		t.Fatalf("Did not return an error when 0 is passed in")
	}
}

func TestSaltGenerationReturnsCustomByteSaltByDefault(t *testing.T) {
	s, _ := GenerateSalt(128)
	if len(s) != 128 {
		t.Fatalf("Failed to generate a 128 byte salt, we got %v (salt=%x)", len(s), s)
	}
}

func TestSaltGeneration(t *testing.T) {
	res := make(map[string]int)
	errors := 0

	var iterations int
	if testing.Short() {
		iterations = 1000
	} else {
		iterations = 100000
	}
	for i := 1; i <= iterations; i++ {
		s, err := GenerateSalt(64)
		if err != nil {
			errors++

		} else {
			res[fmt.Sprintf("%x", s)] = 1
		}
	}
	if errors > 0 {
		t.Errorf("Failed to generate random strings, dups=%v", errors)
	}
}

func TestGetNReturnsAValidDefaultCostValue(t *testing.T) {
	//default cost 16384
	res := getN(0)
	if res != 16384 {
		t.Error("Did not get default cost value 16384")
	}
}

func TestGetNReturnsNoErrorWithAValidCostValue(t *testing.T) {
	res := getN(512)

	if res != 512 {
		t.Error("did not returned expected value of 512")
	}
}

func TestGetRReturnsDefault(t *testing.T) {
	res := getR(0)

	if res != 16 {
		t.Error("Failed to return the default number of rounds 16")
	}
}

func TestGetRReturnsSpecifiedNumberOfRounds(t *testing.T) {
	res := getR(28)

	if res != 28 {
		t.Error("Failed to return the set number of rounds 28")
	}
}

func TestEncodeHashPayloadReturnsCorrectString(t *testing.T) {
	s := []byte("mysalt")
	p := []byte("mypassword")

	a := encodeHashPayload(9, 1111, 64, s, p)
	if a != "9:1111:64:bXlzYWx0:bXlwYXNzd29yZA==" {
		t.Error("failed to produce expected string", a)
	}
}

func TestDecodeHashPayloadReturnsCorrectString(t *testing.T) {

	hashPayload := "9:1111:64:bXlzYWx0:bXlwYXNzd29yZA=="

	r, n, l, salt, p, err := decodeHashPaylaod(hashPayload)

	if err != nil {
		t.Errorf("Error encountered, %v", err)
	}

	saltRes := subtle.ConstantTimeCompare(salt, []byte("mysalt"))
	pRes := subtle.ConstantTimeCompare(p, []byte("mypassword"))

	if !(saltRes == 1) {
		t.Error("aggg fucked")
	}

	if !(pRes == 1) {
		t.Errorf("incorrect password hash decoded expected: mypassword but got %s", p)
	}

	if l != 64 {
		t.Errorf("incorrect passwordHash length decoded expected: 64 but got %d", l)
	}

	if r != 9 {
		t.Errorf("incorrect number of rounds decoded expected: 9 but got %d", r)
	}
	if n != 1111 {
		t.Errorf("incorrect cost decoded expected: 1111 but got %d", n)
	}
}

func TestDecodeHashPayloadReturnsErrorWhenPayloadContainsWrongNumberOfParts(t *testing.T) {
	toLong := "1:1:1:1:1:1:1"
	toShort := "1:1"

	_, _, _, _, _, err := decodeHashPaylaod(toLong)

	if err == nil {
		t.Error("Did not raise error for more then 4 sections")
	}

	_, _, _, _, _, err = decodeHashPaylaod(toShort)

	if err == nil {
		t.Error("Did not raise error for less then 4 sections")
	}

}

func TestgetByteLengthReturnsErrorWhenByteSizeIsLessThan64(t *testing.T) {
	_, err := getByteLength(31)
	if err == nil {
		t.Error("Should of returned an error for an int less than 64")
	}
}

func TestgetByteLengthReturnsThedefaultByteLength(t *testing.T) {
	s, err := getByteLength(0)
	if err != nil {
	}
	if s != 64 {
		t.Error("Should of returned 64 as the default ByteSize")
	}
}

func TestValidateReturnsTrueWhenValid(t *testing.T) {
	pass := "mypassword"
	hashedPayload, _ := Hash(pass, pass, 0, 0, 0, 0)

	res := Validate(pass, hashedPayload)
	if res != true {
		t.Error("Password shoud be valid")
	}
}

func TestValidateReturnsFalseWhenInvalid(t *testing.T) {
	pass := "mypassword"
	hashedPayload, _ := Hash(pass, pass, 0, 0, 0, 0)

	res := Validate("aaa", hashedPayload)
	if res != false {
		t.Error("Password shoud be invalid")
	}
}

// Benchmarks
func BenchmarkSaltGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateSalt(0)
	}
}
