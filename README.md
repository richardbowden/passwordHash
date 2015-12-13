#passwordHash

https://codeship.com/projects/a7cdabc0-3c9f-0133-8f33-3ebbb4d77cd4/status?branch=master

An easy to use wrapper around https://godoc.org/golang.org/x/crypto/scrypt

Extracted from a bigger application so this can be used by others if it helps.

This wrapper sets sensible defaults for use with the scrypt package, it also generates a cryptographically secure pseudorandom number for a per password salt using crypto/rand.

#defaults

Name  | Setting | Description
------------- | -------------|-------
defaultByteLength  | 64 | used salt and password hash length
defaultR  | 16 | number of rounds
defaultN  | 16384 | CPU / Memory cost, needs to be power of 2

#Usage

```go
package main
import (
	"fmt"

	"github.com/richardbowden/passwordHash"
)

func main() {
	mypass := "mypassword"
	fmt.Println("Test password=", mypass)
	hashToStore, _ := passwordHash.HashWithDefaults(mypass)

	valid := passwordHash.Validate(mypass, hashToStore)

	fmt.Printf("Password is valid=%v\n", valid)

	fmt.Println("Testing invalid password=no against passowrd=mypassword")
	valid = passwordHash.Validate("no", hashToStore)
	fmt.Printf("Password is not valid=%v\n", valid)
}

```
