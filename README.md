#passwordHash

An easy to use wrapper around https://godoc.org/golang.org/x/crypto/scrypt

Extracted from a bigger application so this can be used by others if it helps.

This wrapper sets sensible defaults for use with the scrypt package, it also generates a cryptographically secure pseudorandom number for a per password salt using crypto/rand.

#defaults

OWASP 2026 compliant parameters for strong password security:

Name  | Setting | Description
------------- | -------------|-------
defaultSaltByteLength  | 64 | salt length in bytes
defaultKeyByteLength | 64 | password hash length in bytes
defaultR  | 8 | block size parameter (standard)
defaultN  | 131072 | CPU/Memory cost (2^17, ~128MB), must be power of 2
defaultP | 1 | parallelization parameter

#Security Notes

- **Password Confirmation**: The second parameter in `HashWithDefaults()` exists for backward compatibility only. Password confirmation should be handled at the application level before calling the hashing function. Only the first parameter is used for hashing.
- **Memory Usage**: With N=131072 and r=8, each hash operation uses approximately 128MB of memory. This is intentional to resist GPU and ASIC-based attacks.
- **Backward Compatibility**: Existing password hashes will continue to work since the parameters are encoded in the hash string itself.
- **Standards Compliance**: These parameters meet OWASP 2026 recommendations for password storage.

#Usage

```go
package main
import (
	"fmt"

	"github.com/richardbowden/passwordHash"
)

func main() {
	password := "mypassword"

	// Note: Second parameter is for backward compatibility only.
	// Password confirmation should be done at application level.
	hashToStore, err := passwordHash.HashWithDefaults(password, password)
	if err != nil {
		fmt.Printf("Error hashing password: %v\n", err)
		return
	}

	fmt.Printf("Hashed password: %s\n\n", hashToStore)

	// Validate correct password
	valid, err := passwordHash.Validate(password, hashToStore)
	if err != nil {
		fmt.Printf("Error validating password: %v\n", err)
		return
	}
	fmt.Printf("Password '%s' is valid: %v\n", password, valid)

	// Validate incorrect password
	valid, err = passwordHash.Validate("wrongpassword", hashToStore)
	if err != nil {
		fmt.Printf("Error validating password: %v\n", err)
		return
	}
	fmt.Printf("Password 'wrongpassword' is valid: %v\n", valid)
}

```
