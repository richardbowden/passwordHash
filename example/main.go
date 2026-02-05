package main

import (
	"fmt"
	"log"

	"github.com/richardbowden/passwordHash"
)

func main() {
	password := "mypassword"

	// Note: Second parameter is for backward compatibility only.
	// Password confirmation should be done at application level.
	hashToStore, err := passwordHash.HashWithDefaults(password, password)
	if err != nil {
		log.Fatalf("Error hashing password: %v\n", err)
	}

	fmt.Printf("Hashed password: %s\n\n", hashToStore)

	// Validate correct password
	valid, err := passwordHash.Validate(password, hashToStore)
	if err != nil {
		log.Fatalf("Error validating password: %v\n", err)
	}
	fmt.Printf("Password '%s' is valid: %v\n", password, valid)

	// Validate incorrect password
	valid, err = passwordHash.Validate("wrongpassword", hashToStore)
	if err != nil {
		log.Fatalf("Error validating password: %v\n", err)
	}
	fmt.Printf("Password 'wrongpassword' is valid: %v\n", valid)
}
