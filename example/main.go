package main

import (
	"fmt"
	"log"

	"github.com/richardbowden/passwordHash"
)

func main() {
	p1 := "password1"
	p2 := "password1"

	fmt.Printf("Passwords used in this example. pwd1: %s and pwd2: %s\n\n", p1, p2)

	hashed, err := passwordHash.HashWithDefaults(p1, p2)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Hashed Package: %v\n\n", hashed)

	isValid, err := passwordHash.Validate("password1", hashed)

	fmt.Printf("Password to be validated 'password1' agasint hashed password 'password1' is valid: %v\n", isValid)

	isValid, err = passwordHash.Validate("invalid", hashed)

	fmt.Printf("Password to be validated 'invalid password' against hashed password 'password1 is invalid: %v\n", isValid)
}
