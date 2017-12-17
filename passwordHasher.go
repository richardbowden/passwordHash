package passwordHash

// PasswordHasher is an interface that describes two basic functions that can be
// used to perform a password encode and validate
type PasswordHasher interface {
	Encode(pw1 string, pw2 string) (string, error)
	Validate(pw string, hashPackage string) (bool, error)
}

// DefaultPasswordHasher impliments the PasswordHasher interface which uses passwordHash
type DefaultPasswordHasher struct{}

func (DefaultPasswordHasher) Encode(pw1 string, pw2 string) (string, error) {
	return HashWithDefaults(pw1, pw2)
}

func (DefaultPasswordHasher) Validate(pw string, hashedPackage string) (bool, error) {
	return Validate(pw, hashedPackage)
}
