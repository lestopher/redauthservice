package redauth

import (
	"code.google.com/p/go.crypto/bcrypt"
	"errors"
)

// RedAuth holds important information related to authentication for Red
type RedAuth struct{}

// PasswordAndPasswordConfirmationMatch compares the password and the password
// confirmation. Returns nil on success, otherwise an error.
func PasswordAndPasswordConfirmationMatch(pass, passConf string) error {
	if pass != passConf {
		return errors.New("password and password confirmation do not match")
	}

	return nil
}

// CreatePassword is a wrapper for bcrypt's GenerateFromPassword function. The
// major difference is that it accepts a string instead of a byte array. Returns
// the crypted password on success, otherwise the error from bcrypt
func CreatePassword(password string, stretches int) (string, error) {
	cleartext := []byte(password)
	crypted, err := bcrypt.GenerateFromPassword(cleartext, stretches)

	if err != nil {
		return "", err
	}

	return string(crypted), nil
}

// CompareHashAndPassword is a wrapper for bcrypt's CompareHashAndPassword
// function.
func CompareHashAndPassword(crypted, plaintext string) error {
	return bcrypt.CompareHashAndPassword([]byte(crypted), []byte(plaintext))
}
