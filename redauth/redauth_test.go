package redauth

import (
  "testing"
)

func TestPasswordAndPasswordConfirmationMatch(t *testing.T) {
  const password, passwordConfirmation = "password", "password"
  const diffPassword = "password1"

  // Tests passwords that match
  err := PasswordAndPasswordConfirmationMatch(password, passwordConfirmation)
  if err != nil {
    t.Errorf("Expected password and passwordConfirmation to match\n")
  }

  err = PasswordAndPasswordConfirmationMatch(password, diffPassword)
  if err == nil {
    t.Errorf("Expected PasswordAndPasswordConfirmationMatch to raise an error")
  }
}

func TestCreatePassword(t *testing.T) {
  const plaintext, stretches = "password", 4

  hashedPassword, err := CreatePassword(plaintext, stretches)

  if err != nil {
    t.Errorf("Something went wrong creating the password: %s\n", err)
  }

  if err = CompareHashAndPassword(hashedPassword, plaintext); err != nil {
    t.Errorf("%s\n", err)
  }
}
