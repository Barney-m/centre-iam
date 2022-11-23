package validator

import (
	"fmt"
	"net/mail"
	"regexp"
)

var (
	isValidEmail = regexp.MustCompile("^[a-zA-Z0-9.! #$%&'*+/=? ^_`{|}~-]+@[a-zA-Z0-9-]+(?:\\. [a-zA-Z0-9-]+)*$").MatchString
)

func ValidateString(value string, minLength int, maxLength int) error {
	n := len(value)

	if n < minLength || n > maxLength {
		return fmt.Errorf("Must contain from %d-%d characters", minLength, maxLength)
	}
	return nil
}

func ValidateEmail(email string) error {
	if err := ValidateString(email, 5, 255); err != nil {
		return err
	}

	if _, err := mail.ParseAddress(email); err != nil {
		return fmt.Errorf("Must be an email")
	}

	return nil
}

func ValidatePassword(password string) error {
	return ValidateString(password, 6, 100)
}
