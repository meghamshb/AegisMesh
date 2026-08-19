package domain

import "fmt"

type InvalidEnumError struct {
	Field string
	Value string
}

func (e InvalidEnumError) Error() string {
	return fmt.Sprintf("invalid %s: %q", e.Field, e.Value)
}
