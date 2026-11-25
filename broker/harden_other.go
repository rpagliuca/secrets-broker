//go:build !linux

package broker

import "errors"

// Harden is only implemented on Linux.
func Harden(lock bool) error {
	return errors.New("process hardening is only implemented on Linux")
}
