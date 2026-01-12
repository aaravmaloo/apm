//go:build !windows
// +build !windows

package apm

import "errors"

func IsHelloConfigured() bool {
	return false
}

func SetupHello(masterPassword string) error {
	return errors.New("Windows Hello is only supported on Windows")
}

func GetMasterPasswordWithHello() (string, error) {
	return "", errors.New("Windows Hello is only supported on Windows")
}

func DisableHello() error {
	return nil
}
