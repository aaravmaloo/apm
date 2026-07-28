// Package touchid provides Touch ID authentication for APM on macOS.
//
// On macOS it shells out to osascript (JXA) for biometric authentication
// and the security CLI for Keychain credential storage — zero CGO required.
// On other platforms all operations return ErrNotAvailable.
package touchid

import "errors"

const (
	// KeychainService is the service name used for Keychain items.
	KeychainService = "APM Vault"

	// KeychainAccount is the account name used for Keychain items.
	KeychainAccount = "master-password"
)

// ErrNotAvailable is returned when Touch ID is not available on the platform.
var ErrNotAvailable = errors.New("touch id is not available on this platform")

// ErrNotConfigured is returned when Touch ID has not been set up yet.
var ErrNotConfigured = errors.New("touch id has not been configured")

// ErrAuthFailed is returned when the user cancels or fails Touch ID authentication.
var ErrAuthFailed = errors.New("touch id authentication failed")
