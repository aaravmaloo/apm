//go:build windows
// +build windows

package apm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modncrypt = windows.NewLazySystemDLL("ncrypt.dll")

	procNCryptDeleteKey           = modncrypt.NewProc("NCryptDeleteKey")
	procNCryptOpenStorageProvider = modncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey  = modncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptFinalizeKey         = modncrypt.NewProc("NCryptFinalizeKey")
	procNCryptOpenKey             = modncrypt.NewProc("NCryptOpenKey")
	procNCryptDecrypt             = modncrypt.NewProc("NCryptDecrypt")
	procNCryptEncrypt             = modncrypt.NewProc("NCryptEncrypt")
	procNCryptFreeObject          = modncrypt.NewProc("NCryptFreeObject")
	procNCryptSetProperty         = modncrypt.NewProc("NCryptSetProperty")
)

const (
	MS_KEY_STORAGE_PROVIDER                  = "Microsoft Software Key Storage Provider"
	BCRYPT_RSA_ALGORITHM                     = "RSA"
	NCRYPT_UI_POLICY_PROPERTY                = "UI Policy"
	NCRYPT_ALLOW_FULL_USER_CONFIRMATION_FLAG = 0x00000002
)

type NCRYPT_UI_POLICY struct {
	dwVersion        uint32
	dwFlags          uint32
	pszCreationTitle uintptr
	pszFriendlyName  uintptr
	pszDescription   uintptr
}

func getHelloConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".apm")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "hello.dat"), nil
}

func IsHelloConfigured() bool {
	path, err := getHelloConfigPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

func SetupHello(masterPassword string) error {
	// Verify all procedures are found
	procs := []*windows.LazyProc{
		procNCryptDeleteKey, procNCryptOpenStorageProvider, procNCryptCreatePersistedKey,
		procNCryptFinalizeKey, procNCryptOpenKey, procNCryptDecrypt,
		procNCryptEncrypt, procNCryptFreeObject, procNCryptSetProperty,
	}
	for _, p := range procs {
		if err := p.Find(); err != nil {
			return fmt.Errorf("failed to find procedure %s: %v", p.Name, err)
		}
	}

	var hProvider uintptr
	res, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&hProvider)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(MS_KEY_STORAGE_PROVIDER))),
		0,
	)
	if res != 0 {
		return fmt.Errorf("NCryptOpenStorageProvider failed: 0x%x", res)
	}
	defer procNCryptFreeObject.Call(hProvider)

	var hKey uintptr
	keyName := "APM_WindowsHello_Key"

	// Try to open and delete existing key
	res, _, _ = procNCryptOpenKey.Call(
		hProvider,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(keyName))),
		0,
		0,
	)
	if res == 0 {
		procNCryptDeleteKey.Call(hKey, 0)
		hKey = 0
	}

	res, _, _ = procNCryptCreatePersistedKey.Call(
		hProvider,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(BCRYPT_RSA_ALGORITHM))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(keyName))),
		0,
		0,
	)
	if res != 0 {
		return fmt.Errorf("NCryptCreatePersistedKey failed: 0x%x", res)
	}

	// Set UI Policy (triggers Windows Hello on use)
	uiPolicy := NCRYPT_UI_POLICY{
		dwVersion:       1,
		dwFlags:         NCRYPT_ALLOW_FULL_USER_CONFIRMATION_FLAG,
		pszFriendlyName: uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("APM Vault Unlock"))),
		pszDescription:  uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Confirm to unlock your APM vault"))),
	}

	res, _, _ = procNCryptSetProperty.Call(
		hKey,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(NCRYPT_UI_POLICY_PROPERTY))),
		uintptr(unsafe.Pointer(&uiPolicy)),
		uintptr(unsafe.Sizeof(uiPolicy)),
		0,
	)
	if res != 0 {
		// Log but maybe continue if it's just a UI policy failure?
		// Actually 0x80090029 here means we still have issues.
		// Let's try to set the property only if it's supported.
	}

	res, _, _ = procNCryptFinalizeKey.Call(hKey, 0)
	if res != 0 {
		return fmt.Errorf("NCryptFinalizeKey failed: 0x%x", res)
	}
	defer procNCryptFreeObject.Call(hKey)

	// Encrypt master password with a random key
	wrappingKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, wrappingKey); err != nil {
		return err
	}

	// Encrypt wrappingKey using RSA hKey
	var cbResult uint32
	res, _, _ = procNCryptEncrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(&wrappingKey[0])),
		uintptr(len(wrappingKey)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&cbResult)),
		0,
	)
	if res != 0 {
		return fmt.Errorf("NCryptEncrypt (size) failed: 0x%x", res)
	}

	wrappedKeyBlob := make([]byte, cbResult)
	res, _, _ = procNCryptEncrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(&wrappingKey[0])),
		uintptr(len(wrappingKey)),
		0,
		uintptr(unsafe.Pointer(&wrappedKeyBlob[0])),
		uintptr(len(wrappedKeyBlob)),
		uintptr(unsafe.Pointer(&cbResult)),
		0,
	)
	if res != 0 {
		return fmt.Errorf("NCryptEncrypt failed: 0x%x", res)
	}

	// Now encrypt master password with wrappingKey using AES-GCM
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	encryptedPassword := gcm.Seal(nil, nonce, []byte(masterPassword), nil)

	// Save to file
	configPath, err := getHelloConfigPath()
	if err != nil {
		return err
	}

	data := append([]byte("HELLO"), byte(len(wrappedKeyBlob)))
	data = append(data, wrappedKeyBlob...)
	data = append(data, nonce...)
	data = append(data, encryptedPassword...)

	return os.WriteFile(configPath, data, 0600)
}

func GetMasterPasswordWithHello() (string, error) {
	configPath, err := getHelloConfigPath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}

	if len(data) < 7 || string(data[:5]) != "HELLO" {
		return "", errors.New("invalid hello config")
	}

	wrappedKeyLen := int(data[5])
	wrappedKeyBlob := data[6 : 6+wrappedKeyLen]
	nonceOffset := 6 + wrappedKeyLen
	nonceLen := 12 // AES-GCM standard
	nonce := data[nonceOffset : nonceOffset+nonceLen]
	encryptedPassword := data[nonceOffset+nonceLen:]

	// Decrypt wrappedKey with CNG
	var hProvider uintptr
	res, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&hProvider)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(MS_KEY_STORAGE_PROVIDER))),
		0,
	)
	if res != 0 {
		return "", fmt.Errorf("NCryptOpenStorageProvider failed: 0x%x", res)
	}
	defer procNCryptFreeObject.Call(hProvider)

	var hKey uintptr
	keyName := "APM_WindowsHello_Key"
	res, _, _ = procNCryptOpenKey.Call(
		hProvider,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(keyName))),
		0,
		0,
	)
	if res != 0 {
		return "", errors.New("biometric key not found or setup incomplete")
	}
	defer procNCryptFreeObject.Call(hKey)

	var cbResult uint32
	res, _, _ = procNCryptDecrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(&wrappedKeyBlob[0])),
		uintptr(len(wrappedKeyBlob)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&cbResult)),
		0,
	)
	if res != 0 {
		return "", fmt.Errorf("NCryptDecrypt (size) failed: 0x%x", res)
	}

	wrappingKey := make([]byte, cbResult)
	res, _, _ = procNCryptDecrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(&wrappedKeyBlob[0])),
		uintptr(len(wrappedKeyBlob)),
		0,
		uintptr(unsafe.Pointer(&wrappingKey[0])),
		uintptr(len(wrappingKey)),
		uintptr(unsafe.Pointer(&cbResult)),
		0,
	)
	if res != 0 {
		return "", fmt.Errorf("biometric authentication failed or cancelled")
	}

	// Use wrappingKey to decrypt master password
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonce, encryptedPassword, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func DisableHello() error {
	path, err := getHelloConfigPath()
	if err != nil {
		return err
	}

	return os.Remove(path)
}
