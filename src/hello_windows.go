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
)

var (
	modncrypt = syscall.NewLazyDLL("ncrypt.dll")

	procNCryptOpenStorageProvider = modncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey  = modncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptFinalizeKey         = modncrypt.NewProc("NCryptFinalizeKey")
	procNCryptOpenPersistedKey    = modncrypt.NewProc("NCryptOpenPersistedKey")
	procNCryptDecrypt             = modncrypt.NewProc("NCryptDecrypt")
	procNCryptEncrypt             = modncrypt.NewProc("NCryptEncrypt")
	procNCryptFreeObject          = modncrypt.NewProc("NCryptFreeObject")
	procNCryptSetProperty         = modncrypt.NewProc("NCryptSetProperty")
)

const (
	MS_KEY_STORAGE_PROVIDER                  = "Microsoft Software Key Storage Provider"
	BCRYPT_AES_ALGORITHM                     = "AES"
	NCRYPT_USER_CONFIRMATION_POLICY_PROPERTY = "User Confirmation Policy"
	NCRYPT_ALLOW_FULL_USER_CONFIRMATION_FLAG = 0x00000002
)

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
	res, _, _ = procNCryptCreatePersistedKey.Call(
		hProvider,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(BCRYPT_AES_ALGORITHM))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(keyName))),
		0,
		0,
	)
	if res != 0 && res != 0x8009000f { // NTE_EXISTS
		return fmt.Errorf("NCryptCreatePersistedKey failed: 0x%x", res)
	}

	if res == 0x8009000f {
		res, _, _ = procNCryptOpenPersistedKey.Call(
			hProvider,
			uintptr(unsafe.Pointer(&hKey)),
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(keyName))),
			0,
			0,
		)
		if res != 0 {
			return fmt.Errorf("NCryptOpenPersistedKey failed: 0x%x", res)
		}
	} else {
		// Set user confirmation policy (triggers Windows Hello)
		policy := uint32(NCRYPT_ALLOW_FULL_USER_CONFIRMATION_FLAG)
		res, _, _ = procNCryptSetProperty.Call(
			hKey,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(NCRYPT_USER_CONFIRMATION_POLICY_PROPERTY))),
			uintptr(unsafe.Pointer(&policy)),
			4,
			0,
		)
		if res != 0 {
			return fmt.Errorf("NCryptSetProperty failed: 0x%x", res)
		}

		res, _, _ = procNCryptFinalizeKey.Call(hKey, 0)
		if res != 0 {
			return fmt.Errorf("NCryptFinalizeKey failed: 0x%x", res)
		}
	}
	defer procNCryptFreeObject.Call(hKey)

	// Encrypt master password with a random key protected by CNG
	wrappingKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, wrappingKey); err != nil {
		return err
	}

	// Encrypt wrappingKey using CNG hKey
	var cbResult uint32
	res, _, _ = procNCryptEncrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(&wrappingKey[0])),
		uintptr(len(wrappingKey)),
		0,
		0,
		0,
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
	res, _, _ = procNCryptOpenPersistedKey.Call(
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

	// We don't necessarily need to delete the CNG key, but we delete the config file
	return os.Remove(path)
}
