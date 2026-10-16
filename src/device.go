package apm

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

// Device identifies the machine and user an unlock came from. ID is a hash of
// the OS machine id and the user name, so it stays the same across hostname
// changes and never reveals either.
type Device struct {
	ID    string
	Label string
}

var (
	deviceOnce sync.Once
	deviceVal  Device
)

// currentDeviceFunc returns this machine's device. Tests replace it.
var currentDeviceFunc = func() Device {
	deviceOnce.Do(func() { deviceVal = detectDevice() })
	return deviceVal
}

// CurrentDevice is the machine and user pm runs as.
func CurrentDevice() Device {
	return currentDeviceFunc()
}

func detectDevice() Device {
	host, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	machine := machineID()
	if machine == "" {
		machine = host
	}
	sum := sha256.Sum256([]byte("apm-device\x00" + machine + "\x00" + user))
	label := strings.TrimSuffix(host, ".local")
	if user != "" {
		label += " (" + user + ")"
	}
	return Device{ID: hex.EncodeToString(sum[:])[:16], Label: label}
}

var ioregUUID = regexp.MustCompile(`"IOPlatformUUID" = "([^"]+)"`)

func machineID() string {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err == nil {
			if m := ioregUUID.FindSubmatch(out); m != nil {
				return string(m[1])
			}
		}
	case "linux":
		for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "" {
				return strings.TrimSpace(string(b))
			}
		}
	case "windows":
		out, err := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
		if err == nil {
			fields := strings.Fields(string(out))
			if len(fields) > 0 {
				return fields[len(fields)-1]
			}
		}
	}
	return ""
}
