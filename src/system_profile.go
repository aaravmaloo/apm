package apm

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type SystemProfileInfo struct {
	OS             string
	Arch           string
	CPUCores       int
	TotalMemoryMB  uint64
	MemoryDetected bool
}

func DetectSystemProfileInfo() SystemProfileInfo {
	info := SystemProfileInfo{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		CPUCores: runtime.NumCPU(),
	}

	if memMB, err := detectTotalMemoryMB(); err == nil && memMB > 0 {
		info.TotalMemoryMB = memMB
		info.MemoryDetected = true
	}

	return info
}

func RecommendProfileForSystem(info SystemProfileInfo) (string, string) {
	if info.MemoryDetected {
		switch {
		case info.TotalMemoryMB >= 16384 && info.CPUCores >= 8:
			return "paranoid", fmt.Sprintf("%d CPU cores and %d MB RAM detected", info.CPUCores, info.TotalMemoryMB)
		case info.TotalMemoryMB >= 8192 && info.CPUCores >= 4:
			return "hardened", fmt.Sprintf("%d CPU cores and %d MB RAM detected", info.CPUCores, info.TotalMemoryMB)
		default:
			return "standard", fmt.Sprintf("%d CPU cores and %d MB RAM detected", info.CPUCores, info.TotalMemoryMB)
		}
	}

	if info.CPUCores >= 8 {
		return "hardened", fmt.Sprintf("%d CPU cores detected (RAM unavailable)", info.CPUCores)
	}
	return "standard", fmt.Sprintf("%d CPU cores detected (RAM unavailable)", info.CPUCores)
}

func detectTotalMemoryMB() (uint64, error) {
	switch runtime.GOOS {
	case "linux":
		return detectLinuxMemoryMB()
	case "darwin":
		return detectDarwinMemoryMB()
	case "windows":
		return detectWindowsMemoryMB()
	default:
		return 0, fmt.Errorf("unsupported OS for memory detection: %s", runtime.GOOS)
	}
}

func detectLinuxMemoryMB() (uint64, error) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, fmt.Errorf("invalid MemTotal format")
			}
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0, err
			}
			return kb / 1024, nil
		}
	}
	return 0, fmt.Errorf("MemTotal not found")
}

func detectDarwinMemoryMB() (uint64, error) {
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		return 0, err
	}
	bytesVal, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0, err
	}
	return bytesVal / 1024 / 1024, nil
}

func detectWindowsMemoryMB() (uint64, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory").Output()
	if err == nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			bytesVal, parseErr := strconv.ParseUint(trimmed, 10, 64)
			if parseErr == nil {
				return bytesVal / 1024 / 1024, nil
			}
		}
	}

	out, err = exec.Command("wmic", "computersystem", "get", "TotalPhysicalMemory", "/value").Output()
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(line, "TotalPhysicalMemory=") {
			value := strings.TrimPrefix(line, "TotalPhysicalMemory=")
			value = strings.TrimSpace(value)
			bytesVal, parseErr := strconv.ParseUint(value, 10, 64)
			if parseErr != nil {
				return 0, parseErr
			}
			return bytesVal / 1024 / 1024, nil
		}
	}

	return 0, fmt.Errorf("TotalPhysicalMemory not found in output: %q", bytes.TrimSpace(out))
}
