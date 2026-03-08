package tui

import (
	"fmt"
	src "github.com/aaravmaloo/apm/src"
	"os"
	"path/filepath"
	runtime2 "runtime"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type InfoModel struct {
	vaultPath string
	status    string
	err       string
	content   string
}

func NewInfoModel(vaultPath string) InfoModel {
	m := InfoModel{vaultPath: vaultPath}
	m.refresh()
	return m
}

func (m InfoModel) Update(msg tea.Msg) (InfoModel, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "r", "ctrl+r":
			m.refresh()
			m.status = "Info refreshed"
			m.err = ""
		}
	}
	return m, nil
}

func (m *InfoModel) refresh() {
	var b strings.Builder
	homeDir, _ := os.UserHomeDir()
	homeName := filepath.Base(homeDir)
	processedHomeName := strings.ToLower(strings.ReplaceAll(homeName, " ", ""))
	exe, _ := os.Executable()
	installDir := filepath.Dir(exe)

	b.WriteString("APM v9.1 Stable Release\n")
	b.WriteString("----------------------\n\n")
	b.WriteString(fmt.Sprintf("User:       %s@apm\n", processedHomeName))
	b.WriteString(fmt.Sprintf("Installed:  %s\n", installDir))
	b.WriteString(fmt.Sprintf("Vault:      %s\n", m.vaultPath))
	b.WriteString(fmt.Sprintf("Platform:   %s/%s\n", runtime2.GOOS, runtime2.GOARCH))
	b.WriteString(fmt.Sprintf("Executable: %s\n", exe))
	b.WriteString("\nVersion:    9.1.0\n")
	b.WriteString("Build:      18dcd72 (23-02-2026)\n")
	b.WriteString("Repo:       github.com/aaravmaloo/apm\n")
	b.WriteString("Support:    aaravmaloo06@gmail.com\n\n")
	configValid := installDir != "" && m.vaultPath != ""

	if _, err := os.Stat(m.vaultPath); err != nil {
		b.WriteString("Status:\n")
		b.WriteString("  [x] Vault accessible\n")
		if configValid {
			b.WriteString("  [ ] Config valid\n")
		} else {
			b.WriteString("  [x] Config valid\n")
		}
		b.WriteString("  [x] All systems ok\n")
		m.content = b.String()
		return
	}
	b.WriteString("Status:\n")
	b.WriteString("  [ ] Vault accessible\n")
	if configValid {
		b.WriteString("  [ ] Config valid\n")
		b.WriteString("  [ ] All systems ok\n")
	} else {
		b.WriteString("  [x] Config valid\n")
		b.WriteString("  [x] All systems ok\n")
	}

	data, err := src.LoadVault(m.vaultPath)
	if err != nil {
		m.err = err.Error()
		m.content = b.String()
		return
	}
	profile, version, err := src.GetVaultParams(data)
	if err != nil {
		m.err = err.Error()
		m.content = b.String()
		return
	}
	b.WriteString("\nAPM Crypto Configuration\n")
	b.WriteString("------------------------\n")
	b.WriteString(fmt.Sprintf("Format:    APMVAULT v%d\n", version))
	b.WriteString(fmt.Sprintf("Profile:   %s\n", profile.Name))
	b.WriteString("KDF:       Argon2id\n")
	b.WriteString(fmt.Sprintf("  Time:    %d\n", profile.Time))
	b.WriteString(fmt.Sprintf("  Memory:  %d KB\n", profile.Memory/1024))
	b.WriteString(fmt.Sprintf("  Threads: %d\n", profile.Parallelism))
	b.WriteString("Cipher:    AES-256-GCM\n")
	b.WriteString(fmt.Sprintf("  Nonce:   %d bytes\n", profile.NonceLen))
	b.WriteString(fmt.Sprintf("  Salt:    %d bytes\n", profile.SaltLen))
	b.WriteString("Integrity: HMAC-SHA256 (Encrypt-then-MAC)\n")

	vaultDir := filepath.Dir(m.vaultPath)
	b.WriteString("\nPaths:\n")
	b.WriteString(fmt.Sprintf("Vault Dir: %s\n", vaultDir))
	b.WriteString(fmt.Sprintf("Policies:  %s\n", filepath.Join(vaultDir, "policies")))
	m.content = b.String()
}

func (m InfoModel) View() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render(" Info / Crypto "))
	b.WriteString("\n\n")
	b.WriteString(m.content)
	if m.err != "" {
		b.WriteString("\n")
		b.WriteString(ErrorStyle.Render("Error: " + m.err))
		b.WriteString("\n")
	}
	if m.status != "" {
		b.WriteString("\n")
		b.WriteString(SuccessStyle.Render(m.status))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(GrayStyle.Render("r: refresh info"))
	return BorderStyle.Render(b.String())
}
