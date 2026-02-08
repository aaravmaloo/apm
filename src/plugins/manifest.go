package plugins

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

type Manifest struct {
	Name                string   `json:"name"`
	Version             string   `json:"version"`
	Description         string   `json:"description"`
	Author              string   `json:"author"`
	PermissionsRequired []string `json:"permissions_required"`
	AllowedFileTypes    []string `json:"allowed_file_types"`
	Commands            []string `json:"commands"`
	Hooks               []string `json:"hooks"`
}

func (m *Manifest) Validate() error {
	if m.Name == "" {
		return fmt.Errorf("plugin name is required")
	}

	semverRegex := regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)
	if !semverRegex.MatchString(m.Version) {
		return fmt.Errorf("invalid version: %s (must follow semantic versioning)", m.Version)
	}

	allowedPermissions := map[string]bool{
		// Base
		"vault.read":       true,
		"vault.write":      true,
		"file.storage":     true,
		"crypto.use":       true,
		"network.outbound": true,

		// Vault
		"vault.delete":  true,
		"vault.import":  true,
		"vault.export":  true,
		"vault.backup":  true,
		"vault.restore": true,
		"vault.history": true,
		"vault.lock":    true,
		"vault.unlock":  true,
		"vault.sync":    true,

		// Vault Items
		"vault.item.create": true,
		"vault.item.read":   true,
		"vault.item.update": true,
		"vault.item.delete": true,
		"vault.item.move":   true,
		"vault.item.copy":   true,
		"vault.item.share":  true,

		// Vault Fields
		"vault.item.field.password.read":  true,
		"vault.item.field.password.write": true,
		"vault.item.field.username.read":  true,
		"vault.item.field.username.write": true,
		"vault.item.field.url.read":       true,
		"vault.item.field.url.write":      true,
		"vault.item.field.notes.read":     true,
		"vault.item.field.notes.write":    true,
		"vault.item.field.totp.read":      true,
		"vault.item.field.totp.write":     true,
		"vault.item.field.tags.read":      true,
		"vault.item.field.tags.write":     true,
		"vault.item.field.metadata.read":  true,
		"vault.item.field.metadata.write": true,
		"vault.item.field.custom.read":    true,
		"vault.item.field.custom.write":   true,

		// Network
		"network.http":     true,
		"network.https":    true,
		"network.ftp":      true,
		"network.sftp":     true,
		"network.ssh":      true,
		"network.ws":       true,
		"network.wss":      true,
		"network.tcp":      true,
		"network.udp":      true,
		"network.icmp":     true,
		"network.inbound":  true,
		"network.proxy":    true,
		"network.dns":      true,
		"network.api.rest": true,
		"network.api.grpc": true,

		// System
		"system.read":            true,
		"system.write":           true,
		"system.exec":            true,
		"system.env.read":        true,
		"system.env.write":       true,
		"system.process.read":    true,
		"system.process.write":   true,
		"system.process.kill":    true,
		"system.clipboard.read":  true,
		"system.clipboard.write": true,
		"system.notification":    true,
		"system.audio.record":    true,
		"system.audio.play":      true,
		"system.camera":          true,
		"system.location":        true,
		"system.power":           true,
		"system.usb.read":        true,
		"system.usb.write":       true,
		"system.bluetooth":       true,
		"system.wifi":            true,

		// Crypto
		"crypto.hash":          true,
		"crypto.random":        true,
		"crypto.encrypt":       true,
		"crypto.decrypt":       true,
		"crypto.sign":          true,
		"crypto.verify":        true,
		"crypto.key.generate":  true,
		"crypto.key.store":     true,
		"crypto.key.load":      true,
		"crypto.key.delete":    true,
		"crypto.cert.generate": true,
		"crypto.cert.validate": true,

		// Plugin Management
		"plugin.list":         true,
		"plugin.install":      true,
		"plugin.uninstall":    true,
		"plugin.update":       true,
		"plugin.config.read":  true,
		"plugin.config.write": true,
		"plugin.reload":       true,

		// UI
		"ui.prompt":          true,
		"ui.alert":           true,
		"ui.confirm":         true,
		"ui.toast":           true,
		"ui.dialog":          true,
		"ui.window.open":     true,
		"ui.window.close":    true,
		"ui.window.maximize": true,
		"ui.window.minimize": true,
		"ui.menu.add":        true,
		"ui.menu.remove":     true,
		"ui.theme.set":       true,
		"ui.font.set":        true,

		// User
		"user.read":          true,
		"user.write":         true,
		"user.auth":          true,
		"user.session.read":  true,
		"user.session.write": true,
		"user.profile.read":  true,
		"user.profile.write": true,
		"user.biometric":     true,

		// Audit
		"audit.read":       true,
		"audit.write":      true,
		"audit.log.read":   true,
		"audit.log.write":  true,
		"audit.alert.read": true,
		"audit.report":     true,

		// Database (Internal)
		"db.read":         true,
		"db.write":        true,
		"db.query":        true,
		"db.schema.read":  true,
		"db.schema.write": true,

		// AI / ML
		"ai.model.load": true,
		"ai.predict":    true,
		"ai.train":      true,

		// IoT / Hardware
		"iot.scan":    true,
		"iot.connect": true,
		"iot.control": true,

		// Cloud
		"cloud.sync":         true,
		"cloud.backup":       true,
		"cloud.restore":      true,
		"cloud.config.read":  true,
		"cloud.config.write": true,
	}

	for _, p := range m.PermissionsRequired {
		if allowedPermissions[p] {
			continue
		}
		// Allow wildcards (e.g. "vault.*")
		if len(p) > 2 && p[len(p)-2:] == ".*" {
			continue
		}
		return fmt.Errorf("unknown permission: %s", p)
	}

	return nil
}

func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	if err := m.Validate(); err != nil {
		return nil, err
	}

	return &m, nil
}
