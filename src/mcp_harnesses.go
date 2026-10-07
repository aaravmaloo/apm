package apm

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// An MCPHarness is an AI assistant pm knows how to add itself to. Kind says
// how: "cli" runs the assistant's own command (Argv), "deeplink" opens URL in
// the assistant, and "file" merges Entry into the assistant's config file
// under ConfigKey. Every way starts `pm mcp serve --client <ID>`.
type MCPHarness struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Kind         string            `json:"kind"`
	Argv         []string          `json:"argv,omitempty"`
	URL          string            `json:"url,omitempty"`
	Restart      string            `json:"restart,omitempty"`
	ConfigFiles  map[string]string `json:"configFiles,omitempty"`
	ConfigFormat string            `json:"configFormat,omitempty"`
	ConfigKey    string            `json:"configKey,omitempty"`
	Entry        json.RawMessage   `json:"entry,omitempty"`
	ClientInfo   string            `json:"clientInfoName,omitempty"`
	Notes        string            `json:"notes,omitempty"`
	// AliasOf names the harness whose setup this one shares (the ChatGPT
	// desktop app uses Codex's), so pm runs as --client <AliasOf>.
	AliasOf string `json:"aliasOf,omitempty"`
}

// mcp_harnesses.json lists the harnesses in popularity order.
//
//go:embed mcp_harnesses.json
var mcpHarnessesJSON []byte

var mcpHarnesses = func() []MCPHarness {
	var list []MCPHarness
	if err := json.Unmarshal(mcpHarnessesJSON, &list); err != nil {
		panic("mcp_harnesses.json: " + err.Error())
	}
	return list
}()

// MCPHarnesses returns the known harnesses in popularity order.
func MCPHarnesses() []MCPHarness {
	out := make([]MCPHarness, len(mcpHarnesses))
	copy(out, mcpHarnesses)
	return out
}

// GetMCPHarness finds a harness by id.
func GetMCPHarness(id string) (MCPHarness, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, h := range mcpHarnesses {
		if h.ID == id {
			return h, true
		}
	}
	return MCPHarness{}, false
}

// MCPHarnessName is the display name for a harness id, or "" if unknown.
func MCPHarnessName(id string) string {
	if h, ok := GetMCPHarness(id); ok {
		return h.Name
	}
	return ""
}

// MCPServeArgs are the arguments an assistant passes to pm.
func MCPServeArgs(harness string) []string {
	args := []string{"mcp", "serve"}
	if harness != "" {
		args = append(args, "--client", harness)
	}
	return args
}

// Command is the one-line setup as a person would type it: the harness's own
// command, or `pm mcp add <id>` for harnesses set up by a file or a link.
func (h MCPHarness) Command() string {
	if len(h.Argv) == 0 {
		return FormatArgv([]string{"pm", "mcp", "add", h.ID})
	}
	return FormatArgv(h.Argv)
}

// FormatArgv shows argv as a POSIX shell command line, quoting arguments
// that need it. It is for display; pm never runs it through a shell.
func FormatArgv(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = shellQuoteArg(a)
	}
	return strings.Join(parts, " ")
}

func shellQuoteArg(a string) string {
	if a == "" {
		return "''"
	}
	safe := true
	for _, r := range a {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./=:@%+,", r)) {
			safe = false
			break
		}
	}
	if safe {
		return a
	}
	return "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
}

// ConfigFile is where the harness keeps its MCP servers on this OS, or "".
func (h MCPHarness) ConfigFile() string {
	key := runtime.GOOS
	if key == "windows" {
		key = "win32"
	}
	return ExpandMCPConfigPath(h.ConfigFiles[key])
}

// ExpandMCPConfigPath expands ~, $HOME, %USERPROFILE%, %APPDATA% and
// $XDG_CONFIG_HOME in a config path.
func ExpandMCPConfigPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	home, _ := os.UserHomeDir()
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = filepath.Join(home, "AppData", "Roaming")
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = filepath.Join(home, ".config")
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		p = home + p[1:]
	}
	r := strings.NewReplacer("%USERPROFILE%", home, "%APPDATA%", appData, "$HOME", home, "${HOME}", home, "$XDG_CONFIG_HOME", xdg, "${XDG_CONFIG_HOME}", xdg)
	return filepath.Clean(filepath.FromSlash(r.Replace(p)))
}

// MCPEntryWithCommand returns entry with the program "pm" replaced by
// pmPath, whether the entry has "command": "pm" or a command array that
// starts with "pm". Other keys and their order are kept.
func MCPEntryWithCommand(entry json.RawMessage, pmPath string) (json.RawMessage, error) {
	members, err := parseJSONObject(entry)
	if err != nil {
		return nil, err
	}
	for i, m := range members {
		if m.key != "command" {
			continue
		}
		var single string
		if json.Unmarshal(m.raw, &single) == nil {
			if single == "pm" {
				members[i].raw = jsonString(pmPath)
			}
			continue
		}
		var argv []string
		if json.Unmarshal(m.raw, &argv) == nil && len(argv) > 0 && argv[0] == "pm" {
			argv[0] = pmPath
			raw, _ := json.Marshal(argv)
			members[i].raw = raw
		}
	}
	var buf bytes.Buffer
	writeJSONObject(&buf, members, 0, "  ")
	var compact bytes.Buffer
	if err := json.Compact(&compact, buf.Bytes()); err != nil {
		return nil, err
	}
	return compact.Bytes(), nil
}

// ErrMCPConfigUnparseable means pm left a config file alone because it is
// not plain JSON (it may have comments or a syntax error).
var ErrMCPConfigUnparseable = errors.New("the file is not valid JSON")

// MergeMCPConfigFile adds (or replaces) the server called name, with entry
// as its definition, in the JSON config file at path, under keyPath (keys
// separated by "/"). Other keys, their order and their formatting are kept.
// An existing file is copied to <path>.apm-backup first; a missing one is
// created. It returns the backup path ("" when the file was new) and whether
// an existing entry was replaced.
func MergeMCPConfigFile(path, keyPath, name string, entry json.RawMessage) (backup string, replaced bool, err error) {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	original, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return "", false, err
	}
	mode := os.FileMode(0600)
	if exists {
		if st, err := os.Stat(path); err == nil {
			mode = st.Mode().Perm()
		}
	}
	out, replaced, err := mergeMCPConfig(original, keyPath, name, entry)
	if err != nil {
		return "", false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", false, err
	}
	if exists {
		backup = path + ".apm-backup"
		if err := os.WriteFile(backup, original, 0600); err != nil {
			return "", false, fmt.Errorf("could not back up %s: %w", path, err)
		}
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, out, mode); err != nil {
		return backup, false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return backup, false, err
	}
	return backup, replaced, nil
}

type jsonMember struct {
	key string
	raw json.RawMessage
}

func mergeMCPConfig(original []byte, keyPath, name string, entry json.RawMessage) ([]byte, bool, error) {
	if !json.Valid(entry) {
		return nil, false, errors.New("the server entry is not valid JSON")
	}
	var members []jsonMember
	unit := "  "
	if len(bytes.TrimSpace(original)) > 0 {
		var err error
		members, err = parseJSONObject(original)
		if err != nil {
			return nil, false, ErrMCPConfigUnparseable
		}
		unit = detectJSONIndent(original)
	}
	var path []string
	for _, k := range strings.Split(keyPath, "/") {
		if k = strings.TrimSpace(k); k != "" {
			path = append(path, k)
		}
	}
	members, replaced, err := setJSONMember(members, path, name, entry, 0, unit)
	if err != nil {
		return nil, false, err
	}
	var buf bytes.Buffer
	writeJSONObject(&buf, members, 0, unit)
	buf.WriteByte('\n')
	return buf.Bytes(), replaced, nil
}

func parseJSONObject(data []byte) ([]jsonMember, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	members := []jsonMember{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("object key is not a string")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		members = append(members, jsonMember{key: key, raw: raw})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after the JSON object")
	}
	return members, nil
}

// detectJSONIndent returns the indent of the first nested line, or two
// spaces for a one-line file.
func detectJSONIndent(data []byte) string {
	i := bytes.IndexByte(data, '\n')
	if i < 0 {
		return "  "
	}
	rest := data[i+1:]
	n := 0
	for n < len(rest) && (rest[n] == ' ' || rest[n] == '\t') {
		n++
	}
	if n == 0 {
		return "  "
	}
	return string(rest[:n])
}

func setJSONMember(members []jsonMember, path []string, name string, entry json.RawMessage, depth int, unit string) ([]jsonMember, bool, error) {
	key := name
	if len(path) > 0 {
		key = path[0]
	}
	idx := -1
	for i, m := range members {
		if m.key == key {
			idx = i
			break
		}
	}
	var value json.RawMessage
	replaced := false
	if len(path) == 0 {
		var buf bytes.Buffer
		if err := json.Indent(&buf, entry, strings.Repeat(unit, depth+1), unit); err != nil {
			return nil, false, err
		}
		value = buf.Bytes()
		replaced = idx >= 0
	} else {
		var child []jsonMember
		if idx >= 0 && strings.TrimSpace(string(members[idx].raw)) != "null" {
			var err error
			child, err = parseJSONObject(members[idx].raw)
			if err != nil {
				return nil, false, fmt.Errorf("%q is not an object", key)
			}
		}
		child, r, err := setJSONMember(child, path[1:], name, entry, depth+1, unit)
		if err != nil {
			return nil, false, err
		}
		replaced = r
		var buf bytes.Buffer
		writeJSONObject(&buf, child, depth+1, unit)
		value = buf.Bytes()
	}
	if idx < 0 {
		return append(members, jsonMember{key: key, raw: value}), replaced, nil
	}
	members[idx].raw = value
	// A duplicate key would override the one just set.
	out := members[:idx+1]
	for _, m := range members[idx+1:] {
		if m.key != key {
			out = append(out, m)
		}
	}
	return out, replaced, nil
}

func writeJSONObject(buf *bytes.Buffer, members []jsonMember, depth int, unit string) {
	if len(members) == 0 {
		buf.WriteString("{}")
		return
	}
	buf.WriteString("{\n")
	for i, m := range members {
		buf.WriteString(strings.Repeat(unit, depth+1))
		buf.Write(jsonString(m.key))
		buf.WriteString(": ")
		buf.Write(m.raw)
		if i < len(members)-1 {
			buf.WriteByte(',')
		}
		buf.WriteByte('\n')
	}
	buf.WriteString(strings.Repeat(unit, depth))
	buf.WriteByte('}')
}

func jsonString(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return bytes.TrimRight(buf.Bytes(), "\n")
}
