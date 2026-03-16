package inject

import (
	"bytes"
	"os"
	"runtime"
	"strings"
)

type Shell int

const (
	Bash Shell = iota
	Zsh
	Fish
	PowerShell
)

func DetectShell() Shell {
	shell, ok := DetectShellFromEnv(os.Getenv("SHELL"))
	if ok {
		return shell
	}
	if runtime.GOOS == "windows" && os.Getenv("PSModulePath") != "" {
		return PowerShell
	}
	return Bash
}

func DetectShellFromEnv(shellEnv string) (Shell, bool) {
	s := strings.ToLower(strings.TrimSpace(shellEnv))
	switch {
	case strings.Contains(s, "fish"):
		return Fish, true
	case strings.Contains(s, "zsh"):
		return Zsh, true
	case strings.Contains(s, "bash"):
		return Bash, true
	case strings.Contains(s, "pwsh") || strings.Contains(s, "powershell"):
		return PowerShell, true
	default:
		return Bash, false
	}
}

func WriteExports(entries []ResolvedEntry, sessionID string, shell Shell) string {
	var buf bytes.Buffer
	for i := range entries {
		e := entries[i]
		if strings.TrimSpace(e.EnvVarName) == "" {
			continue
		}
		writeExportLine(&buf, e.EnvVarName, e.Value, shell)
	}
	if strings.TrimSpace(sessionID) != "" {
		writeExportLine(&buf, "APM_INJECT_SESSION", []byte(sessionID), shell)
	}

	out := buf.String()
	zeroBytes(buf.Bytes())
	return out
}

func WriteUnsets(varNames []string, shell Shell) string {
	var buf bytes.Buffer
	for _, name := range varNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		switch shell {
		case Fish:
			buf.WriteString("set -e ")
			buf.WriteString(name)
			buf.WriteString(";\n")
		case PowerShell:
			buf.WriteString("Remove-Item Env:")
			buf.WriteString(name)
			buf.WriteString(" -ErrorAction SilentlyContinue;\n")
		case Zsh, Bash:
			fallthrough
		default:
			buf.WriteString("unset ")
			buf.WriteString(name)
			buf.WriteString(";\n")
		}
	}

	out := buf.String()
	zeroBytes(buf.Bytes())
	return out
}

func writeExportLine(buf *bytes.Buffer, name string, value []byte, shell Shell) {
	switch shell {
	case Fish:
		buf.WriteString("set -x ")
		buf.WriteString(name)
		buf.WriteByte(' ')
		escaped := escapeDoubleQuoted(value, shell)
		buf.Write(escaped)
		zeroBytes(escaped)
		buf.WriteString(";\n")
	case PowerShell:
		buf.WriteString("$env:")
		buf.WriteString(name)
		buf.WriteString(" = ")
		escaped := escapeSingleQuoted(value, shell)
		buf.Write(escaped)
		zeroBytes(escaped)
		buf.WriteString(";\n")
	case Zsh, Bash:
		fallthrough
	default:
		buf.WriteString("export ")
		buf.WriteString(name)
		buf.WriteByte('=')
		escaped := escapeSingleQuoted(value, shell)
		buf.Write(escaped)
		zeroBytes(escaped)
		buf.WriteString(";\n")
	}
}

func escapeSingleQuoted(value []byte, shell Shell) []byte {
	if len(value) == 0 {
		return []byte("''")
	}
	out := make([]byte, 0, len(value)+2)
	out = append(out, '\'')
	for _, b := range value {
		if b == '\'' {
			out = append(out, '\'', '\\', '\'', '\'')
			continue
		}
		out = append(out, b)
	}
	out = append(out, '\'')
	return out
}

func escapeDoubleQuoted(value []byte, shell Shell) []byte {
	if len(value) == 0 {
		return []byte("\"\"")
	}
	out := make([]byte, 0, len(value)+2)
	out = append(out, '"')
	for _, b := range value {
		switch b {
		case '\\', '"', '$', '`':
			out = append(out, '\\', b)
		default:
			out = append(out, b)
		}
	}
	out = append(out, '"')
	return out
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
