package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/aaravmaloo/apm/internal/inject"
	apm "github.com/aaravmaloo/apm/src"
)

func BuildInjectCmd(unlock func() (string, *apm.Vault, bool, error)) *cobra.Command {
	var injectFlag string

	injectCmd := &cobra.Command{
		Use:          "inject",
		Short:        "Inject vault entries into the current shell session",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if unlock == nil {
				return errors.New("unlock handler not configured")
			}
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}

			if session, err := inject.ReadSession(); err == nil && session != nil {
				return fmt.Errorf("inject session already active [%s]. Run 'pm inject kill' first", session.ID)
			} else if err != nil && !errors.Is(err, inject.ErrSessionNotFound) {
				return err
			}

			_, vault, _, err := unlock()
			if err != nil {
				return err
			}

			names, mappings, err := resolveInjectTargets(injectFlag)
			if err != nil {
				return err
			}

			resolved, err := inject.ResolveEntries(vault, names)
			if err != nil {
				return err
			}

			if len(mappings) > 0 {
				for i := range resolved {
					if mappings[i].As != "" {
						resolved[i].EnvVarName = mappings[i].As
					}
				}
			}

			for i := range resolved {
				if resolved[i].EnvVarName == "" {
					resolved[i].EnvVarName = inject.ToEnvVarName(resolved[i].EntryName)
				}
			}

			shellEnv := os.Getenv("SHELL")
			if strings.TrimSpace(shellEnv) == "" {
				if os.Getenv("PSModulePath") != "" {
					shellEnv = "powershell"
				} else if comspec := os.Getenv("ComSpec"); strings.TrimSpace(comspec) != "" {
					shellEnv = comspec
				}
			}
			if _, ok := inject.DetectShellFromEnv(shellEnv); !ok {
				fmt.Fprintln(os.Stderr, "Warning: unknown shell; defaulting to bash syntax")
			}
			if strings.Contains(strings.ToLower(shellEnv), "powershell") || os.Getenv("PSModulePath") != "" {
				fmt.Fprintln(os.Stderr, "PowerShell tip: run `pm inject | Invoke-Expression` or use `pm inject setup-shell`.")
			}

			eval, err := inject.StartSession(resolved, shellEnv)
			if err != nil {
				return err
			}

			session, _ := inject.ReadSession()
			sessionID := ""
			if session != nil {
				sessionID = session.ID
			}

			entryNames := make([]string, 0, len(resolved))
			envNames := make([]string, 0, len(resolved))
			for _, e := range resolved {
				entryNames = append(entryNames, e.EntryName)
				if e.EnvVarName != "" {
					envNames = append(envNames, e.EnvVarName)
				}
			}

			apm.LogAction("INJECT_START", fmt.Sprintf("session=%s entries=%s shell=%s", sessionID, strings.Join(entryNames, ","), shellEnv))

			fmt.Fprint(os.Stdout, eval)

			green := color.New(color.FgGreen)
			if sessionID != "" {
				green.Fprintf(os.Stderr, "✓ Injected %d vars into session [%s]\n", len(envNames), sessionID)
			} else {
				green.Fprintf(os.Stderr, "✓ Injected %d vars into session\n", len(envNames))
			}
			if len(envNames) > 0 {
				fmt.Fprintln(os.Stderr, "  "+strings.Join(envNames, ", "))
			}

			return nil
		},
	}

	injectCmd.Flags().StringVar(&injectFlag, "inject", "", "Comma-separated list of vault entries to inject")

	killCmd := &cobra.Command{
		Use:          "kill",
		Short:        "Kill the active injection session and wipe env vars",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}

			shellEnv := os.Getenv("SHELL")
			if strings.TrimSpace(shellEnv) == "" && os.Getenv("PSModulePath") != "" {
				shellEnv = "powershell"
			}
			if _, ok := inject.DetectShellFromEnv(shellEnv); !ok {
				fmt.Fprintln(os.Stderr, "Warning: unknown shell; defaulting to bash syntax")
			}
			if strings.Contains(strings.ToLower(shellEnv), "powershell") || os.Getenv("PSModulePath") != "" {
				fmt.Fprintln(os.Stderr, "PowerShell tip: run `pm inject kill | Invoke-Expression` or use `pm inject setup-shell`.")
			}

			session, err := inject.ReadSession()
			if err != nil {
				if errors.Is(err, inject.ErrSessionNotFound) {
					fmt.Fprintln(os.Stderr, "No active injection session found.")
					return nil
				}
				return err
			}

			eval, err := inject.KillSession()
			if err != nil {
				return err
			}

			fmt.Fprint(os.Stdout, eval)

			duration := time.Since(session.InjectedAt)
			apm.LogAction("INJECT_KILL", fmt.Sprintf("session=%s duration=%s method=manual", session.ID, formatDuration(duration)))

			color.New(color.FgGreen).Fprintf(os.Stderr, "✓ Session [%s] killed. %d vars wiped. (active %s)\n", session.ID, len(session.VarNames), formatDuration(duration))
			return nil
		},
	}

	setupShellCmd := &cobra.Command{
		Use:   "setup-shell",
		Short: "Install an inject() shell function for eval-free usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}
			return setupShellFunction()
		},
	}

	injectCmd.AddCommand(killCmd, setupShellCmd)

	return injectCmd
}

func resolveInjectTargets(injectFlag string) ([]string, []inject.InjectMapping, error) {
	if strings.TrimSpace(injectFlag) != "" {
		parts := strings.Split(injectFlag, ",")
		names := make([]string, 0, len(parts))
		for _, p := range parts {
			name := strings.TrimSpace(p)
			if name == "" {
				continue
			}
			names = append(names, name)
		}
		if len(names) == 0 {
			return nil, nil, errors.New("no entries provided to --inject")
		}
		return names, nil, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil, err
	}

	path, err := inject.FindAPMInjectFile(cwd)
	if err != nil {
		if errors.Is(err, inject.ErrAPMInjectNotFound) {
			return nil, nil, errors.New("No .apminject file found. Use --inject to specify entries explicitly, or create a .apminject file.")
		}
		return nil, nil, err
	}

	mappings, err := inject.ParseAPMInjectFile(path)
	if err != nil {
		return nil, nil, err
	}

	names := make([]string, 0, len(mappings))
	for _, m := range mappings {
		names = append(names, m.Entry)
	}

	if len(names) == 0 {
		return nil, nil, fmt.Errorf("no entries listed in %s", path)
	}

	return names, mappings, nil
}

func setupShellFunction() error {
	shellEnv := os.Getenv("SHELL")
	shell, known := inject.DetectShellFromEnv(shellEnv)
	if !known {
		fmt.Fprintln(os.Stderr, "Warning: unknown shell; defaulting to bash configuration")
		shell = inject.Bash
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	var rcPath string
	var snippet string

	switch shell {
	case inject.Zsh:
		rcPath = filepath.Join(home, ".zshrc")
		snippet = "\n# APM inject helper\ninject() { eval $(pm inject \"$@\"); }\n"
	case inject.Fish:
		rcPath = filepath.Join(home, ".config", "fish", "config.fish")
		snippet = "\n# APM inject helper\nfunction inject\n    eval (pm inject $argv)\nend\n"
	case inject.PowerShell:
		profile := os.Getenv("PROFILE")
		if strings.TrimSpace(profile) == "" {
			return errors.New("PowerShell profile not found; set $PROFILE or configure manually")
		}
		rcPath = profile
		snippet = "\n# APM inject helper\nfunction inject { Invoke-Expression (pm inject $args) }\n"
	case inject.Bash:
		fallthrough
	default:
		rcPath = filepath.Join(home, ".bashrc")
		snippet = "\n# APM inject helper\ninject() { eval $(pm inject \"$@\"); }\n"
	}

	existing, _ := os.ReadFile(rcPath)
	if strings.Contains(string(existing), "inject() { eval $(pm inject") || strings.Contains(string(existing), "function inject") {
		color.Yellow("inject() already configured in %s", rcPath)
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(rcPath), 0700); err != nil {
		return err
	}

	f, err := os.OpenFile(rcPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(snippet); err != nil {
		return err
	}

	color.Green("inject() function added to %s", rcPath)
	return nil
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d > time.Second {
		d = d.Round(time.Second)
	}
	return d.String()
}
