package autofillcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"password-manager/src/autofill"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type Options struct {
	VaultPath    *string
	ReadPassword func() (string, error)
}

func NewAutofillAndVaultCommands(opts Options) (*cobra.Command, *cobra.Command) {
	if opts.VaultPath == nil {
		panic("vault path pointer is required")
	}
	if opts.ReadPassword == nil {
		panic("read password callback is required")
	}

	var daemonHotkey string

	autofillCmd := &cobra.Command{
		Use:   "autofill",
		Short: "Manage the autofill daemon and providers",
	}

	autofillStartCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the autofill daemon",
		Run: func(cmd *cobra.Command, args []string) {
			if err := ensureAutofillDaemonRunning(*opts.VaultPath, daemonHotkey); err != nil {
				color.Red("Failed to start autofill daemon: %v", err)
				return
			}
			color.Green("Autofill daemon started.")
		},
	}
	autofillStartCmd.Flags().StringVar(&daemonHotkey, "hotkey", "CTRL+SHIFT+ALT+A", "Global hotkey for system autofill")

	autofillStopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the autofill daemon",
		Run: func(cmd *cobra.Command, args []string) {
			client, err := autofill.NewClientFromState()
			if err != nil {
				color.Yellow("Autofill daemon is not running.")
				_ = autofill.ClearDaemonState()
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := client.Stop(ctx); err != nil {
				color.Yellow("Autofill daemon stop failed: %v", err)
				_ = autofill.ClearDaemonState()
				return
			}
			color.Green("Autofill daemon stopped.")
		},
	}

	autofillStatusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show autofill daemon status",
		Run: func(cmd *cobra.Command, args []string) {
			client, err := autofill.NewClientFromState()
			if err != nil {
				fmt.Println("Status: stopped")
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			status, err := client.Status(ctx)
			if err != nil {
				fmt.Println("Status: stopped")
				_ = autofill.ClearDaemonState()
				return
			}

			state := "unlocked"
			if status.Locked {
				state = "locked"
			}
			fmt.Printf("Status: %s\n", state)
			fmt.Printf("PID: %d\n", status.PID)
			fmt.Printf("Hotkey: %s\n", status.Hotkey)
			fmt.Printf("System Engine: %s\n", status.SystemEngine)
			fmt.Printf("Profiles: %d\n", status.ProfileCount)
			if status.PendingSelection > 0 {
				fmt.Printf("Pending Selection: %d matches\n", status.PendingSelection)
			}
		},
	}

	autofillProfilesCmd := &cobra.Command{
		Use:   "list-profiles",
		Short: "List autofill profiles available to the daemon",
		Run: func(cmd *cobra.Command, args []string) {
			client, err := autofill.NewClientFromState()
			if err != nil {
				color.Red("Autofill daemon is not running.")
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			profiles, err := client.ListProfiles(ctx)
			if err != nil {
				color.Red("Failed to list profiles: %v", err)
				return
			}
			if len(profiles) == 0 {
				fmt.Println("No profiles found.")
				return
			}

			fmt.Printf("%-32s %-25s %-20s %-20s\n", "PROFILE_ID", "SERVICE", "DOMAIN", "USERNAME")
			fmt.Println(strings.Repeat("-", 102))
			for _, p := range profiles {
				fmt.Printf("%-32s %-25s %-20s %-20s\n", p.ID, p.Service, p.Domain, p.EntryUsername)
			}
		},
	}

	autofillDaemonCmd := &cobra.Command{
		Use:    "daemon",
		Short:  "Run autofill daemon (internal)",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			hotkey, _ := cmd.Flags().GetString("hotkey")
			if err := autofill.Run(autofill.RunOptions{
				VaultPath: *opts.VaultPath,
				Hotkey:    hotkey,
			}); err != nil {
				color.Red("Autofill daemon failed: %v", err)
				os.Exit(1)
			}
		},
	}
	autofillDaemonCmd.Flags().String("hotkey", "CTRL+SHIFT+ALT+A", "Global hotkey for system autofill")

	autofillCmd.AddCommand(
		autofillStartCmd,
		autofillStopCmd,
		autofillStatusCmd,
		autofillProfilesCmd,
		autofillDaemonCmd,
	)

	vaultCmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage daemon vault lock state for autofill",
	}

	vaultUnlockCmd := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock vault in autofill daemon",
		Run: func(cmd *cobra.Command, args []string) {
			timeout, _ := cmd.Flags().GetDuration("timeout")
			inactivity, _ := cmd.Flags().GetDuration("inactivity")
			hotkey, _ := cmd.Flags().GetString("hotkey")

			if err := ensureAutofillDaemonRunning(*opts.VaultPath, hotkey); err != nil {
				color.Red("Unable to start autofill daemon: %v", err)
				return
			}

			fmt.Print("Master Password: ")
			password, err := opts.ReadPassword()
			fmt.Println()
			if err != nil {
				color.Red("Failed to read password: %v", err)
				return
			}
			if strings.TrimSpace(password) == "" {
				color.Red("Password cannot be empty.")
				return
			}

			client, err := autofill.NewClientFromState()
			if err != nil {
				color.Red("Autofill daemon unavailable: %v", err)
				return
			}

			req := autofill.UnlockRequest{
				MasterPassword:       password,
				SessionTimeoutSec:    int(timeout.Seconds()),
				InactivityTimeoutSec: int(inactivity.Seconds()),
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := client.Unlock(ctx, req); err != nil {
				color.Red("Unlock failed: %v", err)
				return
			}
			color.Green("Vault unlocked for autofill daemon.")
		},
	}
	vaultUnlockCmd.Flags().Duration("timeout", 1*time.Hour, "Unlock duration")
	vaultUnlockCmd.Flags().Duration("inactivity", 15*time.Minute, "Inactivity auto-lock duration")
	vaultUnlockCmd.Flags().String("hotkey", "CTRL+SHIFT+ALT+A", "Global hotkey used if daemon must be started")

	vaultLockCmd := &cobra.Command{
		Use:   "lock",
		Short: "Lock vault in autofill daemon",
		Run: func(cmd *cobra.Command, args []string) {
			client, err := autofill.NewClientFromState()
			if err != nil {
				color.Yellow("Autofill daemon is not running.")
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			if err := client.Lock(ctx); err != nil {
				color.Red("Failed to lock daemon vault: %v", err)
				return
			}
			color.Green("Vault locked in autofill daemon.")
		},
	}

	vaultCmd.AddCommand(vaultUnlockCmd, vaultLockCmd)
	return autofillCmd, vaultCmd
}

func ensureAutofillDaemonRunning(vaultPath, hotkey string) error {
	if status, err := autofill.TryStatus(context.Background()); err == nil && status != nil {
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	cmd := exec.Command(exe, "autofill", "daemon", "--vault", vaultPath, "--hotkey", hotkey)
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		if status, err := autofill.TryStatus(context.Background()); err == nil && status != nil {
			return nil
		}
	}
	return errors.New("daemon did not become ready")
}
