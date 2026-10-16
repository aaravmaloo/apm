package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	src "github.com/aaravmaloo/apm/src"
	"github.com/aaravmaloo/apm/src/touchid"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// pm watchtower replaces pm health and pm trust: one scan of the whole vault
// with a score, the findings behind it, the vault's setup, per-item trust and
// the activity log.

func newWatchtowerCmd() *cobra.Command {
	var all, asJSON, showDismissed bool
	var kind, space string
	var failUnder int
	cmd := &cobra.Command{
		Use:   "watchtower",
		Short: "Check the vault for weak, reused, old and breached passwords and risky setup",
		Long: "Watchtower checks every item in the vault: weak, reused and old passwords, breached passwords (opt-in), items about to expire, " +
			"sites without HTTPS, sites that offer two-factor or passkeys you haven't set up, weak SSH keys and certificates, open Wi-Fi, " +
			"used-up recovery codes and live API keys pasted into notes. It also checks the vault's setup.\n\n" +
			"The score goes from 0 to 100 and counts the share of items affected in each category, so a few problems in a big vault don't sink it. " +
			"Dismiss a finding you accept with 'pm watchtower ignore'.",
		Example: "  pm watchtower\n  pm watchtower --kind reused\n  pm watchtower --json\n  pm watchtower --fail-under 80\n  pm watchtower ignore reused:4f1c2a9e0b7d3c21 --reason \"Shared account\"",
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(runWatchtower(watchtowerFlags{all: all, json: asJSON, showDismissed: showDismissed, kind: kind, space: space, failUnder: failUnder, failSet: cmd.Flags().Changed("fail-under")}))
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "List every finding, not only the top ones")
	cmd.Flags().StringVar(&kind, "kind", "", "Only show findings of this kind (weak, reused, breached, old, ...)")
	cmd.Flags().StringVar(&space, "space", "", "Only check items in this space")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print the full report as JSON, as the desktop app reads it")
	cmd.Flags().IntVar(&failUnder, "fail-under", 0, "Exit with status 1 when the score is below this, for scripts and CI")
	cmd.Flags().BoolVar(&showDismissed, "show-dismissed", false, "Also list dismissed findings")
	cmd.AddCommand(newWatchtowerIgnoreCmd(), newWatchtowerRestoreCmd(), newWatchtowerTrustCmd(), newWatchtowerMarkCmd(), newWatchtowerBreachCmd(), newWatchtowerActivityCmd())
	return cmd
}

type watchtowerFlags struct {
	all, json, showDismissed bool
	kind, space              string
	failUnder                int
	failSet                  bool
}

func watchtowerKindLabel(kind string) (string, bool) {
	for _, k := range src.WatchtowerKinds {
		if k.Kind == kind {
			return k.Label, true
		}
	}
	return "", false
}

func cliTouchID() (available, configured bool) {
	if runtime.GOOS != "darwin" || strings.TrimSpace(os.Getenv("APM_DESKTOP_NO_TOUCHID")) != "" {
		return false, false
	}
	configured = touchid.IsConfigured()
	return configured || touchid.IsAvailable(), configured
}

// scanForCLI runs a scan, keeps the day's score in the vault and saves it
// when something changed and the session can write.
func scanForCLI(pass string, v *src.Vault, readonly bool, space string, quiet bool) *src.WatchtowerReport {
	avail, conf := cliTouchID()
	changed := len(src.ScanActivity(v, &conf)) > 0
	if !readonly && src.BreachCheckDue(v) {
		if !quiet {
			fmt.Fprintln(os.Stderr, "Checking passwords against known breaches...")
		}
		_, err := src.RunBreachCheck(context.Background(), v)
		if err != nil && !quiet {
			color.Yellow("Breach check skipped: %v", err)
		}
		changed = true
	}
	opt := src.WatchtowerOptions{Space: space, TouchIDAvailable: avail, TouchIDConfigured: conf}
	rep := src.ScanWatchtower(v, opt)
	if readonly || v.IsNewerFormat() {
		return rep
	}
	if space == "" && src.RecordWatchtowerHistory(v, rep.Score) {
		changed = true
		rep = src.ScanWatchtower(v, opt)
	}
	if changed {
		if err := saveCLIVault(v, pass); err != nil && !quiet {
			cliSaveError(err)
		}
	}
	return rep
}

func runWatchtower(f watchtowerFlags) int {
	if f.kind != "" {
		if _, ok := watchtowerKindLabel(f.kind); !ok {
			kinds := make([]string, 0, len(src.WatchtowerKinds))
			for _, k := range src.WatchtowerKinds {
				kinds = append(kinds, k.Kind)
			}
			color.Red("Unknown kind %q. Use one of: %s.", f.kind, strings.Join(kinds, ", "))
			return 1
		}
	}
	pass, v, readonly, err := src_unlockVault()
	if err != nil {
		reportUnlockError(err)
		return 1
	}
	rep := scanForCLI(pass, v, readonly, f.space, f.json)
	src.LogAction("WATCHTOWER_SCAN", fmt.Sprintf("Score: %d", rep.Score))

	if f.json {
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(out))
	} else {
		printWatchtower(rep, f)
	}
	if f.failSet && rep.Score < f.failUnder {
		if !f.json {
			color.Red("Score %d is below %d.", rep.Score, f.failUnder)
		}
		return 1
	}
	return 0
}

func severityColor(sev string) func(format string, a ...interface{}) string {
	switch sev {
	case src.SeverityCritical:
		return color.HiRedString
	case src.SeverityHigh:
		return color.RedString
	case src.SeverityMedium:
		return color.YellowString
	}
	return color.CyanString
}

func gradeColor(score int) func(format string, a ...interface{}) string {
	switch {
	case score >= 80:
		return color.HiGreenString
	case score >= 65:
		return color.YellowString
	}
	return color.HiRedString
}

// trendText prints the engine's trend, the same value the app shows.
func trendText(rep *src.WatchtowerReport) string {
	if rep.Trend == nil {
		return ""
	}
	d := rep.Trend.Delta
	when := time.UnixMilli(rep.Trend.Since).Format("Jan 2")
	switch {
	case d > 0:
		return color.GreenString("up %d since %s", d, when)
	case d < 0:
		return color.RedString("down %d since %s", -d, when)
	}
	return "unchanged since " + when
}

var setupCLIFix = map[string]string{
	"settings:recovery": "pm auth codes generate",
	"settings:alerts":   "pm auth alerts --enable",
	"settings:autolock": "pm autolock --idle 15m",
	"settings:touchid":  "pm auth touchid setup",
	"settings:profile":  "pm profile set standard",
	"settings:ai":       "pm mcp list",
	"settings:breach":   "pm watchtower breach on",
	"settings:audit":    "pm logs",
}

func printWatchtower(rep *src.WatchtowerReport, f watchtowerFlags) {
	fmt.Println()
	color.HiCyan("  Watchtower")
	color.HiCyan("  ==========")
	line := fmt.Sprintf("  Score %s  grade %s  %d items checked", gradeColor(rep.Score)("%d/100", rep.Score), gradeColor(rep.Score)(rep.Grade), rep.ItemsChecked)
	if t := trendText(rep); t != "" {
		line += "  (" + t + ")"
	}
	fmt.Println(line)
	if f.space != "" {
		fmt.Printf("  Space: %s\n", f.space)
	}
	if rep.Breach.Enabled {
		when := "never"
		if rep.Breach.LastChecked > 0 {
			when = src.HumanWhen(time.UnixMilli(rep.Breach.LastChecked), time.Now())
		}
		fmt.Printf("  Breach check: %d passwords checked, %d found in breaches, last run %s\n", rep.Breach.Checked, rep.Breach.Found, when)
	}

	fmt.Println()
	var cats []string
	for _, c := range rep.Categories {
		if c.Kind == "setup" || c.Count == 0 {
			continue
		}
		cats = append(cats, severityColor(c.Severity)("%s %d", c.Label, c.Count))
	}
	if len(cats) == 0 {
		color.Green("  No problems found in your items.")
	} else {
		fmt.Println("  " + strings.Join(cats, "   "))
	}

	if f.kind == "" {
		fmt.Println()
		color.HiCyan("  Setup")
		for _, s := range rep.Setup {
			mark := color.HiGreenString("✔")
			if !s.OK {
				mark = color.HiRedString("✘")
			}
			fmt.Printf("  %s %-20s %s", mark, s.Label, s.Detail)
			if !s.OK {
				if hint := setupCLIFix[s.Fix]; hint != "" {
					fmt.Printf("  %s", color.HiBlackString("(%s)", hint))
				}
			}
			fmt.Println()
		}
	}

	var list []src.Finding
	for _, fd := range rep.Findings {
		if fd.Kind == "setup" {
			continue
		}
		if f.kind != "" && fd.Kind != f.kind {
			continue
		}
		if fd.Dismissed != nil && !f.showDismissed {
			continue
		}
		list = append(list, fd)
	}
	if len(list) == 0 {
		fmt.Println()
		return
	}
	limit := len(list)
	if !f.all && f.kind == "" && limit > 10 {
		limit = 10
	}
	fmt.Println()
	if f.kind != "" {
		label, _ := watchtowerKindLabel(f.kind)
		color.HiCyan("  %s", label)
	} else if limit < len(list) {
		color.HiCyan("  Top findings")
	} else {
		color.HiCyan("  Findings")
	}
	for _, fd := range list[:limit] {
		sev := severityColor(fd.Severity)("%-8s", strings.ToUpper(fd.Severity))
		impact := ""
		if fd.Impact > 0 && fd.Dismissed == nil {
			impact = color.GreenString("+%d", fd.Impact)
		}
		fmt.Printf("  %s %-26s %-24s %s\n", sev, truncate(fd.Title, 26), truncate(fd.ItemTitle, 24), impact)
		fmt.Printf("           %s\n", fd.Body)
		if fd.ChangeURL != "" {
			fmt.Printf("           %s\n", color.HiBlackString(fd.ChangeURL))
		}
		if fd.Dismissed != nil {
			reason := fd.Dismissed.Reason
			if reason == "" {
				reason = "no reason given"
			}
			fmt.Printf("           %s\n", color.HiBlackString("Dismissed: %s", reason))
		}
		fmt.Printf("           %s\n", color.HiBlackString("id %s", fd.ID))
	}
	if limit < len(list) {
		fmt.Printf("\n  Showing %d of %d. Use --all to list every finding.\n", limit, len(list))
	}
	fmt.Println()
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func newWatchtowerIgnoreCmd() *cobra.Command {
	var reason string
	var days int
	cmd := &cobra.Command{
		Use:     "ignore <finding-id>",
		Short:   "Dismiss a finding so it no longer counts against the score",
		Example: "  pm watchtower ignore reused:4f1c2a9e0b7d3c21 --reason \"Shared account\"\n  pm watchtower ignore old:9a0b1c2d3e4f5a6b --days 30",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if days < 0 {
				cliFail("--days can't be negative.")
			}
			pass, v := unlockForWrite("dismiss findings")
			exitIfVaultNewer(v)
			if err := src.DismissFinding(v, args[0], reason, days); err != nil {
				cliFail("%v", err)
			}
			if err := saveCLIVault(v, pass); err != nil {
				cliSaveError(err)
				os.Exit(1)
			}
			src.LogAction("WATCHTOWER_DISMISSED", args[0])
			if days > 0 {
				color.Green("Dismissed %s for %d days.", args[0], days)
			} else {
				color.Green("Dismissed %s. Bring it back with 'pm watchtower restore %s'.", args[0], args[0])
			}
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "Why you accept this finding")
	cmd.Flags().IntVar(&days, "days", 0, "Dismiss for this many days (default: until restored)")
	return cmd
}

func newWatchtowerRestoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restore <finding-id>",
		Short: "Bring back a dismissed finding",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			pass, v := unlockForWrite("restore findings")
			exitIfVaultNewer(v)
			if !src.RestoreFinding(v, args[0]) {
				cliFail("%s isn't dismissed.", args[0])
			}
			if err := saveCLIVault(v, pass); err != nil {
				cliSaveError(err)
				os.Exit(1)
			}
			src.LogAction("WATCHTOWER_RESTORED", args[0])
			color.Green("Restored %s.", args[0])
		},
	}
}

func newWatchtowerTrustCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Show how much each item can be trusted, from its open findings, age, use, exposure and privilege",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			_, v, _, err := src_unlockVault()
			if err != nil {
				reportUnlockError(err)
				os.Exit(1)
			}
			rep := src.ScanWatchtower(v, src.WatchtowerOptions{})
			src.LogAction("TRUST_VIEWED", fmt.Sprintf("Displayed %d trust scores", len(rep.Trust)))
			if asJSON {
				out, _ := json.MarshalIndent(rep.Trust, "", "  ")
				fmt.Println(string(out))
				return
			}
			if len(rep.Trust) == 0 {
				fmt.Println("The vault has no items yet.")
				return
			}
			fmt.Println()
			color.HiCyan("  Trust scores")
			color.HiCyan("  ============")
			for _, t := range rep.Trust {
				space := t.Space
				if space == "" {
					space = "default"
				}
				level := trustLevelColor(t.Level)("%-8s", strings.ToUpper(t.Level))
				fmt.Printf("  %s %3d  %-28s %-12s %s\n", level, t.Score, truncate(t.ItemTitle, 28), t.ItemType, space)
				for _, r := range t.Reasons {
					fmt.Printf("                %s\n", color.HiBlackString("%s (%d)", r.Text, r.Delta))
				}
			}
			fmt.Println()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print the scores as JSON")
	return cmd
}

func trustLevelColor(level string) func(format string, a ...interface{}) string {
	switch level {
	case "critical":
		return color.HiRedString
	case "high":
		return color.RedString
	case "medium":
		return color.YellowString
	}
	return color.GreenString
}

// findItemByName finds one item by id or title, preferring an exact match.
func findItemByName(v *src.Vault, query string) (src.VaultItemRef, error) {
	query = strings.TrimSpace(query)
	if ref, ok := v.FindItem(query); ok {
		return ref, nil
	}
	var exact, partial []src.VaultItemRef
	for _, r := range v.ItemRefs() {
		switch {
		case strings.EqualFold(r.Title, query):
			exact = append(exact, r)
		case query != "" && strings.Contains(strings.ToLower(r.Title), strings.ToLower(query)):
			partial = append(partial, r)
		}
	}
	pick := exact
	if len(pick) == 0 {
		pick = partial
	}
	switch len(pick) {
	case 1:
		return pick[0], nil
	case 0:
		return src.VaultItemRef{}, fmt.Errorf("No item matches %q.", query)
	}
	names := make([]string, 0, len(pick))
	for _, r := range pick {
		names = append(names, fmt.Sprintf("%s (%s, id %s)", itemTitle(r), kindOf(r).Label, r.ID))
	}
	sort.Strings(names)
	return src.VaultItemRef{}, fmt.Errorf("Several items match %q: %s. Use the id.", query, strings.Join(names, "; "))
}

func newWatchtowerMarkCmd() *cobra.Command {
	var exposed, notExposed bool
	var privilege string
	cmd := &cobra.Command{
		Use:   "mark <item>",
		Short: "Mark an item as exposed or set how privileged it is",
		Long: "Mark an item as exposed when its secret may have leaked, so Watchtower lists it until you change it and clear the flag. " +
			"Privilege (standard, elevated, admin, root or critical) raises the severity of the item's findings and alerts you when an assistant reads it for the first time.",
		Example: "  pm watchtower mark github --exposed\n  pm watchtower mark github --not-exposed\n  pm watchtower mark \"AWS root\" --privilege root",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if exposed && notExposed {
				cliFail("Use --exposed or --not-exposed, not both.")
			}
			if !exposed && !notExposed && !cmd.Flags().Changed("privilege") {
				cliFail("Say what to mark: --exposed, --not-exposed or --privilege.")
			}
			var priv *string
			if cmd.Flags().Changed("privilege") {
				p := strings.ToLower(strings.TrimSpace(privilege))
				switch p {
				case "standard", "elevated", "admin", "root", "critical":
				default:
					cliFail("Privilege is standard, elevated, admin, root or critical.")
				}
				priv = &p
			}
			var exp *bool
			if exposed || notExposed {
				exp = &exposed
			}
			pass, v := unlockForWrite("mark items")
			exitIfVaultNewer(v)
			ref, err := findItemByName(v, args[0])
			if err != nil {
				cliFail("%v", err)
			}
			v.SetItemTelemetryFlags(ref, priv, exp)
			if err := saveCLIVault(v, pass); err != nil {
				cliSaveError(err)
				os.Exit(1)
			}
			var what []string
			if exp != nil {
				if *exp {
					what = append(what, "exposed")
				} else {
					what = append(what, "not exposed")
				}
			}
			if priv != nil {
				what = append(what, "privilege "+*priv)
			}
			src.LogAction("ITEM_MARKED", fmt.Sprintf("%s: %s", itemTitle(ref), strings.Join(what, ", ")))
			color.Green("Marked %s as %s.", itemTitle(ref), strings.Join(what, ", "))
		},
	}
	cmd.Flags().BoolVar(&exposed, "exposed", false, "The secret may have leaked")
	cmd.Flags().BoolVar(&notExposed, "not-exposed", false, "Clear the exposed flag")
	cmd.Flags().StringVar(&privilege, "privilege", "", "standard, elevated, admin, root or critical")
	return cmd
}

func newWatchtowerBreachCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "breach <on|off|check>",
		Short: "Turn the opt-in breach check on or off, or run it now",
		Long: "The breach check asks Have I Been Pwned whether your passwords appear in known data breaches. " +
			"Only the first 5 characters of each password's SHA-1 hash leave this computer, and the answer is padded, so neither your passwords nor which ones you asked about are revealed. " +
			"It is off until you turn it on. Unchanged passwords are checked again after a week.",
		Example:   "  pm watchtower breach on\n  pm watchtower breach check\n  pm watchtower breach off",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"on", "off", "check"},
		Run: func(cmd *cobra.Command, args []string) {
			action := strings.ToLower(args[0])
			if action != "on" && action != "off" && action != "check" {
				cliFail("Use on, off or check.")
			}
			pass, v := unlockForWrite("change the breach check")
			exitIfVaultNewer(v)
			switch action {
			case "on":
				src.SetBreachCheck(v, true)
				src.LogAction("SETTINGS_CHANGED", "breach check on")
				color.Green("Breach check on.")
			case "off":
				src.SetBreachCheck(v, false)
				if err := saveCLIVault(v, pass); err != nil {
					cliSaveError(err)
					os.Exit(1)
				}
				src.LogAction("SETTINGS_CHANGED", "breach check off")
				color.Yellow("Breach check off. Saved results were removed.")
				return
			case "check":
				if !src.BreachEnabled(v) {
					cliFail("The breach check is off. Turn it on with 'pm watchtower breach on'.")
				}
			}
			fmt.Println("Checking passwords against known breaches...")
			run, err := src.RunBreachCheck(context.Background(), v)
			if saveErr := saveCLIVault(v, pass); saveErr != nil {
				cliSaveError(saveErr)
				os.Exit(1)
			}
			if err != nil {
				cliFail("%v", err)
			}
			src.LogAction("BREACH_CHECK", fmt.Sprintf("checked %d, cached %d, found %d, failed %d", run.Checked, run.Cached, run.Found, run.Failed))
			msg := fmt.Sprintf("%d checked now, %d from the last week.", run.Checked, run.Cached)
			if run.Failed > 0 {
				msg += fmt.Sprintf(" %d couldn't be checked.", run.Failed)
			}
			fmt.Println(msg)
			if run.Found > 0 {
				color.Red("%d %s found in known breaches. Run 'pm watchtower --kind breached'.", run.Found, pluralWord(run.Found, "password"))
			} else {
				color.Green("No password found in known breaches.")
			}
		},
	}
}

func newWatchtowerActivityCmd() *cobra.Command {
	var all, asJSON bool
	cmd := &cobra.Command{
		Use:     "activity",
		Short:   "Review unusual activity: wrong passwords, new devices, bulk reveals, exports and assistant access",
		Example: "  pm watchtower activity\n  pm watchtower activity --all\n  pm watchtower activity ack evt_1a2b3c4d5e6f7a8b\n  pm watchtower activity ack --all",
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			pass, v, readonly, err := src_unlockVault()
			if err != nil {
				reportUnlockError(err)
				os.Exit(1)
			}
			_, conf := cliTouchID()
			if len(src.ScanActivity(v, &conf)) > 0 && !readonly && !v.IsNewerFormat() {
				if err := saveCLIVault(v, pass); err != nil {
					cliSaveError(err)
				}
			}
			events, unack := src.ListActivity(v, 0, all)
			if asJSON {
				views := make([]map[string]any, 0, len(events))
				for _, e := range events {
					views = append(views, e.View())
				}
				out, _ := json.MarshalIndent(map[string]any{"events": views, "unacknowledged": unack}, "", "  ")
				fmt.Println(string(out))
				return
			}
			if len(events) == 0 {
				color.Green("No new activity.")
				if !all {
					fmt.Println("Use --all to include events you marked as you.")
				}
				return
			}
			fmt.Println()
			color.HiCyan("  Activity")
			color.HiCyan("  ========")
			now := time.Now()
			for _, e := range events {
				sev := severityColor(e.Severity)("%-8s", strings.ToUpper(e.Severity))
				fmt.Printf("  %s %s  %s\n", sev, e.Title, color.HiBlackString(src.HumanWhen(e.At, now)))
				if e.Body != "" {
					fmt.Printf("           %s\n", e.Body)
				}
				meta := "id " + e.ID
				if e.Acknowledged {
					meta += ", marked as you"
				}
				fmt.Printf("           %s\n", color.HiBlackString(meta))
			}
			fmt.Println()
			if unack > 0 {
				fmt.Printf("  %d unreviewed. If they were you, run 'pm watchtower activity ack --all'.\n\n", unack)
			}
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "Include events already marked as you")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print the events as JSON")
	cmd.AddCommand(newWatchtowerActivityAckCmd())
	return cmd
}

func newWatchtowerActivityAckCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "ack [event-id]",
		Short: "Mark activity as yours (\"This was me\"). It also teaches Watchtower your usual unlock hours",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if all == (len(args) == 1) {
				cliFail("Give an event id or --all.")
			}
			pass, v := unlockForWrite("acknowledge activity")
			exitIfVaultNewer(v)
			if all {
				n := src.AckAllActivity(v)
				if err := saveCLIVault(v, pass); err != nil {
					cliSaveError(err)
					os.Exit(1)
				}
				src.LogAction("ACTIVITY_ACKNOWLEDGED", strconv.Itoa(n)+" events")
				color.Green("Marked %d %s as you.", n, pluralWord(n, "event"))
				return
			}
			if !src.AckActivity(v, args[0]) {
				cliFail("No event %s. Run 'pm watchtower activity --all' to see them.", args[0])
			}
			if err := saveCLIVault(v, pass); err != nil {
				cliSaveError(err)
				os.Exit(1)
			}
			src.LogAction("ACTIVITY_ACKNOWLEDGED", args[0])
			color.Green("Marked %s as you.", args[0])
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "Mark every event as you")
	return cmd
}

func newAuthLockoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lockout [N|off]",
		Short: "Require recovery after N wrong passwords (off by default)",
		Long: "Wrong passwords only ever add a wait before the next try: 30 seconds after the 4th, then 1, 5, 15 and 60 minutes. " +
			fmt.Sprintf("With a lockout set, the vault also stops accepting the master password after N wrong ones in a row (N is %d to 100), ", src.MinLockoutAfter) +
			"and only opens with recovery: 'pm auth recover' (recovery email and key) or 'pm auth quorum-recover' (trustee shares).\n\n" +
			"It can only be turned on once the vault has a recovery key ('pm auth email <address>') or trustee shares ('pm auth quorum-setup'). " +
			"Recovery codes and a recovery passkey are extra checks during recovery and can't open the vault on their own. " +
			"'pm auth reset' removes recovery and turns the lockout off with it.",
		Example: "  pm auth lockout\n  pm auth lockout 10\n  pm auth lockout off",
		Args:    cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				_, v, _, err := src_unlockVault()
				if err != nil {
					reportUnlockError(err)
					os.Exit(1)
				}
				if v.LockoutAfter > 0 {
					color.Cyan("The vault needs recovery after %d wrong passwords.", v.LockoutAfter)
					if !src.LockoutRecoveryReady(v) {
						color.Red("But it has no recovery key or trustee shares, so once the lockout trips nothing can open it. " +
							"Set up a recovery key with 'pm auth email <address>', or turn the lockout off with 'pm auth lockout off'.")
					}
				} else {
					color.Cyan("Lockout is off. Wrong passwords only add a wait before the next try.")
				}
				return
			}
			n := 0
			if !strings.EqualFold(args[0], "off") && args[0] != "0" {
				parsed, err := strconv.Atoi(args[0])
				if err != nil {
					cliFail("Give a number of wrong passwords or off.")
				}
				n = parsed
			}
			if err := src.ValidateLockoutAfter(n); err != nil {
				cliFail("%v", err)
			}
			pass, v := unlockForWrite("change the lockout")
			exitIfVaultNewer(v)
			if n > 0 && !src.LockoutRecoveryReady(v) {
				cliFail("Set up a recovery key first ('pm auth email <address>') or trustee shares ('pm auth quorum-setup'). " +
					"Recovery codes and a recovery passkey can't open the vault on their own, so this lockout would lock you out for good.")
			}
			v.LockoutAfter = n
			if err := saveCLIVault(v, pass); err != nil {
				cliSaveError(err)
				os.Exit(1)
			}
			src.LogAction("SETTINGS_CHANGED", fmt.Sprintf("lockout after %d", n))
			if n > 0 {
				color.Green("The vault now needs recovery after %d wrong passwords in a row.", n)
				src.SendAlert(v, src.LevelSettings, "LOCKOUT", fmt.Sprintf("The vault now needs recovery after %d wrong passwords.", n))
			} else {
				color.Yellow("Lockout off. Wrong passwords only add a wait before the next try.")
			}
		},
	}
}
