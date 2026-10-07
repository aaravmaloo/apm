package apm

import (
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
)

const apmAppBundleID = "com.aaravmaloo.apm"

// runApprovalPrompt shows pm's own approval prompt for tx and blocks until the
// user answers or it is closed. ok=false means no prompt could be shown.
var runApprovalPrompt = func(tx MCPTransaction) (approve bool, via string, ok bool) { return false, "", false }

var lsappinfoPID = regexp.MustCompile(`"?pid"?\s*=\s*(\d+)`)

// apmAppRunning reports whether the APM desktop app is running on macOS.
func apmAppRunning() bool {
	out, err := exec.Command("lsappinfo", "info", "-only", "pid", "-app", apmAppBundleID).Output()
	if err != nil {
		return false
	}
	m := lsappinfoPID.FindSubmatch(out)
	if m == nil {
		return false
	}
	pid, err := strconv.Atoi(string(m[1]))
	return err == nil && pid > 0
}

// notifyApprover makes sure someone shows the approval prompt for tx. A
// running APM app polls the request store and shows its own prompt;
// otherwise pm shows one itself and records the answer. Tests replace it to
// see which requests asked the user.
var notifyApprover = defaultNotifyApprover

func defaultNotifyApprover(tx MCPTransaction) {
	if os.Getenv("APM_MCP_NO_APPROVER") == "1" {
		return
	}
	if runtime.GOOS == "darwin" && apmAppRunning() {
		return
	}
	go func() {
		approve, via, ok := runApprovalPrompt(tx)
		if !ok {
			return
		}
		recordPromptAnswer(tx, approve, via)
	}()
}

// recordPromptAnswer records the answer pm's own prompt got. An approval
// that doesn't satisfy the request's approve-with rule (a click on a Touch
// ID only request on a Mac with Touch ID) counts as no answer, so the
// request stays pending. The app may have answered first; its answer stands.
func recordPromptAnswer(tx MCPTransaction, approve bool, via string) {
	if approve && tx.ApproveWith == MCPApproveTouchID && !MCPApprovalAllowed(tx, via, MCPTouchIDAvailable()) {
		return
	}
	_, _ = DecideMCPTransaction(tx.ID, approve, via)
}
