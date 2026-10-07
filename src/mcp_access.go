package apm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// How often an assistant's last use and use count are written back.
var mcpAssistantTouchEvery = time.Minute

// mcpAccess decides whether a tool call may run. With a legacy token the
// token's permissions apply for the whole session. Without one the client is
// paired: after MCP initialize pm looks up the grant for this harness and
// client, or asks the user to allow it, and every call re-reads the grant so
// a revoke or a permission change applies to the next call.
type mcpAccess struct {
	token *MCPToken

	harness   string
	serverCtx context.Context
	identOnce sync.Once
	decided   chan struct{}

	// pairMu serializes starting the pairing; started is set once a grant
	// was found or the user was asked (or asking failed).
	pairMu  sync.Mutex
	started bool
	blocked bool // a refusal under new_assistants block was logged

	mu       sync.Mutex
	client   string // display name
	clientID string // clientInfo.name
	version  string // clientInfo.version
	grantID  string
	txID     string // the connect request, while it may be pending
	denied   bool
	uses     int
	lastSave time.Time
	refs     map[string]string // get_entry's encrypted files, by path, to the entry's name
}

func newMCPTokenAccess(t MCPToken) *mcpAccess {
	a := &mcpAccess{token: &t, decided: make(chan struct{})}
	close(a.decided)
	return a
}

func newMCPPairedAccess(serverCtx context.Context, harness string) *mcpAccess {
	return &mcpAccess{harness: strings.ToLower(strings.TrimSpace(harness)), serverCtx: serverCtx, decided: make(chan struct{})}
}

// name is who the vault's audit log and approval prompts show.
func (a *mcpAccess) name() string {
	if a.token != nil {
		return a.token.Name
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.client
}

func (a *mcpAccess) deniedResult() *mcp.CallToolResult {
	client := a.name()
	return mcpError(fmt.Sprintf("APM didn't allow %s. Ask again by restarting %s.", client, client))
}

// identify reads who the client says it is from its MCP initialize. It runs
// once, from the initialized notification or the first tool call.
func (a *mcpAccess) identify(ss *mcp.ServerSession) {
	a.identOnce.Do(func() {
		var info mcp.Implementation
		if ss != nil {
			if p := ss.InitializeParams(); p != nil && p.ClientInfo != nil {
				info = *p.ClientInfo
			}
		}
		clientID := strings.TrimSpace(info.Name)
		client := MCPHarnessName(a.harness)
		if client == "" {
			client = strings.TrimSpace(info.Title)
		}
		if client == "" {
			client = clientID
		}
		if client == "" {
			client = "An AI assistant"
		}
		a.mu.Lock()
		a.client, a.clientID, a.version = client, clientID, strings.TrimSpace(info.Version)
		a.mu.Unlock()
	})
}

// begin identifies the client and starts pairing: it finds the grant for
// this harness and client or asks the user to allow it. While MCP access is
// paused, or new assistants are blocked and this one is unknown, it asks
// nobody and returns the refusal; a later call tries again, so resuming or
// allowing new assistants applies without a restart.
func (a *mcpAccess) begin(ss *mcp.ServerSession) *mcp.CallToolResult {
	if a.token != nil {
		return nil
	}
	policy, err := LoadMCPPolicy()
	if err != nil {
		return mcpError(fmt.Sprintf("Could not read APM's MCP settings: %v", err))
	}
	return a.beginWith(ss, policy)
}

func (a *mcpAccess) beginWith(ss *mcp.ServerSession, policy MCPPolicy) *mcp.CallToolResult {
	if a.token != nil {
		return nil
	}
	a.identify(ss)
	a.pairMu.Lock()
	defer a.pairMu.Unlock()
	if a.started {
		return nil
	}
	if policy.Paused {
		return mcpError(MCPPausedText)
	}
	a.mu.Lock()
	client, clientID, version := a.client, a.clientID, a.version
	a.mu.Unlock()

	if g, err := FindMCPAssistant(a.harness, clientID); err == nil {
		a.started = true
		a.allow(g.ID)
		return nil
	}
	if policy.NewAssistants == MCPNewBlock {
		if !a.blocked {
			a.blocked = true
			LogAction("MCP_ASSISTANT_BLOCKED", fmt.Sprintf("Refused new assistant '%s': new assistants are blocked", client))
		}
		return mcpError(MCPBlockedNewText)
	}
	a.started = true
	tx, err := CreateMCPConnectTransaction(MCPConnectArgs{
		Client:   client,
		ClientID: clientID,
		Version:  version,
		Harness:  a.harness,
	}, mcpApprovalWait)
	if err != nil {
		a.deny("could not ask for approval: " + err.Error())
		return nil
	}
	a.mu.Lock()
	a.txID = tx.ID
	a.mu.Unlock()
	notifyApprover(tx)
	go a.watchConnect(tx.ID)
	return nil
}

func (a *mcpAccess) allow(grantID string) {
	a.mu.Lock()
	a.grantID = grantID
	a.mu.Unlock()
	close(a.decided)
}

func (a *mcpAccess) deny(reason string) {
	a.mu.Lock()
	a.denied = true
	client := a.client
	a.mu.Unlock()
	LogAction("MCP_ASSISTANT_DENIED", fmt.Sprintf("Did not allow assistant '%s': %s", client, reason))
	close(a.decided)
}

// watchConnect waits for the user's answer to the connect request. The
// request expires when the approval wait does.
func (a *mcpAccess) watchConnect(id string) {
	tick := time.NewTicker(mcpApprovalPoll)
	defer tick.Stop()
	for {
		tx, err := GetMCPTransaction(id)
		switch {
		case errors.Is(err, ErrMCPTxNotFound), errors.Is(err, ErrMCPTxExpired):
			a.deny("the request expired")
			return
		case err != nil:
		case tx.Status == MCPTxRejected, tx.Status == MCPTxAborted:
			a.deny("rejected in APM")
			return
		case tx.Status == MCPTxFailed:
			a.deny(tx.Error)
			return
		case tx.Status == MCPTxApproved && tx.ClaimedBy == "":
			if g, ok, _ := CompleteMCPConnect(id, "serve"); ok {
				a.allow(g.ID)
				return
			}
		case tx.Status == MCPTxCommitted:
			// Completed by the APM app.
			a.mu.Lock()
			clientID := a.clientID
			a.mu.Unlock()
			if g, err := FindMCPAssistant(a.harness, clientID); err == nil {
				a.allow(g.ID)
			} else {
				a.deny("the grant is missing")
			}
			return
		}
		select {
		case <-a.serverCtx.Done():
			return
		case <-tick.C:
		}
	}
}

// check returns nil when the call may use perm, and otherwise the result to
// send back. Calls made before the user answers wait for the answer. The MCP
// settings are read on every call: a pause refuses everything, and with
// ask_before_secrets the read tools ask the user first.
func (a *mcpAccess) check(ctx context.Context, req *mcp.CallToolRequest, perm string) *mcp.CallToolResult {
	policy, err := LoadMCPPolicy()
	if err != nil {
		return mcpError(fmt.Sprintf("Could not read APM's MCP settings: %v", err))
	}
	if policy.Paused {
		return mcpError(MCPPausedText)
	}
	if a.token != nil {
		if !hasPermission(a.token.Permissions, perm) {
			return mcpError("Denied")
		}
	} else if res := a.checkGrant(ctx, req, perm, policy); res != nil {
		return res
	}
	if policy.AskBeforeSecrets && IsMCPReadTool(perm) {
		var raw json.RawMessage
		if req != nil && req.Params != nil {
			raw = req.Params.Arguments
		}
		return a.askToRead(ctx, perm, raw)
	}
	return nil
}

func (a *mcpAccess) checkGrant(ctx context.Context, req *mcp.CallToolRequest, perm string, policy MCPPolicy) *mcp.CallToolResult {
	var ss *mcp.ServerSession
	if req != nil {
		ss = req.Session
	}
	if res := a.beginWith(ss, policy); res != nil {
		return res
	}
	select {
	case <-a.decided:
	case <-ctx.Done():
		return mcpError("Cancelled while waiting for approval in APM.")
	}
	a.mu.Lock()
	denied, grantID := a.denied, a.grantID
	a.mu.Unlock()
	if denied {
		return a.deniedResult()
	}
	g, err := GetMCPAssistant(grantID)
	if errors.Is(err, ErrMCPAssistantNotFound) {
		return a.deniedResult()
	}
	if err != nil {
		return mcpError(fmt.Sprintf("Could not read APM's allowed assistants: %v", err))
	}
	if !hasPermission(g.Perms, perm) {
		return mcpError(fmt.Sprintf("Denied. %s isn't allowed to use %s. You can allow it in APM settings.", g.Name, perm))
	}
	a.touch(false)
	return nil
}

// bypassActive reports whether this assistant's changes are approved without
// asking right now. Legacy tokens always ask.
func (a *mcpAccess) bypassActive() bool {
	if a.token != nil {
		return false
	}
	a.mu.Lock()
	id := a.grantID
	a.mu.Unlock()
	if id == "" {
		return false
	}
	g, err := GetMCPAssistant(id)
	return err == nil && g.BypassActive(time.Now())
}

// rememberRef records which entry an encrypted get_entry file holds, so a
// read request for decrypt_entry can name it.
func (a *mcpAccess) rememberRef(path, name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.refs == nil {
		a.refs = map[string]string{}
	}
	a.refs[path] = name
}

// mcpReadRequestTTL is how long a read request waits for an answer.
var mcpReadRequestTTL = 2 * time.Minute

// mcpReadRequest turns a read tool's arguments into what the request stores
// and the prompt shows. decrypt_entry's reference is the key to the data, so
// only the entry's name is stored.
func (a *mcpAccess) mcpReadRequest(tool string, raw json.RawMessage) (json.RawMessage, string) {
	var in struct {
		Name     string `json:"name"`
		Category string `json:"category"`
		Query    string `json:"query"`
		Path     string `json:"path"`
	}
	_ = json.Unmarshal(raw, &in)
	var args any
	var preview string
	switch tool {
	case "get_entry":
		args = struct {
			Name     string `json:"name"`
			Category string `json:"category,omitempty"`
		}{in.Name, in.Category}
		preview = fmt.Sprintf("Read the secrets of %q", in.Name)
	case "decrypt_entry":
		a.mu.Lock()
		name := a.refs[in.Path]
		a.mu.Unlock()
		args = struct {
			Name string `json:"name"`
		}{name}
		preview = fmt.Sprintf("Read the secrets of %q", name)
		if name == "" {
			preview = "Read the secrets of an item"
		}
	case "get_totp":
		args = struct {
			Name string `json:"name"`
		}{in.Name}
		preview = fmt.Sprintf("Get the 2FA code for %q", in.Name)
	case "search_vault":
		args = struct {
			Query string `json:"query"`
		}{in.Query}
		preview = fmt.Sprintf("Search the vault for %q", in.Query)
	}
	out, _ := json.Marshal(args)
	return out, preview
}

// askToRead asks the user before a read tool runs and waits for the answer.
// nil means approved: the request is closed as committed, since there is
// nothing to apply, and the tool runs. A rejected, expired or cancelled
// request returns "Not allowed in APM.".
func (a *mcpAccess) askToRead(ctx context.Context, tool string, raw json.RawMessage) *mcp.CallToolResult {
	args, preview := a.mcpReadRequest(tool, raw)
	name := a.name()
	tx, err := CreateMCPTransaction(name, tool, args, preview, mcpReadRequestTTL)
	if err != nil {
		return mcpError(fmt.Sprintf("Could not ask for approval in APM: %v", err))
	}
	LogAction("MCP_TX_REQUESTED", fmt.Sprintf("Assistant '%s' requested: %s", name, preview))
	notifyApprover(tx)

	deadline := time.NewTimer(time.Until(tx.ExpiresAt))
	defer deadline.Stop()
	tick := time.NewTicker(mcpApprovalPoll)
	defer tick.Stop()
	for {
		cur, err := GetMCPTransaction(tx.ID)
		switch {
		case errors.Is(err, ErrMCPTxNotFound), errors.Is(err, ErrMCPTxExpired):
			return mcpError(MCPReadDeniedText)
		case err != nil:
		case cur.Status == MCPTxApproved, cur.Status == MCPTxApplying, cur.Status == MCPTxCommitted:
			if cur.Status != MCPTxCommitted {
				_, _ = FinalizeMCPTransaction(tx.ID, preview, true)
			}
			LogAction("MCP_READ_ALLOWED", fmt.Sprintf("Allowed in APM for assistant '%s': %s", name, preview))
			return nil
		case cur.Status != MCPTxPending:
			return mcpError(MCPReadDeniedText)
		}
		select {
		case <-tick.C:
			continue
		case <-deadline.C:
		case <-ctx.Done():
		}
		// Nobody answered in time, or the agent stopped waiting: withdraw the
		// request so the prompt goes away.
		_ = AbortMCPTransaction(tx.ID)
		if cur, err := GetMCPTransaction(tx.ID); err == nil && (cur.Status == MCPTxApproved || cur.Status == MCPTxCommitted) && ctx.Err() == nil {
			_, _ = FinalizeMCPTransaction(tx.ID, preview, true)
			return nil
		}
		return mcpError(MCPReadDeniedText)
	}
}

// close withdraws a connect request nobody answered while this server ran,
// so the prompt doesn't outlive the assistant, and saves the use count.
func (a *mcpAccess) close() {
	if a.token != nil {
		return
	}
	a.mu.Lock()
	id := a.txID
	a.mu.Unlock()
	if id != "" {
		_ = AbortMCPTransaction(id)
	}
	a.touch(true)
}

// touch counts a call and saves the count at most once per
// mcpAssistantTouchEvery, or now when flush is set.
func (a *mcpAccess) touch(flush bool) {
	if a.token != nil {
		return
	}
	a.mu.Lock()
	if !flush {
		a.uses++
	}
	if a.grantID == "" || a.uses == 0 || (!flush && time.Since(a.lastSave) < mcpAssistantTouchEvery) {
		a.mu.Unlock()
		return
	}
	id, n := a.grantID, a.uses
	a.uses = 0
	a.lastSave = time.Now()
	a.mu.Unlock()
	if err := TouchMCPAssistant(id, n, time.Now()); err != nil && !errors.Is(err, ErrMCPAssistantNotFound) {
		a.mu.Lock()
		a.uses += n
		a.mu.Unlock()
	}
}
