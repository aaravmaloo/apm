# MCP Integration

APM ships with a built-in MCP server under `pm mcp`. Assistants are paired the way the browser extension is: you set one up once, approve it in APM the first time it connects, and it can then read your items and ask to change them. You approve every change.

## Add an assistant

```bash
pm mcp add
```

Pick your assistant from the list, or name it: `pm mcp add claude-code`. pm knows Claude Code, Cursor, VS Code, Codex, the ChatGPT desktop app, Gemini CLI, GitHub Copilot CLI, Claude Desktop, Windsurf (Devin Desktop), Antigravity, Cline, Junie, Zed, OpenCode, Kilo Code, Amp, Factory Droid, Warp, Qwen Code and LM Studio; `pm mcp add --help` lists their ids. Depending on the assistant, pm:

- prints its one-line setup command and runs it when you say yes. pm runs the program directly, without a shell,
- adds an `apm` entry to the config file it reads, keeping your other servers and settings, and saving the previous file as `<file>.apm-backup`. Desktop apps don't see your shell's `PATH`, so the entry names pm by its full path. If the file isn't plain JSON (for example it has comments), pm leaves it alone and prints the entry to add yourself,
- or opens its install link (Cursor, LM Studio).

Pass `--yes` to skip the questions. A sample session:

```text
$ pm mcp add
Which assistant do you use?
> Claude Code
  Cursor
  VS Code
  ...
To add APM to Claude Code, run:

  claude mcp add --scope user apm -- pm mcp serve --client claude-code

Run it now? [Y/n] y
Added APM to Claude Code.

Start a new Claude Code session, or run /mcp in Claude Code to check that APM is connected.
The first time Claude Code starts APM, approve it in the prompt.
```

## Approve it

The first time the assistant starts `pm mcp serve`, APM asks **Claude Code wants to use your vault**. Allow it with Touch ID or **Allow**; on a Mac without Touch ID, press Space. **Don't allow** or Esc declines. Tool calls made before you answer wait for it. If the assistant stops before you answer, the request is withdrawn. If you decline, or don't answer within 2 minutes, every tool returns `APM didn't allow <assistant>. Ask again by restarting <assistant>.`

A newly allowed assistant can list, search and read items, read 2FA codes, generate passwords, and ask to add, change or delete items. Tools that apply without asking you (spaces, profiles, cloud sync and config, history, audit logs) are off until you turn them on in **Settings → AI access**. See [Permissions](../concepts/mcp.md#permissions).

## Manage assistants

- `pm mcp list` shows the allowed assistants, when each was last used, and any legacy tokens.
- `pm mcp revoke <name|id>` stops one. A running assistant is denied from its next call.
- **Settings → AI access** in the desktop app shows the same list, lets you change each assistant's permissions, and revoke it. Changes apply from the assistant's next call.

## Other assistants

For an assistant `pm mcp add` doesn't know, print the generic entry and add it to its MCP settings:

```bash
pm mcp config
```

```json
{
  "mcpServers": {
    "apm": {
      "command": "pm",
      "args": ["mcp", "serve"]
    }
  }
}
```

It's paired by the name it reports when it connects.

## Session requirements

The server does not unlock the vault by itself. It expects one of these:

- a normal unlocked session from `pm unlock`
- an ephemeral delegated session provided through `APM_EPHEMERAL_ID`

Ephemeral sessions can also be bound to an agent name through `APM_EPHEMERAL_AGENT`.

## Mutation guardrails

Write tools never commit on their own:

1. The call creates a pending transaction.
2. APM shows an approval prompt on top of every window and Space. Approve it with Touch ID, by clicking **Approve**, or (without Touch ID) by pressing Space. Esc or **Reject** rejects it. The assistant cannot approve it.
3. The call waits up to 2 minutes for your answer and returns the outcome. An approved transaction is applied, shows in History, and gets a receipt string.
4. If you don't answer in time, the call returns the `tx_id` and says it's still waiting. You can still answer within 15 minutes (or the expiry you chose with `pm mcp settings --expiry`), and the assistant can check with `tx_list`.

If the APM app isn't running, `pm mcp serve` shows the prompt itself. When the vault is locked in the app, `pm mcp serve` applies the approved change through your `pm unlock` session; without one, the app applies it when you next unlock.

This applies to the entry add, edit, and delete tools.

## Settings

A few settings apply to every assistant. See [MCP settings](../concepts/mcp.md#settings) for what each does.

```bash
pm mcp settings                                   # show them
pm mcp pause                                      # refuse every assistant's requests
pm mcp resume                                     # let them in again
pm mcp settings --approve-with touchid            # only a touch approves
pm mcp settings --expiry 5m                       # requests expire after 5 minutes
pm mcp settings --new-assistants block            # refuse assistants APM doesn't know
pm mcp settings --ask-before-secrets on           # ask before secrets, 2FA codes and searches
pm mcp bypass "Claude Code" 1h                    # approve its changes without asking for an hour
pm mcp bypass "Claude Code" ask                   # back to asking
```

Stricter settings apply at once. Looser ones (`resume`, `--approve-with any`, a longer `--expiry`, `--new-assistants ask`, `--ask-before-secrets off`, a bypass) ask for Touch ID or your master password, and are refused when pm isn't run at a terminal. The same settings are in **Settings → AI access** in the app, where loosening needs the vault unlocked.

## Tool categories

The MCP implementation covers more than simple vault reads. The current server code includes tooling for:

- entry listing and search
- secret retrieval and TOTP access
- entry mutation
- spaces
- profiles
- cloud sync and cloud config
- audit or history access

See the MCP tools reference for the exact schemas in this repo.

## Legacy tokens

Setups made with `pm mcp token` keep working: `pm mcp serve --token <token>` uses that token's permissions and is not paired. `pm mcp token` is hidden from help but still available. `pm mcp serve` without `--token` no longer falls back to a saved token.

## Recommended flow

```bash
pm unlock
pm mcp add
```

Then start the assistant and approve it in the prompt.
