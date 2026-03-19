# Injecting Secrets Into Your Shell

`pm inject` exports vault data into the **current shell session** as environment variables. It is meant for short-lived developer workflows such as local app startup, CI smoke testing, and ad hoc scripting where a process expects secrets through env vars.

Unlike `pm get`, `pm inject` does not print the secret values directly for you to copy. It emits shell-specific export commands, and you evaluate those commands in your shell.

---

## How It Works

`pm inject`:

1. Unlocks the vault using your normal APM flow
2. Resolves one or more vault entries by name
3. Converts those entries into environment variables
4. Stores a small local inject-session record so the variables can be removed later with `pm inject kill`

The command supports `bash`, `zsh`, `fish`, and `PowerShell`.

---

## Quick Start

### Bash / Zsh

```bash
eval "$(pm inject --inject github)"
```

### Fish

```fish
eval (pm inject --inject github)
```

### PowerShell

```powershell
pm inject --inject github | Invoke-Expression
```

After the command runs, the entry becomes an environment variable in the current shell.

For a password entry named `github`, the default variable name is:

```text
GITHUB
```

---

## Selecting Entries

You can inject explicit entry names:

```bash
pm inject --inject github,aws-prod,openai-token
```

Entry lookup is by vault item name in the active space. If any requested entry is missing, the command fails rather than partially injecting.

Supported entry sources include:

- Password entries
- TOTP entries
- Tokens
- Secure notes
- API keys
- SSH keys
- Wi-Fi passwords
- Recovery codes
- Certificates
- Cloud credential secret keys
- Docker registry tokens
- SSH config private keys

---

## `.apminject` Files

If you omit `--inject`, APM searches upward from the current directory for a `.apminject` file.

This lets you keep project-local injection rules in the repo or workspace root.

### Simple List Format

```yaml
- entry: github
- entry: aws-prod
```

### Wrapped Format

```yaml
inject:
  - entry: github
  - entry: aws-prod
```

You can also use `entries:` instead of `inject:`.

### Custom Variable Names

```yaml
inject:
  - entry: github
    as: GITHUB_TOKEN
  - entry: aws-prod
    as: AWS_SECRET_ACCESS_KEY
```

If `as` is omitted, APM derives a variable name automatically by uppercasing the entry name and replacing separators with underscores.

Examples:

- `github` -> `GITHUB`
- `aws-prod` -> `AWS_PROD`
- `openai token` -> `OPENAI_TOKEN`

---

## Recommended Workflow

For one-off usage:

```bash
eval "$(pm inject --inject github)"
```

For project usage with a checked-in `.apminject` file:

```bash
eval "$(pm inject)"
```

When you are done:

```bash
eval "$(pm inject kill)"
```

On PowerShell:

```powershell
pm inject kill | Invoke-Expression
```

`pm inject kill` removes the injected variables and clears the tracked inject session.

---

## `setup-shell`

APM can install a small shell helper so you do not have to type `eval` manually every time:

```bash
pm inject setup-shell
```

This adds an `inject()` helper to the detected shell config:

- `~/.bashrc` for Bash
- `~/.zshrc` for Zsh
- `~/.config/fish/config.fish` for Fish
- `$PROFILE` for PowerShell

After reloading your shell config, you can run:

```bash
inject --inject github
inject
inject kill
```

---

## Session Behavior

APM tracks one active inject session at a time. If a session is already active, `pm inject` will stop and ask you to run `pm inject kill` first.

The session record stores:

- A generated session ID
- The injected variable names
- Injection time
- Parent shell PID

By default, this record lives under your user config directory:

```text
<config>/apm/inject_session
```

If `APM_DATA_DIR` is set, APM stores it there instead.

---

## Security Notes

- Injected secrets live in your shell environment until you remove them or close the shell.
- Child processes inherit those environment variables.
- Prefer a dedicated shell for sensitive injection workflows.
- Use `pm inject kill` immediately after the dependent process exits.
- Do not commit `.apminject` files that reveal sensitive internal naming unless that is acceptable for the repo.

`pm inject` is convenient, but environment variables are still a wider exposure surface than keeping secrets only inside the vault.

---

## Troubleshooting

### No `.apminject` file found

Use `--inject` explicitly, or create a `.apminject` file in the current directory or a parent directory.

### Unknown shell warning

APM falls back to Bash syntax if it cannot detect the shell from environment variables.

### PowerShell does not persist variables

Use:

```powershell
pm inject --inject github | Invoke-Expression
```

Without `Invoke-Expression`, you will only print the export script instead of applying it.

### A session is already active

Run:

```bash
eval "$(pm inject kill)"
```

or on PowerShell:

```powershell
pm inject kill | Invoke-Expression
```

---

## Related Commands

- `pm unlock` — Start the vault session required for secret access
- `pm get` — View or copy a secret interactively
- `pm inject kill` — Wipe injected variables from the active shell
- `pm inject setup-shell` — Install the `inject()` shell helper
