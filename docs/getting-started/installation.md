# Installation

APM can be installed via one-line scripts, pre-built binaries, or by building from source.

---

## One-Line Install (Recommended)

=== "macOS / Linux"

    ```bash
    curl -sSL https://raw.githubusercontent.com/aaravmaloo/apm/master/scripts/install.sh | bash
    ```

    **Install layout:**

    | Platform | Binary location          | Symlink                                       |
    | :------- | :----------------------- | :-------------------------------------------- |
    | macOS    | `/usr/local/opt/apm/apm` | `/usr/local/bin/apm → /usr/local/opt/apm/apm` |
    | Linux    | `/opt/apm/apm`           | `/usr/local/bin/apm → /opt/apm/apm`           |

=== "Windows PowerShell"

    ```powershell
    Set-ExecutionPolicy Bypass -Scope Process -Force
    iwr https://raw.githubusercontent.com/aaravmaloo/apm/master/scripts/install.ps1 -UseBasicParsing | iex
    ```

    **Install layout:**

    - Binary: `%LOCALAPPDATA%\pm\apm.exe`
    - The installer appends the directory to your user `PATH` if not already present

After installation, verify with:

```bash
pm info
```

---

## Pre-built Binaries

Pre-built binaries for Windows, macOS, and Linux are available for each stable release:

1. Go to the [Releases page](https://github.com/aaravmaloo/apm/releases)
2. Download the binary for your OS and architecture
3. Place it in a directory on your `PATH`
4. Verify with `pm info`

---

## Build from Source

### Requirements

- **Go 1.21** or later
- Git
- Windows, macOS, or Linux

### Steps

```bash
# Clone the repository
git clone https://github.com/aaravmaloo/apm.git
cd apm

# Build the binary
go build -o pm main.go

# Verify the build
./pm info

# Initialize your first vault
./pm init
```

!!! tip
    On Windows, the output binary will be `pm.exe`. You can move it to a directory on your `PATH` for global access.

---

## Preview and Beta Builds

Pre-built binaries for preview, beta, and canary builds are available from the [Builds page](https://github.com/aaravmaloo/apm/tree/master/build).

!!! warning
    Preview and beta builds may be unstable and could potentially corrupt your vault. These builds are intended for developers and testers only. **Do not use them for production vaults.**

The APM version system follows these stages (e.g., for a v8 release):

| Stage       | Tag      | Stability    |
| :---------- | :------- | :----------- |
| Canary      | `can-8`  | Experimental |
| Beta        | `beta-8` | Testing      |
| Pre-release | `pre-8`  | Near-stable  |
| Release     | `v8`     | Stable       |

---

## Updating

APM includes a self-update mechanism:

```bash
pm update
```

This checks for the latest release on GitHub and downloads/replaces the binary automatically. You can also force a check with:

```bash
pm update --force
```

---

## Uninstalling

=== "macOS / Linux"

    ```bash
    # Remove the binary and symlink
    sudo rm -f /usr/local/bin/apm
    sudo rm -rf /usr/local/opt/apm   # macOS
    sudo rm -rf /opt/apm              # Linux

    # Optionally remove config and vault data
    rm -rf ~/.config/apm
    ```

=== "Windows"

    ```powershell
    # Remove the binary directory
    Remove-Item -Recurse -Force "$env:LOCALAPPDATA\pm"

    # Remove from PATH (manual step in System Properties → Environment Variables)

    # Optionally remove config data
    Remove-Item -Recurse -Force "$env:APPDATA\apm"
    ```

---

## Next Steps

Once installed, proceed to [First Steps](first-steps.md) to initialize your vault and start managing secrets.