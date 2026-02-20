# Installing APM

## Installation methods

Install APM by building from source or downloading a pre-built binary from GitHub Releases.

### Build from source

Clone the repository and build the binary with Go:

=== "Windows"

    ```pwsh-session
    PS> git clone https://github.com/aaravmaloo/apm.git
    PS> cd apm
    PS> go build -o pm.exe main.go
    ```

=== "macOS and Linux"

    ```console
    $ git clone https://github.com/aaravmaloo/apm.git
    $ cd apm
    $ go build -o pm main.go
    ```

### Build requirements

- **Go 1.21** or later
- **Git** for cloning the repository
- Windows, macOS, or Linux

### GitHub Releases

Pre-built binaries can be downloaded directly from
[GitHub Releases](https://github.com/aaravmaloo/apm/releases).

Each release includes binaries for all supported platforms.

## Upgrading APM

APM includes a self-update engine that fetches the latest builds:

```console
$ pm update
Checking for updates...
Updated to v9.2 successfully.
```

!!! tip

    You can check the currently installed version with `pm info` before updating.

## Adding to PATH

After building or downloading the binary, ensure it is available on your system `PATH`:

=== "Windows"

    Move `pm.exe` to a directory in your `PATH`, or add the build directory:

    ```pwsh-session
    PS> $env:PATH += ";C:\path\to\apm"
    ```

    To make this permanent, add the directory via **System Properties > Environment Variables**.

=== "macOS and Linux"

    Move the binary to a directory in your `PATH`:

    ```console
    $ sudo mv pm /usr/local/bin/
    ```

    Or add the build directory to your shell profile:

    ```console
    $ echo 'export PATH="$PATH:/path/to/apm"' >> ~/.bashrc
    ```

## Uninstallation

To remove APM from your system:

1. Remove the binary:

    === "Windows"

        ```pwsh-session
        PS> Remove-Item C:\path\to\pm.exe
        ```

    === "macOS and Linux"

        ```console
        $ rm /usr/local/bin/pm
        ```

2. Optionally, remove stored vault data:

    === "Windows"

        ```pwsh-session
        PS> Remove-Item -Recurse $HOME\.apm
        ```

    === "macOS and Linux"

        ```console
        $ rm -rf ~/.apm
        ```

    !!! important

        This will permanently delete your encrypted vault and all stored credentials. Ensure you
        have a backup via `pm export` or `pm cloud push` before removing data.

## Next steps

See the [first steps](./first-steps.md) or jump straight to the [guides](../guides/index.md) to
start using APM.
