# Getting help

## Help menus

The `--help` flag can be used to view the help menu for a command, e.g., for `pm`:

```console
$ pm --help
```

To view the help menu for a specific command, e.g., for `pm add`:

```console
$ pm add --help
```

## Viewing the version

When seeking help, it's important to determine the version of APM that you're using — sometimes the
problem is already solved in a newer version.

To check the installed version and environment details:

```console
$ pm info
APM v9.2
OS: windows/amd64
Vault: ~/.apm/vault.dat
Profile: Standard
```

## Viewing cryptographic info

To inspect the cryptographic parameters of your current vault:

```console
$ pm cinfo
Cipher: AES-256-GCM
KDF: Argon2id
Memory: 64 MB
Iterations: 3
Parallelism: 2
```

## Troubleshooting issues

The reference documentation contains information about
[storage locations](../reference/storage.md) and
[environment variables](../reference/environment-variables.md) that may help debug common issues.

## Open an issue on GitHub

The [issue tracker](https://github.com/aaravmaloo/apm/issues) on GitHub is a good place to report
bugs and request features. Make sure to search for similar issues first, as it is common for someone
else to encounter the same problem.

## Contact

For security-related concerns, contact [aaravmaloo06@gmail.com](mailto:aaravmaloo06@gmail.com)
directly.
