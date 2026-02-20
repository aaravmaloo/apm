# First steps with APM

After [installing APM](./installation.md), you can check that APM is available by running the `pm`
command:

```console
$ pm
APM - Advanced Password Manager

Usage: pm <command> [flags]

Commands:
  init       Initialize a new encrypted vault
  add        Add a new secret entry
  get        Search and retrieve entries
  ...
```

You should see a help menu listing the available commands.

## Initialize your vault

Create a new encrypted vault with `pm init`:

```console
$ pm init
? Set a Master Password: ********
? Confirm Master Password: ********
? Set a Recovery Key (optional): ********

Vault initialized successfully.
```

!!! important

    Your master password is never stored. If you lose it and do not have a recovery key, your
    vault data cannot be recovered. This is by design (zero-knowledge architecture).

## Add your first entry

Store a credential using `pm add`:

```console
$ pm add
? Select category: Password
? Account name: GitHub
? Username: aarav@example.com
? Password: ********

Entry added successfully.
```

## Retrieve an entry

Search and display entries using `pm get`:

```console
$ pm get github
+----------+----------------------+
| Account  | GitHub               |
| Username | aarav@example.com    |
| Category | Password             |
+----------+----------------------+
```

Use the `--show-pass` flag to reveal the stored secret.

## Next steps

Now that you've confirmed APM is installed and working, check out an
[overview of features](./features.md), learn how to [get help](./help.md) if you run into any
problems, or jump to the [guides](../guides/index.md) to start using APM.
