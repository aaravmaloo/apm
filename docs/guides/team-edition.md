# Team Edition

The team edition is a separate CLI whose docs live under [Team](../team/index.md). Build it from the repository's `team/` directory:

```bash
cd team
go build -o pm-team .
```

## What `pm-team` currently provides

- organization initialization
- login and short-lived team sessions
- departments
- roles and per-user permission overrides
- shared entry management
- approval queues
- export, audit, health, and info commands

The team edition exists and is usable, but it is less mature than the personal `pm` CLI. Some behaviors are still uneven across entry types and approval paths.

## Initialize an organization

The current command signature is:

```bash
pm-team init <org_name> <admin_username>
```

Example:

```bash
pm-team init "Acme" aarav
```

This creates:

- the team vault
- a default `general` department
- the initial admin user

## Authenticate

```bash
pm-team login <username>
pm-team whoami
pm-team logout
```

Team sessions are separate from personal `pm` sessions and currently expire after 15 minutes.

## Manage departments

```bash
pm-team dept list
pm-team dept create Engineering
pm-team dept switch alice engineering
```

Department switching in the current CLI is an admin action that changes a user's active department.

## Manage users

```bash
pm-team user list
pm-team user add alice --role USER --dept general
pm-team user remove alice
pm-team user promote alice MANAGER
pm-team user roles
pm-team user permission grant alice add_entry
pm-team user permission revoke alice add_entry
```

Built-in roles in code today:

- `ADMIN`
- `MANAGER`
- `USER`
- `AUDITOR`
- `SECURITY`

## Shared entries

The team add flow currently supports 22 shared entry types, including passwords, TOTP, API keys, tokens, notes, SSH material, certificates, Wi-Fi, recovery codes, documents, cloud credentials, CI/CD secrets, licenses, and legal contracts.

Useful commands:

```bash
pm-team add
pm-team list
pm-team get github
pm-team edit <entry_name>
pm-team delete <entry_name>
pm-team gen
```

Practical notes from the current code:

- `pm-team list` only prints a subset of entry categories rather than every stored type.
- `pm-team edit` is strongest for password and TOTP records; other types are less complete.
- There are also type-specific command groups such as `pm-team password ...`, `pm-team totp ...`, `pm-team apikey ...`, and similar namespaces with `add`, `list`, and `get`.

## Approvals

```bash
pm-team approvals list
pm-team approvals approve <idx>
pm-team approvals deny <idx>
```

The approval system is part of the current command tree and is intended for gated changes or access flows around shared entries.

Implementation note:

- approval handling is most complete for create flows
- edit and delete approval paths are present in the CLI but are less complete in behavior today
