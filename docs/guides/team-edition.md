---
title: Team edition
description:
  A guide to getting started with APM's Team Edition for organizational credential management.
---

# Team edition

APM's Team Edition (`pm-team`) is designed for organizations that need secure credential sharing
via a multi-layered RBAC model with departmental isolation.

## Initializing an organization

Set up a new organization:

```console
$ pm-team init "Acme Corp"
? Set Organization Master Password: ********
Organization "Acme Corp" initialized.
```

## Creating departments

Departments act as isolated encryption domains within the organization:

```console
$ pm-team dept create Engineering
Department "Engineering" created with isolated encryption domain.

$ pm-team dept create Marketing
Department "Marketing" created with isolated encryption domain.
```

Each department has its own encryption boundary, ensuring that secrets in one department cannot be
accessed by members of another without explicit permission.

## Onboarding users

Add team members with specific roles:

```console
$ pm-team user add alice --role admin
User "alice" onboarded as admin.

$ pm-team user add bob --role member --dept Engineering
User "bob" onboarded to Engineering as member.
```

## Managing approvals

Handle pending requests for sensitive entries:

```console
$ pm-team approvals list
+------+--------+------------------+--------+
| ID   | User   | Entry            | Status |
+------+--------+------------------+--------+
| 001  | bob    | Production DB    | Pending|
| 002  | alice  | AWS Root Key     | Pending|
+------+--------+------------------+--------+

$ pm-team approvals approve 001
Request approved. Access granted to bob.
```

## Session management

The Team Edition uses localized session storage, preventing session loss across different shell
environments on the same machine:

```console
$ pm-team unlock
? Organization Master Password: ********
Team session started.
```

!!! tip

    The Team Edition supports piped input for non-interactive use, enabling CI/CD and automation
    scenarios.

## Next steps

See the [team edition documentation](../team/index.md) for in-depth coverage of RBAC, departments,
and approval workflows.
