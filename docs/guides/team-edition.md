# Team Edition

The APM Team Edition (`pm-team`) extends APM for organizational use — enabling secure credential sharing across teams with role-based access control, departmental isolation, and approval workflows.

---

## Overview

While the personal edition (`pm`) focuses on local-first individual security, the Team Edition adds:

- **Multi-user vault management** with shared encryption
- **Role-Based Access Control (RBAC)** with configurable roles
- **Departments** as isolated encryption domains
- **Approval workflows** for gated access to sensitive entries
- **Health monitoring** across the organization

---

## Getting Started

### Initialize an Organization

```bash
pm-team init "Acme Corp"
```

This creates the organizational root environment with the organization name, initial admin user, and master encryption configuration.

---

## User Management

### Adding Users

```bash
pm-team user add alice
```

Onboards a new member with a specified role. Users are assigned to departments and given role-based permissions.

### Listing Users

```bash
pm-team user list
```

---

## Department Management

Departments provide isolated encryption domains within the organization:

```bash
# Create a department
pm-team dept create Engineering

# List departments
pm-team dept list
```

Each department has its own encryption context, meaning secrets in one department are cryptographically isolated from others.

---

## Entry Operations

Team entries work like personal entries but with organizational context:

```bash
# Add a shared entry
pm-team add

# Search for entries (optional query)
pm-team get [query]

# Edit an entry
pm-team edit [name]

# Delete an entry
pm-team del [name]
```

---

## Approval Workflows

Sensitive entries can require approval before access:

```bash
# List pending approvals
pm-team approvals list

# Approve or deny a request
pm-team approvals approve <request_id>
pm-team approvals deny <request_id>
```

The approval system ensures that high-sensitivity credentials are only accessed with explicit authorization from a manager or admin.

---

## Health Dashboard

```bash
pm-team health
```

Shows the organizational vault health status, including security scoring and vulnerability reporting across all departments.

---

## Security Architecture

The Team Edition uses the same cryptographic primitives as the personal edition:

- **Argon2id** for key derivation
- **AEAD vault encryption** aligned with the personal edition's cryptographic model
- **HMAC-SHA256** for integrity verification

### Key Differences

| Feature        | Personal Edition  | Team Edition              |
| :------------- | :---------------- | :------------------------ |
| Users          | Single            | Multiple with roles       |
| Encryption     | Single master key | Per-department keys       |
| Access control | Session-based     | RBAC + approval workflows |
| Audit          | Local log         | Org-wide audit trail      |

---

## Next Steps

- **[RBAC and Roles](../team/rbac.md)** — Role configuration details
- **[Departments](../team/departments.md)** — Department isolation model
- **[Approval Workflows](../team/approvals.md)** — Configuring approval gates
