# Team Edition

APM Team Edition (`pm-team`) extends the personal password manager for organizational use with multi-user support, role-based access control, departmental isolation, and approval workflows.

---

## In This Section

- **[RBAC and Roles](rbac.md)** — Role-based access control system
- **[Departments](departments.md)** — Isolated encryption domains
- **[Approval Workflows](approvals.md)** — Gated access to sensitive credentials

---

## Overview

The Team Edition shares the same cryptographic foundation as the personal edition (Argon2id + AES-256-GCM + HMAC-SHA256) but adds an organizational layer:

| Feature          | Personal (`pm`)   | Team (`pm-team`)             |
| :--------------- | :---------------- | :--------------------------- |
| Users            | Single user       | Multiple users with roles    |
| Vault encryption | Single master key | Per-department keys          |
| Access control   | Session-based     | RBAC + approval workflows    |
| Audit scope      | Local machine     | Organization-wide            |
| Entry sharing    | Not applicable    | Controlled sharing via roles |

---

## Quick Start

```bash
# Initialize an organization
pm-team init "Acme Corp"

# Create departments
pm-team dept create Engineering
pm-team dept create Finance

# Add users
pm-team user add alice --role admin --dept Engineering
pm-team user add bob --role member --dept Finance

# Add shared entries
pm-team add

# Search entries
pm-team get [query]

# Check organizational health
pm-team health
```