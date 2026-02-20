# Approval workflows

APM's Team Edition includes an approval workflow for managing access to sensitive entries. When a
member requests access to a restricted secret, the request must be approved by a Manager, Admin,
or Owner before access is granted.

## Requesting access

When a member attempts to access a restricted entry:

```console
$ pm-team get "Production DB"
Access restricted. Approval request submitted (ID: 001).
```

The request is queued and the member is notified when a decision is made.

## Viewing pending requests

Managers, Admins, and Owners can list pending approval requests:

```console
$ pm-team approvals list
+------+--------+------------------+---------+---------------------+
| ID   | User   | Entry            | Status  | Requested           |
+------+--------+------------------+---------+---------------------+
| 001  | bob    | Production DB    | Pending | 2025-06-01 14:22:00 |
| 002  | alice  | AWS Root Key     | Pending | 2025-06-01 15:10:00 |
+------+--------+------------------+---------+---------------------+
```

## Approving requests

```console
$ pm-team approvals approve 001
Request approved. Access granted to bob for "Production DB".
```

## Denying requests

```console
$ pm-team approvals deny 002 --reason "Use IAM role instead"
Request denied. Reason sent to alice.
```

## Approval scope

| Approver Role | Can Approve                               |
| :------------ | :---------------------------------------- |
| **Owner**     | Any request in any department             |
| **Admin**     | Any request in any department             |
| **Manager**   | Requests within their own department only |
| **Member**    | Cannot approve                            |
| **Viewer**    | Cannot approve                            |

## Audit trail

All approval decisions are logged in the tamper-evident audit log:

```console
$ pm-team audit
[2025-06-01 14:30:00] APPROVE  bob -> "Production DB" (by: carol)
[2025-06-01 15:15:00] DENY     alice -> "AWS Root Key" (by: carol, reason: "Use IAM role instead")
```

## Next steps

See [RBAC and roles](./rbac.md) for the permission model, or [departments](./departments.md)
for encryption domain management.
