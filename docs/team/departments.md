# Departments

Departments are isolated encryption domains within an APM Team Edition organization. Each
department has its own encryption boundary, ensuring secrets cannot cross department lines without
explicit permission.

## Creating departments

```console
$ pm-team dept create Engineering
Department "Engineering" created with isolated encryption domain.
```

Each department generates its own encryption key, wrapped by the organization master key. This
ensures that:

- Secrets in Engineering cannot be accessed by Marketing members.
- Compromising one department key does not expose other departments.
- Department-level key rotation is independent of the organization.

## Department structure

```text
Organization
  |
  +-- Engineering (isolated key)
  |     +-- alice (admin)
  |     +-- bob (member)
  |
  +-- Marketing (isolated key)
  |     +-- carol (manager)
  |     +-- dave (viewer)
  |
  +-- DevOps (isolated key)
        +-- eve (member)
```

## Managing members

### Adding to a department

```console
$ pm-team user add bob --role member --dept Engineering
User "bob" onboarded to Engineering as member.
```

### Moving between departments

```console
$ pm-team user move bob --from Engineering --to DevOps
User "bob" moved to DevOps. Engineering access revoked.
```

!!! important

    Moving a user between departments revokes their access to the previous department's secrets
    and grants access to the new department. This is a cryptographic operation — the user's access
    keys are re-derived for the new encryption domain.

### Listing department members

```console
$ pm-team dept members Engineering
+-------+--------+
| User  | Role   |
+-------+--------+
| alice | admin  |
| bob   | member |
+-------+--------+
```

## Department-scoped secrets

Secrets added within a department context are encrypted with that department's key:

```console
$ pm-team add --dept Engineering
? Select category: API Key
? Service: Production API
? Key: sk-xxxxxxxxxxxx

Entry added to Engineering department.
```

## Deleting departments

```console
$ pm-team dept delete Marketing
? Confirm deletion of "Marketing" and all its secrets? Yes
Department "Marketing" deleted.
```

!!! important

    Deleting a department permanently destroys all secrets within it and revokes access for all
    assigned members. This operation is irreversible.

## Next steps

See [RBAC and roles](./rbac.md) for the permission model, or [approval workflows](./approvals.md)
for handling sensitive access requests.
