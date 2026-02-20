# RBAC and roles

APM's Team Edition uses a multi-layered **Role-Based Access Control (RBAC)** model to enforce
least-privilege access across the organization.

## Role hierarchy

| Role        | Scope             | Permissions                                                                            |
| :---------- | :---------------- | :------------------------------------------------------------------------------------- |
| **Owner**   | Organization-wide | Full access, manage members, manage departments, approve requests, delete organization |
| **Admin**   | Organization-wide | Manage members, manage departments, approve requests                                   |
| **Manager** | Department-scoped | Manage department members, approve requests within department                          |
| **Member**  | Department-scoped | Read/write access to assigned department secrets                                       |
| **Viewer**  | Department-scoped | Read-only access to assigned department secrets                                        |

## Assigning roles

### During onboarding

```console
$ pm-team user add alice --role admin
User "alice" onboarded as admin.
```

### Updating roles

```console
$ pm-team user role alice --set manager --dept Engineering
Role updated: alice is now Manager of Engineering.
```

## Permission matrix

| Action                    | Owner | Admin |  Manager  | Member | Viewer |
| :------------------------ | :---: | :---: | :-------: | :----: | :----: |
| View secrets (own dept)   |  Yes  |  Yes  |    Yes    |  Yes   |  Yes   |
| Add secrets (own dept)    |  Yes  |  Yes  |    Yes    |  Yes   |   No   |
| Edit secrets (own dept)   |  Yes  |  Yes  |    Yes    |  Yes   |   No   |
| Delete secrets (own dept) |  Yes  |  Yes  |    Yes    |   No   |   No   |
| View secrets (other dept) |  Yes  |  Yes  |    No     |   No   |   No   |
| Manage members            |  Yes  |  Yes  | Dept only |   No   |   No   |
| Create departments        |  Yes  |  Yes  |    No     |   No   |   No   |
| Approve requests          |  Yes  |  Yes  | Dept only |   No   |   No   |
| Delete organization       |  Yes  |  No   |    No     |   No   |   No   |

## Encryption boundaries

Each role assignment operates within the cryptographic isolation of the
[department](./departments.md) it is scoped to. A Manager of Engineering cannot decrypt secrets
belonging to Marketing, even with the organization master password.

## Next steps

See [departments](./departments.md) for details on encryption domains, or
[approval workflows](./approvals.md) for managing sensitive access requests.
