# Team Vault Documentation

## Overview

**Team Vault** (`pm-team.exe`) is a multi-user, department-based password manager designed for organizations. It provides secure shared credential management with role-based access control (RBAC), client-side encryption, and comprehensive audit logging.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Core Concepts](#core-concepts)
3. [Command Reference](#command-reference)
4. [Workflows](#workflows)
5. [RBAC & Permissions](#rbac--permissions)
6. [Shared Entry Types](#shared-entry-types)
7. [Security Model](#security-model)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Installation

The team vault executable is located in the `team/` directory:

```powershell
cd team
.\pm-team.exe --help
```

### Quick Start

```powershell
# 1. Initialize organization
.\pm-team.exe init "Acme Corp" admin

# 2. Login as admin
.\pm-team.exe login admin

# 3. Create a department
.\pm-team.exe dept create Engineering

# 4. Add a user
.\pm-team.exe user add alice --role MANAGER --dept engineering

# 5. Add a shared password
.\pm-team.exe add

# 6. List shared entries
.\pm-team.exe list
```

---

## Core Concepts

### Organization

The top-level entity representing your company or team. Each organization has:
- Unique organization ID
- Multiple departments
- Multiple users
- Shared entries
- Audit trail

### Departments

Logical groupings within an organization. Each department has:
- Unique department ID
- Department name
- Department encryption key (DK)
- Shared entries accessible only to department members

**Examples**: Engineering, Finance, Marketing, HR, Operations

### Users

Individual team members with:
- Unique username
- Role (defines permissions)
- Active department
- Wrapped department keys (encrypted with user's password)

### Roles

Five role types with different permission levels:
- **ADMIN**: Full access to everything
- **MANAGER**: Can manage users and entries within departments
- **USER**: Can add/edit own entries, view department entries
- **AUDITOR**: Read-only access to audit logs
- **SECURITY**: Can view audit logs and security-related entries

### Shared Entries

Credentials, keys, and secrets shared within a department:
- Passwords
- TOTP (2FA codes)
- API Keys
- Tokens
- Secure Notes
- SSH Keys
- Certificates
- WiFi Credentials
- Recovery Codes

---

## Command Reference

### Organization Management

#### `pm-team init <org_name> <admin_username>`

Initialize a new team organization.

**Arguments**:
- `<org_name>`: Organization name (e.g., "Acme Corp")
- `<admin_username>`: Username for the admin account

**Example**:
```powershell
.\pm-team.exe init "Acme Corp" admin
# Prompts: Create Master Password for Admin
# Prompts: Confirm Password
```

**Output**:
```
Team Organization 'Acme Corp' initialized. Admin: admin
Run 'pm-team login admin' to start.
```

**Notes**:
- Creates `team_vault.dat` in the same directory
- Admin user is created in the "general" department
- Admin has full permissions

---

### Authentication

#### `pm-team login <username>`

Login to the team organization.

**Arguments**:
- `<username>`: Your username

**Example**:
```powershell
.\pm-team.exe login alice
# Prompts: Password for alice
```

**Output**:
```
Logged in as alice (MANAGER) in department 'engineering'.
```

**Notes**:
- Session expires after 15 minutes of inactivity
- Session is stored in temp directory
- Decrypts department key for active department

#### `pm-team whoami`

Display current session information.

**Example**:
```powershell
.\pm-team.exe whoami
```

**Output**:
```
=== Team Vault Session ===
Organization: Acme Corp
Username: alice
Role: MANAGER
Active Department: engineering
Session Expires: 21:10:45
```

#### `pm-team logout`

End current session.

**Example**:
```powershell
.\pm-team.exe logout
```

**Output**:
```
Logged out successfully.
```

---

### Department Management

#### `pm-team dept list`

List all departments you have access to.

**Permissions**: All users (see only their department, admins see all)

**Example**:
```powershell
.\pm-team.exe dept list
```

**Output**:
```
Departments in Acme Corp:
- General (ID: general)
- Engineering (ID: engineering)
- Marketing (ID: marketing)
```

#### `pm-team dept create <name>`

Create a new department.

**Permissions**: ADMIN, MANAGER

**Arguments**:
- `<name>`: Department name (e.g., "Engineering")

**Example**:
```powershell
.\pm-team.exe dept create Engineering
```

**Output**:
```
Department 'Engineering' created.
```

**Notes**:
- Department ID is auto-generated (lowercase, underscores)
- Creates new department encryption key
- Logged in audit trail

---

### User Management

#### `pm-team user list`

List all users in the organization.

**Permissions**: All users (see only themselves, admins see all)

**Example**:
```powershell
.\pm-team.exe user list
```

**Output**:
```
Users in Acme Corp:
- admin (ADMIN) - Dept: general
- alice (MANAGER) - Dept: engineering
- bob (USER) - Dept: engineering
```

#### `pm-team user add <username> [--role ROLE] [--dept DEPT_ID]`

Add a new user to the organization.

**Permissions**: ADMIN, MANAGER

**Arguments**:
- `<username>`: Username for the new user
- `--role`: Role (default: USER)
- `--dept`: Department ID (default: general)

**Example**:
```powershell
.\pm-team.exe user add alice --role MANAGER --dept engineering
# Prompts: Set Password for alice
```

**Output**:
```
User 'alice' added successfully.
```

**Notes**:
- You must be in the target department or be an admin
- User's password is set during creation
- Department key is wrapped with user's password
- Logged in audit trail

---

### Shared Entry Management

#### `pm-team add`

Add a shared entry (interactive).

**Permissions**: ADMIN, MANAGER, USER

**Example**:
```powershell
.\pm-team.exe add
```

**Interactive Prompts**:
```
Select entry type:
1. Password
2. TOTP
3. API Key
4. Token
5. Secure Note
Choice: 1

Name: GitHub Admin
Username: admin@acme.com
Password: ********
URL: https://github.com/acme
```

**Output**:
```
Shared password 'GitHub Admin' added successfully.
```

**Supported Entry Types**:

1. **Password**
   - Name, Username, Password, URL
   - Encrypted with department key
   - Accessible to all department members

2. **TOTP (2FA)**
   - Name, Secret, Issuer
   - Generate time-based codes
   - Shared 2FA for team accounts

3. **API Key**
   - Label, Service, API Key
   - Shared service credentials
   - For team API access

4. **Token**
   - Name, Token, Type
   - Access tokens (GitHub, GitLab, etc.)
   - Shared authentication tokens

5. **Secure Note**
   - Name, Content (multi-line)
   - Shared documentation
   - Encrypted notes for team

#### `pm-team list`

List all shared entries you have access to.

**Permissions**: All users (see only their department entries, admins see all)

**Example**:
```powershell
.\pm-team.exe list
```

**Output**:
```
=== Shared Passwords ===
- GitHub Admin (admin@acme.com) - Dept: engineering
- AWS Console (devops@acme.com) - Dept: engineering

=== Shared API Keys ===
- Stripe API (Stripe) - Dept: engineering
- SendGrid API (SendGrid) - Dept: engineering

=== Shared TOTPs ===
- GitHub 2FA (GitHub) - Dept: engineering
```

---

## Workflows

### Onboarding a New Team Member

```powershell
# 1. Admin logs in
.\pm-team.exe login admin

# 2. Create user account
.\pm-team.exe user add john --role USER --dept engineering
# Set password: ********

# 3. User logs in
.\pm-team.exe login john
# Password: ********

# 4. User can now access department entries
.\pm-team.exe list
```

### Creating a New Department

```powershell
# 1. Admin/Manager logs in
.\pm-team.exe login admin

# 2. Create department
.\pm-team.exe dept create Finance

# 3. Add users to department
.\pm-team.exe user add sarah --role MANAGER --dept finance

# 4. Sarah can now add entries to Finance department
.\pm-team.exe login sarah
.\pm-team.exe add
# Add shared credentials for Finance team
```

### Sharing Credentials Across Teams

```powershell
# 1. Add entry in Engineering department
.\pm-team.exe login alice  # Manager in Engineering
.\pm-team.exe add
# Add: AWS Root Account

# 2. Admin can share across departments (future feature)
# For now, entries are department-scoped
```

---

## RBAC & Permissions

### Permission Matrix

| Action | ADMIN | MANAGER | USER | AUDITOR | SECURITY |
|--------|-------|---------|------|---------|----------|
| **Department Management** |
| Create Department | Yes | Yes | No | No | No |
| List Departments | Yes (all) | Yes (own) | Yes (own) | Yes (own) | Yes (own) |
| **User Management** |
| Add User | Yes | Yes | No | No | No |
| Remove User | Yes | Yes | No | No | No |
| Promote User | Yes | No | No | No | No |
| List Users | Yes (all) | Yes (dept) | Yes (self) | Yes (self) | Yes (self) |
| **Entry Management** |
| Add Entry | Yes | Yes | Yes | No | No |
| View Entry | Yes | Yes | Yes | No | No |
| Edit Entry | Yes | Yes | Yes (own) | No | No |
| Delete Entry | Yes | Yes | Yes (own) | No | No |
| List Entries | Yes (all) | Yes (dept) | Yes (dept) | No | No |

### Role Descriptions

#### ADMIN
- **Purpose**: Full organizational control
- **Use Cases**: IT administrators, founders, CTOs
- **Permissions**: Everything
- **Restrictions**: None

#### MANAGER
- **Purpose**: Department leadership
- **Use Cases**: Team leads, department heads
- **Permissions**: Manage users and entries within departments
- **Restrictions**: Cannot promote users to ADMIN, cannot delete organization

#### USER
- **Purpose**: Standard team member
- **Use Cases**: Developers, designers, analysts
- **Permissions**: Add entries, view department entries, edit own entries
- **Restrictions**: Cannot manage users or departments

#### AUDITOR
- **Purpose**: Compliance and audit
- **Use Cases**: Security auditors, compliance officers
- **Permissions**: View audit logs only
- **Restrictions**: Cannot access credentials

#### SECURITY
- **Purpose**: Security monitoring
- **Use Cases**: Security engineers, SOC analysts
- **Permissions**: View audit logs and security-related entries
- **Restrictions**: Cannot modify entries

---

## Shared Entry Types

### 1. Shared Passwords

**Use Cases**:
- Team account credentials
- Shared service logins
- Admin console access

**Fields**:
- Name (e.g., "AWS Console")
- Username
- Password (encrypted)
- URL

**Example**:
```
Name: GitHub Organization
Username: admin@acme.com
Password: [encrypted]
URL: https://github.com/acme
```

### 2. Shared TOTP (2FA)

**Use Cases**:
- Team account 2FA
- Shared service authentication
- Emergency access codes

**Fields**:
- Name (e.g., "GitHub 2FA")
- Secret (encrypted)
- Issuer

**Example**:
```
Name: AWS Root 2FA
Secret: [encrypted]
Issuer: Amazon Web Services
```

### 3. Shared API Keys

**Use Cases**:
- Service API credentials
- Third-party integrations
- CI/CD secrets

**Fields**:
- Label (e.g., "Stripe Production")
- Service
- Key (encrypted)

**Example**:
```
Label: Stripe Production API
Service: Stripe
Key: sk_live_[encrypted]
```

### 4. Shared Tokens

**Use Cases**:
- Access tokens
- Bearer tokens
- OAuth tokens

**Fields**:
- Name (e.g., "GitHub PAT")
- Token (encrypted)
- Type

**Example**:
```
Name: GitHub Personal Access Token
Token: ghp_[encrypted]
Type: GitHub
```

### 5. Shared Secure Notes

**Use Cases**:
- Team documentation
- Runbooks
- Emergency procedures

**Fields**:
- Name (e.g., "Production Runbook")
- Content (encrypted, multi-line)

**Example**:
```
Name: Database Recovery Procedure
Content: [encrypted multi-line text]
```

---

## Security Model

### Client-Side Encryption

All sensitive data is encrypted **before** leaving your machine:

1. **User Password** → Argon2id → **User Key (UK)**
2. **Department Key (DK)** → Wrapped with UK → **Wrapped DK**
3. **Entry Data** → AES-256-GCM with DK → **Encrypted Entry**

### Key Hierarchy

```
Organization Salt (stored in vault)
    ↓
User Password + Salt → Argon2id → User Key (UK)
    ↓
Department Key (DK) wrapped with UK → Wrapped DK (stored per user)
    ↓
Entry Data encrypted with DK → Encrypted Entry (stored in department)
```

### Zero-Knowledge Architecture

- **Server/Cloud**: Stores only encrypted data
- **No Plaintext**: Passwords never leave your machine in plaintext
- **Client-Side Only**: All encryption/decryption happens locally

### Audit Trail

Every action is logged with:
- Timestamp
- Username
- Action type
- Details
- Hash chain (tamper-evident)

**Example Audit Entry**:
```
[2026-01-11 20:55:16] alice | ADD_PASSWORD | Added shared password: GitHub Admin
```

---

## Best Practices

### 1. Password Management

**DO**:
- Use strong, unique passwords for each user
- Rotate department keys periodically
- Use TOTP for critical accounts
- Document password rotation schedules

**DON'T**:
- Share user passwords
- Reuse passwords across departments
- Store passwords in plaintext elsewhere

### 2. Role Assignment

**DO**:
- Follow principle of least privilege
- Assign MANAGER role to team leads only
- Use USER role for most team members
- Create dedicated AUDITOR accounts for compliance

**DON'T**:
- Give everyone ADMIN access
- Create unnecessary MANAGER accounts
- Use shared accounts

### 3. Department Structure

**DO**:
- Align departments with organizational structure
- Keep departments focused (Engineering, Finance, etc.)
- Create separate departments for different access levels

**DON'T**:
- Create too many departments
- Mix unrelated teams in one department
- Use generic department names

### 4. Entry Organization

**DO**:
- Use descriptive names ("AWS Production Console")
- Include service names in labels
- Add URLs for password entries
- Document entry purpose in notes

**DON'T**:
- Use vague names ("Password 1")
- Duplicate entries across departments
- Store non-sensitive data

### 5. Session Management

**DO**:
- Logout when done
- Use short session timeouts
- Lock workstation when away

**DON'T**:
- Leave sessions active overnight
- Share session files
- Disable session expiry

---

## Troubleshooting

### "Authentication failed"

**Cause**: Incorrect password or user not found

**Solution**:
```powershell
# Verify username exists
.\pm-team.exe user list

# Ensure you're using the correct password
# Contact admin to reset if forgotten
```

### "Permission denied"

**Cause**: Insufficient role permissions

**Solution**:
```powershell
# Check your role
.\pm-team.exe whoami

# Contact admin to promote your role if needed
```

### "No active session"

**Cause**: Session expired or not logged in

**Solution**:
```powershell
# Login again
.\pm-team.exe login <username>
```

### "Team vault not found"

**Cause**: `team_vault.dat` file missing or in wrong directory

**Solution**:
```powershell
# Ensure you're in the correct directory
cd team

# Verify file exists
ls team_vault.dat

# If missing, initialize new organization or restore from backup
```

### "Department not found"

**Cause**: Department doesn't exist or you don't have access

**Solution**:
```powershell
# List available departments
.\pm-team.exe dept list

# Contact admin to create department or grant access
```

---

## Appendix

### File Locations

- **Vault File**: `team_vault.dat` (same directory as `pm-team.exe`)
- **Session File**: `%TEMP%\pm_team_session.json` (Windows)
- **Executable**: `team\pm-team.exe`

### Vault Format

```
[8 bytes: "APMTEAMV"] [JSON: TeamVault structure]
```

### Session Format

```json
{
  "user_id": "user_123",
  "username": "alice",
  "role": "MANAGER",
  "active_dept_id": "engineering",
  "dept_key": "[base64 encrypted key]",
  "org_id": "acme-corp",
  "expiry": "2026-01-11T21:10:45Z"
}
```

---

## Support

For issues, questions, or feature requests:
- Check this documentation first
- Review the [Security Model](#security-model)
- Consult your organization's admin
- Review audit logs for suspicious activity

---

**Version**: v7 
**Last Updated**: 2026-01-11
