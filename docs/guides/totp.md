---
title: Generating TOTP codes
description:
  A guide to adding TOTP seeds and generating time-based one-time passwords with APM.
---

# Generating TOTP codes

APM can generate time-based one-time passwords (TOTP) directly in your terminal, complete with live
countdowns.

## Adding a TOTP entry

When adding an entry, select the **TOTP** category and provide the seed:

```console
$ pm add
? Select category: TOTP
? Account name: GitHub 2FA
? TOTP Secret/Seed: JBSWY3DPEHPK3PXP
? Issuer (optional): GitHub

Entry added successfully.
```

!!! tip

    You can also add a TOTP seed to an existing password entry. Many services provide a TOTP
    secret alongside your password credentials.

## Viewing TOTP codes

Generate a code for a specific entry using `pm totp show`:

```console
$ pm totp show
? Select entry: GitHub 2FA

  Code: 482 913
  Expires in: 18s [==================------]
```

The code refreshes automatically with a live countdown showing the remaining validity window.

## Using TOTP with MCP

If you have configured the [MCP server](./mcp-integration.md) with `totp` permissions, AI
assistants can also retrieve TOTP codes via the `get_totp` tool. See the
[MCP tools reference](../reference/mcp-tools.md) for details.

## Next steps

Learn about [session management](./sessions.md) to control vault access, or see the
[command reference](../reference/cli.md) for all TOTP-related options.
