# APM Plugin Development Guide

APM (Advanced Password Manager) features a powerful, JSON-driven plugin architecture. This guide provides a comprehensive walkthrough for building, testing, and distributing APM plugins.

---

## 1. Conceptual Overview

APM's plugin system is designed to be **extensible**, **secure**, and **declarative**. 

- **Declarative**: You don't write Go code for plugins. You define **Metadata**, **Commands**, and **Hooks** in a `plugin.json` file.
- **Isolated**: Plugins run in a restricted environment. They can only perform actions explicitly granted by their **Permissions**.
- **Variable-Driven**: Plugins use a state-based system where actions store results in variables, which can then be used in subsequent steps via Handlebars-style templates (`{{variable}}`).

---

## 2. Plugin Structure

A plugin is simply a directory containing a manifest file.

```text
my-plugin/
├── plugin.json      # The Manifest (Required)
├── README.md        # Documentation (Recommended)
└── assets/          # Optional static assets
```

---

## 3. Deep Dive into `plugin.json`

The most critical part of a plugin is the `plugin.json` file. Let's explain every field.

### Metadata Fields
- **`name`**: (String) Unique identifier for the plugin (e.g., `hello_vault`).
- **`version`**: (String) Semantic versioning (e.g., `1.0.0`).
- **`description`**: (String) Short summary of what the plugin does.
- **`author`**: (String) Your name or organization.
- **`permissions`**: (Array of Strings) List of capabilities the plugin requires.

### Commands
The `commands` object defines new CLI verbs that the user can run via `pm <command_name>`.

```json
"commands": {
  "my-cmd": {
    "description": "What this command does",
    "flags": { ... },
    "steps": [ ... ]
  }
}
```

#### Flags
Flags allow users to pass arguments to your command (e.g., `pm my-cmd --user "Alice"`).
- **`type`**: Currently supporting `string`.
- **`default`**: The value used if the user doesn't provide the flag.

#### Steps (The Logic)
Steps are an ordered list of **Actions**. Each step executes sequentially.
- **`action`**: The implementation name (e.g., `print`, `vault.get`).
- **`assign_to`**: (Optional) Stores the output of the action into a variable.

### Hooks
Hooks target existing APM events.
- **`post:unlock`**: Runs after a successful vault unlock.
- **`pre:add`**: Runs before a new entry is saved. Excellent for validation.

---

## 4. Permission System

APM uses a "White-List" permission model. If a permission isn't requested, the action will fail.

| Permission | What it unlocks |
|------------|-----------------|
| `vault.read` | Allows use of `vault.get` and `vault.find`. |
| `vault.write` | Allows use of `vault.add` and `vault.delete`. |
| `file.storage` | Allows reading/writing to the local plugin directory. |
| `network.outbound` | Allows making HTTP requests. |
| `crypto.use` | Allows hashing and custom encryption steps. |

---

## 5. Action Reference

Here is a line-by-line explanation of core actions.

### `print`
Outputs text to the terminal.
- **Line 1 (`action`)**: `"print"`
- **Line 2 (`message`)**: The text. Use `{{var}}` for dynamic content.

### `vault.get`
Fetches a secret by its exact name.
- **`key`**: The account/secret name.
- **`assign_to`**: The name of the resulting variable (e.g., `my_secret`).

### `prompt.input`
Asks the user for information during execution.
- **`message`**: The prompt question.
- **`assign_to`**: Stores the user's answer.

---

## 6. Variables & Templating

Plugins maintain a local context during execution. 
1. **Initial Variables**: Populated by **flags**.
2. **Context Variables**: Set by `assign_to` in steps.
3. **Environment**: APM provides `{{USER}}`, `{{OS}}`, and `{{TIMESTAMP}}` automatically.

**Usage**: Anywhere in a `message` or `key` field, you can use `{{var_name}}`.

---

## 7. Example: `hello_vault`

Here is a complete, line-by-line breakdown of a functioning plugin.

```json
{
  "name": "hello_vault",
  "version": "1.0.0",
  "description": "Demonstrates security and vault access",
  "permissions": ["vault.read"],
  "commands": {
    "check": {
      "description": "Checks if a specific account exists",
      "flags": {
        "account": { "type": "string", "default": "github" }
      },
      "steps": [
        {
          "action": "print",
          "message": "Searching for {{account}}..."
        },
        {
          "action": "vault.get",
          "key": "{{account}}",
          "assign_to": "result"
        },
        {
          "action": "print",
          "message": "Status: Found mapping for {{account}}."
        }
      ]
    }
  }
}
```

- **Lines 1-5**: Boilerplate metadata.
- **Line 4 (`permissions`)**: Explicitly asks for `vault.read`. Without this, Step 2 would crash.
- **Line 9 (`flags`)**: Defines a `--account` flag. If I run `pm check --account google`, `{{account}}` becomes "google".
- **Step 1**: Just feedback to the user.
- **Step 2**: The heavy lifting. It searches the vault for whatever is in `{{account}}`.
- **Step 3**: Reports back.

---

## 8. Development Workflow

### Step 1: Initialization
Create a new directory inside `plugins/` (or anywhere).

### Step 2: Local Testing
Run the command directly from the source:
```bash
pm plugins install ./my-new-plugin
```

### Step 3: Registration
APM will automatically register the new commands. You can verify with:
```bash
pm help
```

### Step 4: Marketplace Push
If you want to share your plugin:
```bash
pm plugins push my-plugin
```
*Note: This requires Cloud configured.*

---

## 9. Best Practices

- **Validate Input**: Use `pre:add` hooks to ensure passwords meet your org's complexity requirements.
- **Error Handling**: Currently, if a step fails, the command stops. Design your steps linearly.
- **Naming**: Use descriptive command names to avoid collisions with core APM verbs.
