# Disabling Automatic Task Execution in IDEs

This guide covers how to disable the `runOn: folderOpen` automatic task execution in VS Code, Cursor, Windsurf, and other compatible IDEs.

## VS Code

### Method 1: Settings UI

1. Open Settings: `Ctrl+,` (Windows/Linux) or `Cmd+,` (macOS)
2. Search for: `task.allowAutomaticTasks`
3. Set the value to **`off`**

### Method 2: settings.json

1. Open Command Palette: `Ctrl+Shift+P` / `Cmd+Shift+P`
2. Type: `Preferences: Open User Settings (JSON)`
3. Add the following line:

```json
{
    "task.allowAutomaticTasks": "off"
}
```

### Method 3: Workspace Trust (Additional Layer)

Ensure Workspace Trust is enabled (it is by default):

```json
{
    "security.workspace.trust.enabled": true
}
```

When enabled, VS Code prompts you before trusting new folders. **Do not click "Trust" on unfamiliar repositories without reviewing their `.vscode/` contents first.**

## Cursor

Cursor inherits VS Code settings. The same methods apply:

1. Open Settings: `Ctrl+,` / `Cmd+,`
2. Search for `task.allowAutomaticTasks`
3. Set to **`off`**

Or add to `settings.json`:

```json
{
    "task.allowAutomaticTasks": "off"
}
```

## Windsurf (Codeium)

Windsurf also inherits VS Code task infrastructure:

1. Open Settings: `Ctrl+,` / `Cmd+,`
2. Search for `task.allowAutomaticTasks`
3. Set to **`off`**

## VSCodium

Same as VS Code:

```json
{
    "task.allowAutomaticTasks": "off"
}
```

## Settings File Locations

| IDE | Platform | Path |
|-----|----------|------|
| VS Code | Windows | `%APPDATA%\Code\User\settings.json` |
| VS Code | macOS | `~/Library/Application Support/Code/User/settings.json` |
| VS Code | Linux | `~/.config/Code/User/settings.json` |
| Cursor | Windows | `%APPDATA%\Cursor\User\settings.json` |
| Cursor | macOS | `~/Library/Application Support/Cursor/User/settings.json` |
| Cursor | Linux | `~/.config/Cursor/User/settings.json` |

## Verifying the Setting

After applying the setting, test with the Variant 1 PoC from this repository:

1. Open the `variants/1-basic/` folder in your IDE.
2. If Calculator does **NOT** open, the mitigation is working.
3. If Calculator opens, the setting was not applied correctly.

## Important Notes

- This setting applies **globally** to your IDE. Legitimate `runOn: folderOpen` tasks will also be disabled.
- If you need auto-tasks for specific trusted projects, you can use Workspace Trust instead of disabling auto-tasks entirely. However, this requires discipline to not blindly trust unfamiliar workspaces.
- The `"prompt"` value for `task.allowAutomaticTasks` will ask before running, which is safer than `"on"` but still relies on user judgment.
