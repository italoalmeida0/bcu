# Bulk Crap Uninstaller (BCU) - Python CLI & AI Agent Engine

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Tooling](https://img.shields.io/badge/Managed%20with-uv-purple.svg)](https://github.com/astral-sh/uv)

A modern, standalone Python CLI port of **[Bulk Crap Uninstaller (BCU)](https://github.com/Klocman/Bulk-Crap-Uninstaller)**.

Designed specifically for **terminal power users** and **autonomous AI coding/maintenance agents** to discover installed software, synthesize silent uninstallation routines, detect leftover filesystem, registry, services, tasks, and autostart remnants using fuzzy confidence scoring, and perform safe, deep **"Clean Slate"** cleanups (as if the program had never existed).

---

## 🌟 Key Features

- **Multi-Source Discovery Engine**:
  - Windows Registry (64-bit and 32-bit `Wow6432Node` across `HKLM` and `HKCU`).
  - Windows Store Apps (UWP / AppX / MSIX packages).
  - Package Managers (`winget`, `scoop`, `chocolatey`).
  - Steam Games & Applications (parses `appmanifest_*.acf` manifests).
  - Oculus VR Software & Game Libraries (JSON manifests and registry).
  - Windows Optional Features (DISM & PowerShell optional capabilities).
  - Windows Updates & Hotfixes (KBs via WUSA & Get-HotFix).
  - Standalone and orphaned directory installations (`unins000.exe`, `uninstall.exe`).

- **Intelligent Silent Uninstaller Generator**:
  - Automatically identifies uninstaller types: InnoSetup, NSIS, MSI/MsiExec, InstallShield, SdbInst, StoreApp, PowerShell, Winget, Scoop, Chocolatey, Steam, WindowsFeature, WindowsUpdate, and SimpleDelete.
  - Automatically generates quiet / silent parameter strings (e.g. `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`, `/S`, `msiexec /x {GUID} /qn /norestart`, `dism /Disable-Feature`, `wusa /uninstall /kb /quiet`) even when not provided in the registry.

- **🧹 Deep "Clean Slate" Remnant Eradication Engine**:
  - **COM / CLSID & Typelib**: Cleans orphaned `InprocServer32` / `LocalServer32` class registrations.
  - **AppCompat & Layers**: Cleans lingering application compatibility registry entries.
  - **Crash Dumps & WER Logs**: Cleans crash dumps (`%LOCALAPPDATA%\CrashDumps`) and Windows Error Reporting archives.
  - **Windows Prefetch**: Cleans `.pf` cache files for uninstalled executables.
  - **Audio Policy Config**: Cleans orphaned volume and endpoint keys.
  - **Windows Services & Drivers**: Discovers and unregisters leftover services via `sc.exe` and `CurrentControlSet\Services`.
  - **Scheduled Tasks**: Discovers and deletes updater/background tasks via `schtasks.exe`.
  - **Startup Autostart Entries**: Cleans `Run` and `RunOnce` registry keys and Startup folders.
  - **Firewall Rules**: Removes orphaned Windows Defender Firewall policy rules.
  - **App Paths**: Cleans orphaned `App Paths` binary alias registry keys.
  - **User Profile Dotfolders**: Cleans root configuration folders (e.g. `~/.appname`, `~/.config/app`).
  - **Fuzzy Confidence Scoring (Sift4)**: Evaluates match score, depth penalties, parent company boosts, and multi-level confidence: `VeryGood`, `Good`, `Questionable`, `Bad`, `Unknown`.

- **🛡️ Enterprise Safety & Rollback Protections**:
  - **Windows System Restore Point (`--restore-point`)**: Creates an official Windows System Restore Point (`Checkpoint-Computer`) before uninstallation.
  - **Native Windows Recycle Bin Deletion**: Deletes files safely via Win32 `SHFileOperationW` (zero extra dependencies).
  - **Automatic `.reg` Registry Backup**: Automatically exports registry keys to `%LOCALAPPDATA%\bcu\backups\<app>_<timestamp>.reg` before deletion for 1-click instant rollback.
  - **Process File-Lock Terminator (`--kill-running`)**: Gracefully stops blocking background processes to prevent file sharing violations during uninstalls.
  - **Authenticode Digital Signature Verifier**: Validates software publisher certificates.
  - **System Directory Blacklist**: Strictly protects core OS directories (`C:\Windows`, `System32`, user profiles, root drives).
  - **Simulation Mode**: Full preview support via `--dry-run` flag.

- **🚨 Software Vulnerability & Security Auditor (`bcu audit`)**:
  - **CVE & Advisory Cross-Referencing**: Audits installed desktop software against known CVEs and security advisories (similar to `npm audit` / `cargo audit`).
  - **Hybrid Scanning Engine**: Uses a local curated zero-latency CVE database (e.g. WinRAR, 7-Zip, PuTTY, Notepad++, VLC, Git, Python) plus live querying of Google OSV.dev feeds.
  - **Severity Badges**: Standardized CVSS ratings (`Critical`, `High`, `Medium`, `Low`) with affected version ranges and fixed patch versions.
  - **CLI & MCP Tool**: Integrated into CLI (`bcu audit --min-severity HIGH --json`) and FastMCP for AI agents.

- **🤖 AI-First CLI Design**:
  - Universal `--json` flag on all subcommands for machine consumption.
  - `bcu ai-helper` diagnostics command designed for LLMs and agent toolkits.
  - Non-interactive batch execution (`--yes` / `-y`, `--quiet`, `--deep`).

---

## 🚀 Quickstart with `uv`

### Installation

Clone the repository and install dependencies with `uv`:

```bash
# Clone the repository
cd bcuni

# Install dependencies and sync virtual environment
uv sync
```

### Running Commands

You can run the CLI via `uv run bcu` or activate the virtualenv:

```bash
# Display help and available commands
uv run bcu --help

# List installed applications in a rich table
uv run bcu list --limit 15

# Output application inventory in JSON format for AI agents
uv run bcu list --json --limit 5
```

---

## 🖥️ Big-Tech Textual Terminal User Interface (TUI)

Launch the interactive, Big-Tech tier graphical terminal interface powered by **Textual**:

```bash
# Launch TUI
uv run bcu tui
# or
uv run bcu-tui
# or
uv run bcu gui
```

### 🎮 TUI Features & Keybindings

- **Header Stats Banner**: Live counters for Total Apps, Silent Uninstall percentage, Disk Space usage, and Selection count.
- **Real-Time Live Search & Filter Bar**: Instant debounce search across names, publishers, IDs, and type dropdowns (MSI, InnoSetup, NSIS, Store Apps, Steam, Package Managers).
- **Application Grid & Inspector Sidebar**: Split view inspired by BCU's ObjectListView and properties drawer.
- **Interactive Modals**:
  - `Uninstall Modal`: Bulk uninstaller runner with live progress bar, process logs, and dry-run toggle.
  - `Junk Remnants Modal`: Deep clean-slate remnant inspector with confidence badges and auto `.reg` backup.
  - `AI Diagnostic Modal`: System health overview and recommended actions.

| Keybinding | Action |
| :--- | :--- |
| `[Space]` | Toggle checkbox selection on highlighted application |
| `[A]` | Select All / Deselect All visible applications |
| `[U]` | Open Bulk Uninstallation Manager for selected applications |
| `[J]` | Open Clean Slate Remnant Manager |
| `[D]` | Open AI Assistant Diagnostic Suite |
| `[R]` | Refresh system discovery |
| `[Q]` | Quit TUI |

### 2. `bcu search`
Quick fuzzy / regex search across applications.

```bash
uv run bcu search "Visual Studio"
uv run bcu search "^Python 3\." --regex
uv run bcu search "Adobe" --json
```

### 3. `bcu info`
Inspects all metadata, registry paths, and uninstaller commands for a specific app.

```bash
uv run bcu info "Notepad++"
uv run bcu info "reg:hklm:notepadplusplus" --json
```

### 4. `bcu scan-junk`
Scans for leftover remnants (directories, registry, services, tasks, startup entries, firewall rules) for a target application or uninstalled software.

```bash
# Deep scan remnants for a specific app
uv run bcu scan-junk "Spotify" --deep

# Set minimum confidence threshold (VeryGood, Good, Questionable, Bad)
uv run bcu scan-junk "Adobe" --min-confidence VeryGood --deep --json
```

### 5. `bcu uninstall`
Uninstalls one or more applications with automatic quiet mode, process supervision, clean-slate cleanup, and `.reg` backups.

```bash
# Interactive uninstallation
uv run bcu uninstall "Notepad++"

# Unattended silent clean-slate uninstallation (kills blocking processes & deep cleans)
uv run bcu uninstall "Spotify" --quiet --yes --deep-junk --kill-running

# Safe simulation (Dry-Run)
uv run bcu uninstall "VLC media player" --dry-run --json

# Batch uninstallation of multiple applications
uv run bcu uninstall "App1" "App2" "App3" --quiet --yes --clean-junk
```

### 6. `bcu clean-junk`
Removes leftover files, registry keys, services, and tasks for applications that were already manually deleted.

```bash
# Preview leftover deletions in dry-run mode
uv run bcu clean-junk "OldProgram" --deep --dry-run --json

# Permanently delete leftover remnants with Good or higher confidence and auto-backup
uv run bcu clean-junk "OldProgram" --deep --min-confidence Good --backup --yes
```

### 7. `bcu export`
Exports application inventory to JSON or CSV.

```bash
# Export all apps to JSON
uv run bcu export apps_backup.json --format json

# Export filtered apps to CSV
uv run bcu export large_apps.csv --format csv --query "Game"
```

### 8. `bcu ai-helper`
Provides system inventory summary, backup folder path, uninstaller health diagnostics, and actionable command guides formatted for AI assistants.

```bash
uv run bcu ai-helper --json
```

---

## 🔌 Model Context Protocol (MCP) Server

BCU includes a native **Model Context Protocol (MCP)** server, enabling seamless integration with AI tools such as **Claude Desktop, Cursor, VS Code Copilot, Antigravity, Windsurf, and custom LLM agents**.

### 🛠️ Exposed MCP Tools

1. `list_applications`: Lists installed software with query, publisher, size, and quiet filters.
2. `search_applications`: Fast search by keyword or regex.
3. `get_application_info`: Inspects complete metadata, quiet commands, registry paths, and size.
4. `scan_application_junk`: Performs deep clean-slate remnant scans (files, registry, services, tasks, startup, firewall).
5. `uninstall_application`: Safely simulates or executes uninstallation with auto `.reg` backup and process termination.
6. `clean_application_junk`: Cleans remnants for target or uninstalled software.
7. `get_system_inventory_summary`: Executive system diagnostics and large apps overview.

### ⚙️ Claude Desktop / MCP Client Configuration

Add this to your `claude_desktop_config.json` or MCP settings:

```json
{
  "mcpServers": {
    "bcu-uninstaller": {
      "command": "uv",
      "args": [
        "--directory",
        "C:\\Users\\italo\\Downloads\\bcuni",
        "run",
        "bcu-mcp"
      ]
    }
  }
}
```

Or run directly in terminal:
```bash
uv run bcu mcp
# or
uv run bcu-mcp
```

---

## 🧪 Testing

Run the test suite using `pytest` via `uv`:

```bash
# Run all 35 tests
uv run pytest

# Run tests with detailed verbose output
uv run pytest -v
```

---

## 📄 License

This project is licensed under the **Apache License 2.0** - matching the original Bulk Crap Uninstaller license. See [LICENSE](LICENSE) for details.
