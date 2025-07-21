# VSX-Bastion Quick Reference

📖 **[← Back to Main README](../README.md)** | **[YAML Config Guide](YAML_CONFIG_GUIDE.md)** | **[Blacklist System](BLACKLIST_SYSTEM.md)**

## 🚀 Essential Commands

### Installation
```bash
# Install extensions marked install: true
python3 main.py --config extensions-list/whitelist.yaml

# Install all whitelisted extensions
python3 main.py --config extensions-list/whitelist.yaml --install-all

# Install for specific editor
python3 main.py --config extensions-list/whitelist.yaml --editor cursor
```

### Security
```bash
# Scan new extensions before install
python3 main.py --config extensions-list/whitelist.yaml --scan-new

# Security scan only (no install)
python3 main.py --config extensions-list/whitelist.yaml --scan-only

# Force install extensions under review
python3 main.py --config extensions-list/whitelist.yaml --force
```

### Information
```bash
# List extensions marked for installation
python3 main.py --list-installable

# List all whitelisted extensions
python3 main.py --list-all

# Check extension status
python3 main.py --status extension.name

# Update security blacklist
python3 scanner.py --update-blacklist
```

## 📋 YAML Format

### Basic Structure
```yaml
authors:
  Publisher Name:
    - id: publisher.extension-name
      url: https://marketplace.visualstudio.com/items?itemName=publisher.extension-name
      install: true
```

### Required Fields
- `id`: Extension identifier (publisher.extension-name)
- `url`: Official marketplace URL
- `install`: Boolean (true/false)

### Example Configuration
```yaml
authors:
  Microsoft:
    - id: ms-python.python
      url: https://marketplace.visualstudio.com/items?itemName=ms-python.python
      install: true
    - id: ms-python.vscode-pylance
      url: https://marketplace.visualstudio.com/items?itemName=ms-python.vscode-pylance
      install: false

  GitHub:
    - id: github.copilot
      url: https://marketplace.visualstudio.com/items?itemName=github.copilot
      install: true
```

## 🛡️ Security Features

### Blacklist Override
- Extensions in `blacklist.yaml` are **never installed**
- Blacklist overrides `install: true` in whitelist
- Protects against compromised extensions

### Extension Status
- ✅ **INSTALLABLE**: Whitelisted + install: true + not blocked
- ⏸️ **WHITELISTED**: Approved but install: false
- 🚫 **BLOCKED**: Security blacklist blocked
- ⏳ **UNDER_REVIEW**: Temporarily blocked pending review

## 🎯 Supported Editors

| Editor | ID | Command |
|--------|----|----|
| Cursor AI | `cursor` | `--editor cursor` |
| Windsurf | `windsurf` | `--editor windsurf` |
| VS Code | `vscode` | `--editor vscode` |
| VSCodium | `vscodium` | `--editor vscodium` |
| Code-OSS | `code-oss` | `--editor code-oss` |

## ⚡ Quick Workflows

### Daily Setup
```bash
python3 main.py --config extensions-list/whitelist.yaml --editor cursor
# Fast install of pre-verified extensions (~30 seconds)
```

### New Extension Testing
```bash
# 1. Test security
python3 scanner.py --extension new.extension

# 2. Add to whitelist.yaml with install: true

# 3. Install with verification
python3 main.py --config extensions-list/whitelist.yaml --scan-new
```

### Team Deployment
```bash
# Production environment
python3 main.py --config extensions-list/production.yaml --install-all

# Development environment
python3 main.py --config extensions-list/development.yaml
```

## 🔧 Common Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `--config` | YAML config file | `--config team.yaml` |
| `--editor` | Target editor | `--editor windsurf` |
| `--install-all` | Install all whitelisted | `--install-all` |
| `--scan-new` | Security scan enabled | `--scan-new` |
| `--scan-only` | Scan without install | `--scan-only` |
| `--force` | Force install under review | `--force` |
| `--verbose` | Detailed output | `--verbose` |

## 🐛 Quick Troubleshooting

### YAML Errors
```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('extensions-list/whitelist.yaml'))"

# Check configuration
python3 main.py --list-all
```

### Extension Issues
```bash
# Check extension status
python3 main.py --status problematic.extension

# Verify format: publisher.extension-name (not publisher/extension-name)
```

### Security Blocks
```bash
# Check blacklist
cat extensions-list/blacklist.yaml

# Review blocking reason
python3 main.py --status blocked.extension
```

## 📁 File Structure
```
vsx-bastion/
├── main.py              # Main installer
├── scanner.py           # Security scanner
├── extensions-list/     # Configuration files
│   ├── whitelist.yaml   # Extension configuration
│   └── blacklist.yaml   # Security blocks (auto-generated)
├── modules/             # Core modules
│   ├── config.py        # Centralized configuration
│   ├── app.py           # Main application logic
│   └── ...              # Other modules
└── docs/               # Documentation
```

## ✅ Install Flag Decision Guide

### Use `install: true` for:
- Essential development tools
- Team-wide standards
- Required for project builds
- Security/compliance tools

### Use `install: false` for:
- Specialized/optional tools
- Personal preference extensions
- Resource-intensive extensions
- Experimental features

## 🔒 Security Best Practices

1. **Always use official marketplace URLs**
2. **Verify publisher names are correct**
3. **Review security blacklist regularly**
4. **Test new extensions before adding to team config**
5. **Keep install: true list minimal for performance**

---

## 📚 Related Documentation

- **[Main README](../README.md)** - Overview, installation, and basic workflows
- **[YAML Configuration Guide](YAML_CONFIG_GUIDE.md)** - Complete YAML format specification and best practices
- **[Blacklist System](BLACKLIST_SYSTEM.md)** - Security architecture and blacklist management

## 🔗 Quick Navigation

- **[Essential Commands](#essential-commands)** - Core installation and security commands
- **[YAML Format](#yaml-format)** - Configuration file structure
- **[Security Features](#security-features)** - Blacklist and protection systems
- **[Workflows](#quick-workflows)** - Common usage patterns
- **[Troubleshooting](#quick-troubleshooting)** - Problem resolution

**Quick Start**: `python3 main.py --config extensions-list/whitelist.yaml`

For comprehensive setup and usage, see the [Main README](../README.md). For detailed YAML configuration, see the [YAML Configuration Guide](YAML_CONFIG_GUIDE.md).