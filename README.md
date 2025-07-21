# VSX-Bastion - YAML-Based Secure VS Code Extension Manager

A modern, security-first VS Code extension installer that uses YAML configuration files to manage extensions with metadata and automated security protection.

## 🚀 Quick Installation

### Dependencies
- **Python 3.7+**
- **Docker** (optional, for security scanning)

### Setup
```bash
# 1. Clone repository
git clone <repository-url>
cd VSX-Bastion

# 2. Create virtual environment
python3 -m venv vsx-bastion-env

# 3. Activate virtual environment
source vsx-bastion-env/bin/activate  # Linux/macOS
# or
.\vsx-bastion-env\Scripts\activate   # Windows

# 4. Install Python dependencies
pip install -r requirements.txt

# 5. Verify installation
python3 main.py --list-installable

# 6. Test YAML syntax
python3 -c "import yaml; yaml.safe_load(open('extensions-list/whitelist.yaml'))"
```



### First Use
```bash
# Install extensions marked for installation
python3 main.py --config extensions-list/whitelist.yaml

# Install for specific editor
python3 main.py --config extensions-list/whitelist.yaml --editor cursor
```

## 🎯 What is VSX-Bastion?

VSX-Bastion transforms VS Code extension management from manual installations to a **curated, automated workflow**:

- **📋 YAML Configuration**: Extensions organized by publisher with install flags
- **🔒 Security Protection**: Automatic blocking of malicious extensions
- **⚡ Fast Installation**: Install curated extensions in ~30 seconds
- **🎯 Multi-Editor Support**: VS Code, Cursor, Windsurf, VSCodium, Code-OSS

## 📋 How It Works

### YAML Configuration (`extensions-list/whitelist.yaml`)

Extensions are organized by publisher with install flags:

```yaml
authors:
  Microsoft:
    - id: ms-python.python
      url: https://marketplace.visualstudio.com/items?itemName=ms-python.python
      install: true    # Will be installed by default
    - id: ms-python.vscode-pylance
      url: https://marketplace.visualstudio.com/items?itemName=ms-python.vscode-pylance
      install: false   # Available but not installed by default

  GitHub:
    - id: github.copilot
      url: https://marketplace.visualstudio.com/items?itemName=github.copilot
      install: true
```

**Required fields**: `id`, `url` (official marketplace), `install` (true/false)

### Security Protection (`extensions-list/blacklist.yaml`)

Auto-generated security blocks override whitelist decisions:

```yaml
blocked_extensions:
  malicious.example:
    reason: "MALWARE"
    details: "Remote code execution detected"
```

**Security guarantee**: Even if an extension has `install: true`, it won't be installed if blacklisted.

## 🎯 Supported Editors

| Editor | Command | Extensions Path |
|--------|---------|----------------|
| Cursor AI | `--editor cursor` | `~/.cursor/extensions` |
| Windsurf | `--editor windsurf` | `~/.windsurf/extensions` |
| VS Code | `--editor vscode` | `~/.vscode/extensions` |
| VSCodium | `--editor vscodium` | `~/.vscode-oss/extensions` |
| Code-OSS | `--editor code-oss` | `~/.vscode-oss/extensions` |

## 🛡️ Security Features

### Extension Status Types
- ✅ **INSTALLABLE**: Whitelisted + install: true + not blocked
- ⏸️ **WHITELISTED**: Approved but install: false
- 🚫 **BLOCKED**: Security blacklist blocked
- ⏳ **UNDER_REVIEW**: Temporarily blocked pending review

### Protection Levels
- **Malware**: Never installed, even if `install: true`
- **Vulnerabilities**: Blocked automatically by security scanner
- **Under Review**: Temporarily blocked, can be bypassed with `--force`

## 📁 File Structure

```
VSX-Bastion/
├── main.py              # Main installer application
├── scanner.py           # Security scanner
├── requirements.txt     # Python dependencies
├── extensions-list/     # Configuration files directory
│   ├── whitelist.yaml   # Extension configuration
│   └── blacklist.yaml   # Security blocks (auto-generated)
├── modules/             # Core application modules
│   ├── config.py        # Centralized configuration constants
│   ├── app.py           # Main application logic
│   └── ...              # Other modules
├── reports/             # Security scan reports
└── docs/               # Detailed documentation
```

## 🔧 Common Workflows

### Daily Development Setup
```bash
# Fast installation of curated environment (~30 seconds)
python3 main.py --config extensions-list/whitelist.yaml --editor cursor
```

### Adding New Extensions
```bash
# 1. Test security first
python3 scanner.py --extension new.extension

# 2. Add to extensions-list/whitelist.yaml with proper format (see YAML guide)
# 3. Install with verification
python3 main.py --config extensions-list/whitelist.yaml --scan-new
```

### Team Environment
```bash
# Use team-specific configuration
python3 main.py --config extensions-list/team-config.yaml --install-all
```

### Utility Commands
```bash
# List all whitelisted extensions
python3 main.py --list-all

# List extensions marked for installation
python3 main.py --list-installable

# Check specific extension status
python3 main.py --status extension.name

# Update security blacklist
python3 scanner.py --update-blacklist
```

## 🐛 Quick Troubleshooting

### Common Issues
```bash
# YAML syntax errors
python3 -c "import yaml; yaml.safe_load(open('extensions-list/whitelist.yaml'))"

# Check configuration status
python3 main.py --list-all

# Extension problems
python3 main.py --status problematic.extension

# Review security blocks
cat extensions-list/blacklist.yaml
```

### Dependencies
```bash
# Install missing packages
pip install -r requirements.txt

# Verify Python version
python3 --version  # Should be 3.7+

# Reinstall in virtual environment
python3 -m venv vsx-bastion-env
source vsx-bastion-env/bin/activate
pip install -r requirements.txt
```

### Virtual Environment Issues
```bash
# Create new virtual environment
python3 -m venv vsx-bastion-env

# Activate virtual environment
source vsx-bastion-env/bin/activate  # Linux/macOS
.\vsx-bastion-env\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Verify installation
python3 -c "import requests; import yaml; print('Success')"
```

## 📚 Documentation

### Essential Guides
- **[Quick Reference](docs/QUICK_REFERENCE.md)** - Complete command reference and format guide
- **[YAML Configuration Guide](docs/YAML_CONFIG_GUIDE.md)** - Configuration format, guidelines, and best practices
- **[Blacklist System](docs/BLACKLIST_SYSTEM.md)** - Security architecture and advanced workflows

### Key Topics
- **Commands & Format**: [Quick Reference](docs/QUICK_REFERENCE.md)
- **YAML Format Guidelines**: [YAML Configuration Guide](docs/YAML_CONFIG_GUIDE.md#yaml-file-structure)
- **Adding New Extensions**: [YAML Configuration Guide](docs/YAML_CONFIG_GUIDE.md#adding-new-extensions)
- **Security Architecture**: [Blacklist System](docs/BLACKLIST_SYSTEM.md#security-policies)
- **Team Configurations**: [YAML Configuration Guide](docs/YAML_CONFIG_GUIDE.md#team-specific-configurations)

## ⚡ Performance

- **Standard Install** (4 extensions): ~30 seconds
- **Bulk Install** (27 extensions): ~2-3 minutes
- **With Security Scan**: +15-30 minutes (one-time for new extensions)

## 🔒 Security Best Practices

1. **Use Official URLs**: Always link to VS Code marketplace
2. **Verify Publishers**: Use exact publisher names from marketplace
3. **Minimal Install Flags**: Only mark essential extensions `install: true`
4. **Regular Security Scans**: Use `--scan-new` for new extensions
5. **Monitor Blacklist**: Review blocked extensions regularly

For comprehensive security guidelines, see [Blacklist System Documentation](docs/BLACKLIST_SYSTEM.md).

## 🤝 Contributing

### Adding Extensions to Whitelist
1. **Research**: Verify publisher and official marketplace URL
2. **Format**: Follow [YAML Configuration Guide](docs/YAML_CONFIG_GUIDE.md#required-fields)
3. **Security**: Test with `python3 scanner.py --extension new.extension`
4. **Guidelines**: See [YAML Configuration Guide](docs/YAML_CONFIG_GUIDE.md) for detailed requirements

---

**VSX-Bastion v2.0** - Modern YAML-based extension management with security-first design.

**Need commands?** See [Quick Reference](docs/QUICK_REFERENCE.md) for complete command guide.
