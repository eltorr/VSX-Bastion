# VSX-Bastion - YAML-Based VS Code Extension Manager

Tool for installing VS Code extensions using YAML configuration, with security scanning to detect malicious extensions.

## Why VSX-Bastion Exists

Malicious VS Code extensions have compromised developer systems, leading to data theft and unauthorized code execution.

### Real-World Extension Attacks

- July 2025: Malicious pull request in Ethcode extension targeted 6,000+ users, adding dependency for malware that stole cryptocurrency.
- April 2025: Fake extensions like "Discord Rich Presence" (189,000 installs) and "Prettier Code for VSCode" (955,000 installs) installed cryptominers and disabled Windows security.
- May 2025: Three Solidity-focused extensions stole wallet credentials via obfuscated JS and PowerShell.
- 2023: Proof-of-concept fake Prettier extension gained 1,000+ installs in 48 hours.
- 2023: "Theme Darcula dark" (45,000+ installs) stole PII and opened backdoors.
- 2024 Research: 1,283 malicious extensions with 229 million installs, some opening reverse shells.

### Common Attack Vectors

- Typosquatting: Extensions with names similar to legitimate ones.
- Publisher spoofing: Impersonating trusted publishers.
- Compromised accounts: Hijacking legitimate extensions.
- Social engineering: Promoting malicious extensions via fake resources.

### VSX-Bastion Features

- Curated whitelist: Lists verified official extensions by publisher.
- Container isolation: Uses a container with official VS Code to install extensions.
- Automated scanning: Detects malicious patterns in downloaded extensions.
- Official URLs: Requires links to verified marketplace entries.
- Blacklist override: Blocks known malicious extensions.

## 🚀 Quick Installation

### Dependencies
- **Python 3.7+**
- **Docker** (for container-based installation and security scanning)

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

## 🎯 How VSX-Bastion Protects You

VSX-Bastion uses a **bastion host approach** - creating temporary Docker containers with official VS Code to safely install extensions. Each installation uses a fresh, isolated environment that:

1. **Creates temporary container** with official VS Code for each extension
2. **Fetches extensions** from verified official sources only in isolation
3. **Scans for malicious code** using pattern detection and behavioral analysis
4. **Installs in mounted directory** preventing direct access to your development machine
5. **Transfers clean extensions** to your selected editor's extensions folder
6. **Auto-destroys container** ensuring no persistent contamination between runs

### Security Architecture

- **📋 YAML Configuration**: Extensions organized by verified publisher with install flags
- **🔒 Temporary Container Isolation**: Fresh Docker container for each extension prevents malicious code execution on host
- **⚡ Curated Installation**: Install verified extensions in ~30 seconds using bastion approach
- **🎯 Multi-Editor Support**: VS Code, Cursor, Windsurf, VSCodium, Code-OSS
- **🛡️ Dynamic Threat Detection**: Real-time scanning with auto-updating threat intelligence
- **🧹 Auto-Cleanup**: Containers automatically destroyed after each installation

## 📋 Configuration Format

### YAML Whitelist (`extensions-list/whitelist.yaml`)

Extensions are organized by **verified publisher** with official marketplace URLs:

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

**Required fields**: `id` (official extension ID), `url` (official marketplace URL), `install` (true/false)

### Security Blacklist (`extensions-list/blacklist.yaml`)

Auto-generated security blocks override whitelist decisions:

```yaml
blocked_extensions:
  malicious.example:
    reason: "MALWARE"
    details: "Remote code execution detected"
    threat_level: "HIGH"
    detection_date: "2024-01-15"
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
- ✅ **INSTALLABLE**: Whitelisted + install: true + not blocked + verified safe
- ⏸️ **WHITELISTED**: Approved but install: false (available for manual install)
- 🚫 **BLOCKED**: Security blacklist blocked due to threats detected
- ⏳ **UNDER_REVIEW**: Temporarily blocked pending security analysis

### Multi-Layer Protection
- **Publisher Verification**: Only official publishers from verified marketplace entries
- **URL Validation**: Direct links to official VS Code marketplace prevent spoofing
- **Container Isolation**: Bastion approach prevents malicious code from accessing host system
- **Pattern Detection**: AI-powered scanning identifies malicious code patterns
- **Behavioral Analysis**: Detects suspicious extension behaviors (network calls, file access, etc.)
- **Automatic Updates**: Blacklist automatically updated with latest threat intelligence

## 📁 File Structure

```
VSX-Bastion/
├── main.py              # Main installer application
├── scanner.py           # Security scanner with threat detection
├── requirements.txt     # Python dependencies
├── extensions-list/     # Configuration files directory
│   ├── whitelist.yaml   # Curated extension configuration
│   └── blacklist.yaml   # Security blocks (auto-generated)
├── modules/             # Core application modules
│   ├── config.py        # Centralized configuration constants
│   ├── app.py           # Main application logic
│   └── ...              # Other security modules
├── reports/             # Security scan reports
└── docs/               # Detailed documentation
```

## 🔧 Common Workflows

### Daily Development Setup
```bash
# Fast installation of curated environment (~30 seconds)
python3 main.py --config extensions-list/whitelist.yaml --editor cursor

# Install only extensions marked with install: true
python3 main.py --config extensions-list/whitelist.yaml

# Install all whitelisted extensions regardless of install flag
python3 main.py --config extensions-list/whitelist.yaml --install-all
```

### Security Scanning Workflows
```bash
# Install with security scanning first
python3 main.py --config extensions-list/whitelist.yaml --scan-new

# Scan only without installing
python3 main.py --config extensions-list/whitelist.yaml --scan-only

# Skip scanning entirely (faster, less secure)
python3 main.py --config extensions-list/whitelist.yaml --no-scan
```

### Cleanup and Maintenance
```bash
# Clean extensions directory before installing (fresh start)
python3 main.py --config extensions-list/whitelist.yaml --cleanup

# Force reinstall extensions (updates to latest versions)
python3 main.py --config extensions-list/whitelist.yaml --force-reinstall

# Full cleanup with force reinstall
python3 main.py --config extensions-list/whitelist.yaml --cleanup --force-reinstall
```

### Team Environment Protection
```bash
# Deploy curated extensions across team
python3 main.py --config extensions-list/team-config.yaml --install-all --scan-new

# Verbose output for debugging
python3 main.py --config extensions-list/whitelist.yaml --verbose
```

### Security Monitoring
```bash
# List all whitelisted extensions
python3 main.py --list-all

# List extensions marked for installation
python3 main.py --list-installable

# Check specific extension security status
python3 main.py --status extension.name

# Force install even with security concerns (use with caution)
python3 main.py --config extensions-list/whitelist.yaml --force
```

## 🐛 Quick Troubleshooting

### Security Validation
```bash
# YAML syntax errors
python3 -c "import yaml; yaml.safe_load(open('extensions-list/whitelist.yaml'))"

# Check configuration status
python3 main.py --list-all

# Extension security analysis
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

## 📚 Command Reference

### Core Installation Commands
```bash
# Basic installation (extensions with install: true)
python3 main.py --config extensions-list/whitelist.yaml

# Install all whitelisted extensions
python3 main.py --config extensions-list/whitelist.yaml --install-all

# Install for specific editor
python3 main.py --config extensions-list/whitelist.yaml --editor vscode
```

### Security Options
```bash
# Scan extensions before installing
python3 main.py --config extensions-list/whitelist.yaml --scan-new

# Scan only, don't install
python3 main.py --config extensions-list/whitelist.yaml --scan-only

# Skip security scanning
python3 main.py --config extensions-list/whitelist.yaml --no-scan

# Force install despite security warnings
python3 main.py --config extensions-list/whitelist.yaml --force
```

### Cleanup Options
```bash
# Clean target directory before installing
python3 main.py --config extensions-list/whitelist.yaml --cleanup

# Force reinstall extensions (updates)
python3 main.py --config extensions-list/whitelist.yaml --force-reinstall
```

### Information Commands
```bash
# List all whitelisted extensions
python3 main.py --list-all

# List extensions marked for installation
python3 main.py --list-installable

# Check specific extension status
python3 main.py --status extension.name

# Verbose output for debugging
python3 main.py --config extensions-list/whitelist.yaml --verbose
```

### Essential Security Guides
- **[Quick Reference](docs/QUICK_REFERENCE.md)** - Complete command reference and security format guide
- **[YAML Configuration Guide](docs/YAML_CONFIG_GUIDE.md)** - Safe configuration format, guidelines, and best practices
- **[Blacklist System](docs/BLACKLIST_SYSTEM.md)** - Security architecture and threat detection workflows

## ⚡ Performance

- **Secure Install** (4 verified extensions): ~30 seconds
- **Bulk Install** (27 verified extensions): ~2-3 minutes
- **With Security Scan**: +15-30 minutes (one-time verification for new extensions)
- **Temporary Container Overhead**: ~2-3 seconds per extension (isolation for security)
- **Fresh Container Per Extension**: Ensures maximum security isolation

## 🔒 Security Best Practices

### Critical Security Rules
1. **🔍 ALWAYS Scan First**: Use `python3 scanner.py --extension new.extension` before adding any extension
2. **🔗 Official URLs Only**: Always use direct VS Code marketplace links
3. **✅ Verify Publishers**: Confirm exact publisher names from official marketplace
4. **⚠️ Minimal Install Flags**: Only mark truly essential extensions as `install: true`
5. **🔄 Regular Scans**: Use `--scan-new` periodically for new extensions
6. **📊 Monitor Blacklist**: Review blocked extensions and security reports regularly

### Protection Against Common Attacks
- **Typosquatting Protection**: Whitelist contains only verified official extension IDs
- **Publisher Spoofing Prevention**: Official marketplace URLs prevent fake publishers
- **Supply Chain Security**: Container isolation prevents malicious code execution
- **Credential Protection**: Bastion approach prevents access to development credentials

For comprehensive security guidelines, see [Blacklist System Documentation](docs/BLACKLIST_SYSTEM.md).

## 🤝 Contributing Safely

### Adding Extensions to Whitelist
1. **🔍 Security Research**: Verify publisher legitimacy and scan for threats
2. **📋 Format Verification**: Follow [YAML Configuration Guide](docs/YAML_CONFIG_GUIDE.md#required-fields)
3. **🛡️ Security Testing**: ALWAYS test with `python3 scanner.py --extension new.extension`
4. **📚 Guidelines**: See [YAML Configuration Guide](docs/YAML_CONFIG_GUIDE.md) for detailed security requirements

### Security Reporting
If you discover a malicious extension or security vulnerability:
1. **DO NOT** install or test the extension outside of VSX-Bastion
2. Scan the extension for threats: `python3 scanner.py --extension suspicious.extension`
3. Submit security issues through proper channels

---

**VSX-Bastion v2.0** - Protecting developers from extension-based attacks through security-first design.

**🛡️ Stay Safe**: See [Quick Reference](docs/QUICK_REFERENCE.md) for complete security command guide.

**⚠️ Remember**: The cost of a single compromised extension can be devastating. VSX-Bastion ensures you only install verified, safe extensions from legitimate publishers.
