# VSX-Bastion YAML Blacklist System

📖 **[← Back to Main README](../README.md)** | **[YAML Config Guide](YAML_CONFIG_GUIDE.md)** | **[Quick Reference](QUICK_REFERENCE.md)**

## Overview

The VSX-Bastion scanner now supports a YAML-based blacklist system that automatically blocks malicious or vulnerable extensions while allowing fast, secure installations from your curated whitelist.

## How It Works

### 1. YAML Whitelist Format
Your extensions are now managed in `whitelist.yaml` with install flags:

```yaml
authors:
  Microsoft:
    - id: ms-python.python
      url: https://marketplace.visualstudio.com/items?itemName=ms-python.python
      install: true    # This extension will be installed
    - id: ms-python.debugpy
      url: https://marketplace.visualstudio.com/items?itemName=ms-python.debugpy
      install: false   # This extension is approved but not installed by default
```

### 2. Blacklist Override System
- **Whitelist**: Curated, pre-approved extensions (safe to install)
- **Blacklist**: Auto-generated security blocks (overrides whitelist)
- **Install Logic**: `whitelist.install=true AND NOT blacklisted = install`

### 3. Fast Installation Workflow
```bash
# Default: Fast install (no scanning, checks blacklist only)
python3 main.py --config whitelist.yaml

# Only when adding new extensions: Security scan
python3 VSX-Bastion/scanner.py --extension new.extension

# Periodic: Update blacklist from whitelist  
python3 VSX-Bastion/scanner.py --update-blacklist
```

## Commands

### Scanner Commands

#### Update Blacklist
```bash
# Scan all extensions marked install=true and update blacklist
python3 VSX-Bastion/scanner.py --update-blacklist --whitelist whitelist.yaml
```

This will:
- Scan only extensions with `install: true`
- Block extensions with `MALWARE` status
- Block extensions with `HIGH`/`CRITICAL` vulnerabilities  
- Queue low-confidence detections for manual review
- Update blacklist metadata

#### Scan Single Extension
```bash
# Test a new extension before adding to whitelist
python3 VSX-Bastion/scanner.py --extension publisher.extension-name
```

#### Scan All Whitelist Extensions
```bash
# Comprehensive security audit of entire whitelist
python3 VSX-Bastion/scanner.py --whitelist whitelist.yaml
```

### Main Installer Commands

#### Fast Install (Recommended)
```bash
# Install extensions marked install=true, skip blacklisted ones
python3 main.py --config whitelist.yaml
```

#### Scan Before Install
```bash
# Scan new/unverified extensions before installing
python3 main.py --scan-new --config whitelist.yaml
```

## File Formats

### Blacklist Structure (`blacklist.yaml`)

```yaml
# Auto-generated - DO NOT EDIT MANUALLY
blocked_extensions:
  malicious.extension:
    reason: "MALWARE"
    blocked_date: "2025-01-20"
    details: "Remote code execution detected"
    risk_level: "CRITICAL"

  vulnerable.package:
    reason: "VULNERABLE" 
    blocked_date: "2025-01-20"
    details: "High severity CVE in dependencies"
    risk_level: "HIGH"

review_queue:
  questionable.extension:
    reason: "LOW_CONFIDENCE"
    queued_date: "2025-01-20"
    details: "Low confidence threats detected: 0.45"

metadata:
  last_updated: "2025-01-20"
  scanner_version: "2.0"
  total_blocked: 2
  total_review_queue: 1
```

## Security Policies

### Auto-Block Rules
- **MALWARE**: Always blocked automatically
- **HIGH/CRITICAL Vulnerabilities**: Blocked automatically  
- **MEDIUM/LOW Vulnerabilities**: Allowed (with warning)
- **LOW CONFIDENCE**: Added to review queue

### Review Queue
Extensions in the review queue are temporarily blocked pending manual review:
- Low confidence threat detections
- Suspicious but unclear patterns
- False positive candidates

### Blacklist Precedence
The blacklist **always overrides** whitelist decisions:
- `whitelist.install=true` + `blacklisted=true` = **NOT INSTALLED**
- Extensions are blocked until manually removed from blacklist

## Workflow Examples

### Daily Extension Installation
```bash
# Fast, secure installation from curated list
python3 main.py --config whitelist.yaml
# ✅ Installs: ms-python.python, github.copilot, esbenp.prettier-vscode
# 🚫 Skips: any blacklisted extensions
# ⏱️  Time: ~30 seconds (no scanning)
```

### Adding New Extensions
```bash
# 1. Test new extension
python3 VSX-Bastion/scanner.py --extension new.cool-extension

# 2. If clean, add to whitelist.yaml
# Edit whitelist.yaml:
#   - id: new.cool-extension
#     install: true

# 3. Install normally
python3 main.py --config whitelist.yaml
```

### Weekly Security Maintenance  
```bash
# Update blacklist from current whitelist
python3 VSX-Bastion/scanner.py --update-blacklist

# Check for newly blocked extensions
cat blacklist.yaml
```

### Security Audit
```bash
# Comprehensive scan of all whitelisted extensions
python3 VSX-Bastion/scanner.py --whitelist whitelist.yaml

# Review detailed security report
cat reports/enhanced_security_report_*.json
```

## Benefits

### Performance
- **Fast Installs**: No scanning delay (30s vs 30+ minutes)
- **Efficient**: Only scan when adding new extensions
- **Scalable**: Handles large whitelists efficiently

### Security  
- **Zero Trust**: Blacklist blocks known threats
- **Curated Whitelist**: Pre-approved, verified extensions
- **Automatic Protection**: New threats blocked without user action
- **Audit Trail**: Complete history of security decisions

### Workflow
- **Developer Friendly**: Simple install commands
- **Maintainer Friendly**: Clear security oversight
- **CI/CD Ready**: Scriptable and automatable
- **Flexible**: Support both YAML and legacy text formats

## Migration from Legacy Format

### From Plain Text Whitelist
```bash
# Old format (still supported)
python3 VSX-Bastion/scanner.py --whitelist old-whitelist.txt

# New format  
python3 VSX-Bastion/scanner.py --whitelist whitelist.yaml
```

### Converting Extensions List
```bash
# Convert plain text to YAML format
# old-whitelist.txt:
# ms-python.python
# github.copilot

# whitelist.yaml:
# authors:
#   Microsoft:
#     - id: ms-python.python
#       install: true
#   GitHub:  
#     - id: github.copilot
#       install: true
```

## Troubleshooting

### YAML Not Available
```bash
# Install PyYAML
pip install PyYAML
```

### Blacklist Issues
```bash
# Check blacklist status
cat blacklist.yaml

# Force blacklist update
python3 VSX-Bastion/scanner.py --update-blacklist --whitelist whitelist.yaml

# Manual blacklist edit (not recommended)
# Edit blacklist.yaml carefully and update metadata dates
```

### Extension Blocked Incorrectly
```bash
# Check blocking reason
grep -A5 "extension-id" blacklist.yaml

# Review security report
cat reports/enhanced_security_report_*.json

# If false positive, manually remove from blacklist.yaml
# (Update metadata last_updated date)
```

## Best Practices

### For Teams
1. **Regular Blacklist Updates**: Weekly `--update-blacklist` runs
2. **Review Queue Monitoring**: Check and resolve review queue entries
3. **Security Reports**: Archive and review security reports
4. **Whitelist Curation**: Only add well-vetted extensions

### For CI/CD
1. **Automated Blacklist Updates**: Scheduled scanner runs
2. **Security Gates**: Block deployments with new threats
3. **Audit Logging**: Track all extension changes
4. **Emergency Response**: Rapid blocking of new threats

### For Security
1. **Defense in Depth**: Blacklist + container isolation + pattern detection
2. **Threat Intelligence**: Regular pattern updates
3. **Incident Response**: Investigation of blocked extensions
4. **False Positive Tuning**: Continuous improvement of detection accuracy

## Integration

### With CI/CD Pipelines
```yaml
# GitHub Actions example
- name: Update Extension Blacklist
  run: |
    python3 VSX-Bastion/scanner.py --update-blacklist
    if [ -s blacklist.yaml ]; then
      echo "New threats detected - review required"
      cat blacklist.yaml
    fi
```

### With Configuration Management
```bash
# Ansible/Chef/Puppet integration
python3 main.py --config {{ whitelist_file }}
```

### With Security Tools
```bash
# Export security data
python3 VSX-Bastion/scanner.py --format json > security-report.json

# Import into SIEM/security tools
curl -X POST security-api/events -d @security-report.json
```

## Maintenance

### Regular Tasks
- **Weekly**: Update blacklist from whitelist
- **Monthly**: Review and resolve review queue  
- **Quarterly**: Comprehensive whitelist security audit
- **As Needed**: Add new extensions, investigate blocked extensions

### Monitoring
- **Blacklist Growth**: Track number of blocked extensions
- **Review Queue**: Monitor pending manual reviews  
- **False Positives**: Track and tune detection accuracy
- **Performance**: Monitor scan times and system resources

---

## 📚 Related Documentation

- **[Main README](../README.md)** - Overview, installation, and basic workflows
- **[YAML Configuration Guide](YAML_CONFIG_GUIDE.md)** - Complete YAML format specification and best practices
- **[Quick Reference](QUICK_REFERENCE.md)** - At-a-glance commands and format reference

## 🔗 Quick Navigation

- **[YAML Whitelist Format](#1-yaml-whitelist-format)** - Configuration file structure
- **[Blacklist Override System](#2-blacklist-override-system)** - Security protection mechanism
- **[Fast Installation Workflow](#3-fast-installation-workflow)** - Performance-first approach
- **[Security Policies](#security-policies)** - Auto-block rules and review queue
- **[Workflow Examples](#workflow-examples)** - Common usage patterns

**Note**: This blacklist system provides additional security layers but requires PyYAML (`pip install PyYAML`). The scanner gracefully falls back to legacy text format if YAML is not available.

For basic setup and usage, see the [Main README](../README.md). For detailed YAML configuration, see the [YAML Configuration Guide](YAML_CONFIG_GUIDE.md).