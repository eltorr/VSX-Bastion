# VSX-Bastion YAML Configuration Guide

📖 **[← Back to Main README](../README.md)** | **[Quick Reference](QUICK_REFERENCE.md)** | **[Blacklist System](BLACKLIST_SYSTEM.md)**

## Overview

VSX-Bastion uses YAML configuration files to manage extensions with rich metadata, install flags, and author organization. All configuration files are stored in the `extensions-list/` directory with centralized path management through the config system. This guide covers the complete YAML format specification and best practices.

## YAML File Structure

### Basic Format

```yaml
# VSX-Bastion Extension Whitelist
# YAML format with install flags and author organization

authors:
  Author Name:
    - id: publisher.extension-name
      url: https://marketplace.visualstudio.com/items?itemName=publisher.extension-name
      install: true
```

### Required Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✅ | Extension identifier (publisher.extension-name) |
| `url` | string | ✅ | Official VS Code marketplace URL |
| `install` | boolean | ✅ | Whether to install by default (true/false) |

### Author Organization

Extensions must be grouped under the `authors` key by publisher/company name:

```yaml
authors:
  Microsoft:           # Publisher/Company name
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

## Configuration System

### Centralized Path Management

VSX-Bastion uses a centralized configuration system located in `modules/config.py` that manages all file paths and constants:

```python
# modules/config.py - Centralized configuration
EXTENSIONS_DIR = "extensions-list"
DEFAULT_WHITELIST_PATH = "extensions-list/whitelist.yaml"
DEFAULT_BLACKLIST_PATH = "extensions-list/blacklist.yaml"
SUPPORTED_EDITORS = ["cursor", "windsurf", "vscodium", "vscode", "code-oss"]
```

### File Structure

All configuration files are organized in the `extensions-list/` directory:

```
vsx-bastion/
├── extensions-list/
│   ├── whitelist.yaml       # Main extension configuration
│   ├── blacklist.yaml       # Security blacklist (auto-generated)
│   ├── production.yaml      # Production environment config
│   └── development.yaml     # Development environment config
├── modules/
│   ├── config.py           # Centralized configuration constants
│   └── ...                 # Other modules
└── main.py                 # Uses config.DEFAULT_WHITELIST_PATH by default
```

### Default Behavior

- **Default whitelist**: `extensions-list/whitelist.yaml`
- **Default blacklist**: `extensions-list/blacklist.yaml`
- **Custom configs**: Place in `extensions-list/` directory
- **Path changes**: Modify only `modules/config.py` to update all references

## Field Specifications

### Extension ID Format

Extension IDs must follow the format: `publisher.extension-name`

```yaml
# ✅ CORRECT
id: ms-python.python
id: github.copilot
id: esbenp.prettier-vscode

# ❌ INCORRECT
id: ms-python/python           # Wrong separator
id: Python                     # Missing publisher
id: ms-python.python.latest    # Extra components
```

### Marketplace URL Format

URLs must link to the official VS Code marketplace:

```yaml
# ✅ CORRECT
url: https://marketplace.visualstudio.com/items?itemName=ms-python.python

# ❌ INCORRECT
url: https://github.com/microsoft/vscode-python           # GitHub repo
url: https://open-vsx.org/extension/ms-python/python      # Alternative marketplace
url: https://marketplace.visualstudio.com/ms-python      # Incomplete URL
```

### Install Flag Values

The `install` field must be a boolean:

```yaml
# ✅ CORRECT
install: true
install: false

# ❌ INCORRECT
install: "true"     # String instead of boolean
install: yes        # YAML yes/no syntax
install: 1          # Number instead of boolean
```

## Complete Example Configuration

```yaml
# VSX-Bastion Extension Whitelist
# Production configuration for development team

authors:
  Microsoft:
    # Python development
    - id: ms-python.python
      url: https://marketplace.visualstudio.com/items?itemName=ms-python.python
      install: true
    - id: ms-python.vscode-pylance
      url: https://marketplace.visualstudio.com/items?itemName=ms-python.vscode-pylance
      install: false
    - id: ms-python.debugpy
      url: https://marketplace.visualstudio.com/items?itemName=ms-python.debugpy
      install: false
    
    # TypeScript/JavaScript
    - id: ms-vscode.vscode-typescript-next
      url: https://marketplace.visualstudio.com/items?itemName=ms-vscode.vscode-typescript-next
      install: false
    
    # Docker
    - id: ms-azuretools.vscode-docker
      url: https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-docker
      install: false
    
    # Remote development
    - id: ms-vscode-remote.remote-ssh
      url: https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-ssh
      install: false
    - id: ms-vscode-remote.remote-containers
      url: https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers
      install: false

  GitHub:
    # AI assistance
    - id: github.copilot
      url: https://marketplace.visualstudio.com/items?itemName=github.copilot
      install: true
    - id: github.copilot-chat
      url: https://marketplace.visualstudio.com/items?itemName=github.copilot-chat
      install: true

  Esben Petersen:
    # Code formatting
    - id: esbenp.prettier-vscode
      url: https://marketplace.visualstudio.com/items?itemName=esbenp.prettier-vscode
      install: true

  GitLens:
    # Git integration
    - id: eamodio.gitlens
      url: https://marketplace.visualstudio.com/items?itemName=eamodio.gitlens
      install: false

  Tailwind Labs:
    # CSS framework
    - id: bradlc.vscode-tailwindcss
      url: https://marketplace.visualstudio.com/items?itemName=bradlc.vscode-tailwindcss
      install: false

  Christian Kohler:
    # Path assistance
    - id: christian-kohler.path-intellisense
      url: https://marketplace.visualstudio.com/items?itemName=christian-kohler.path-intellisense
      install: false
    - id: christian-kohler.npm-intellisense
      url: https://marketplace.visualstudio.com/items?itemName=christian-kohler.npm-intellisense
      install: false
```

## Configuration Strategies

### Install Flag Philosophy

#### Essential Extensions (`install: true`)
Mark extensions as `install: true` if they are:
- Required for basic development workflow
- Used by majority of team members
- Critical for project compilation/testing
- Security or compliance related

```yaml
# Examples of install: true extensions
- id: ms-python.python          # Core language support
  install: true
- id: github.copilot           # Team-wide AI assistance
  install: true
- id: esbenp.prettier-vscode   # Code formatting standard
  install: true
```

#### Optional Extensions (`install: false`)
Mark extensions as `install: false` if they are:
- Specialized for specific tasks
- Personal preference tools
- Experimental or beta features
- Resource intensive

```yaml
# Examples of install: false extensions
- id: ms-azuretools.vscode-docker    # Only for containerization work
  install: false
- id: eamodio.gitlens               # Advanced Git features (optional)
  install: false
- id: wayou.vscode-todo-highlight   # Personal productivity tool
  install: false
```

### Author Organization Strategies

#### By Official Publisher
Group by the official marketplace publisher name:

```yaml
authors:
  Microsoft:        # Official company name
  GitHub:           # Official organization name
  Google:           # Official company name
```

#### Consistent Naming
Use consistent, official names across the configuration:

```yaml
# ✅ CONSISTENT
authors:
  Microsoft:        # Always use "Microsoft"
  Red Hat:          # Always use "Red Hat"

# ❌ INCONSISTENT
authors:
  Microsoft:        # Sometimes "Microsoft"
  MS:              # Sometimes "MS"
  RedHat:          # Sometimes "RedHat"
  Red Hat:         # Sometimes "Red Hat"
```

#### Logical Grouping
For community extensions, group by maintainer or project:

```yaml
authors:
  Rust Language Team:
    - id: rust-lang.rust-analyzer
      install: false
  
  Go Team at Google:
    - id: golang.go
      install: false
  
  TabNine:
    - id: tabnine.tabnine-vscode
      install: false
```

## Team-Specific Configurations

### Frontend Team Configuration

```yaml
# frontend-team.yaml
authors:
  Microsoft:
    - id: ms-vscode.vscode-typescript-next
      url: https://marketplace.visualstudio.com/items?itemName=ms-vscode.vscode-typescript-next
      install: true

  Esben Petersen:
    - id: esbenp.prettier-vscode
      url: https://marketplace.visualstudio.com/items?itemName=esbenp.prettier-vscode
      install: true

  Tailwind Labs:
    - id: bradlc.vscode-tailwindcss
      url: https://marketplace.visualstudio.com/items?itemName=bradlc.vscode-tailwindcss
      install: true

  Wix:
    - id: wix.vscode-import-cost
      url: https://marketplace.visualstudio.com/items?itemName=wix.vscode-import-cost
      install: true
```

### Backend Team Configuration

```yaml
# backend-team.yaml
authors:
  Microsoft:
    - id: ms-python.python
      url: https://marketplace.visualstudio.com/items?itemName=ms-python.python
      install: true
    - id: ms-azuretools.vscode-docker
      url: https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-docker
      install: true

  Red Hat:
    - id: redhat.java
      url: https://marketplace.visualstudio.com/items?itemName=redhat.java
      install: true

  Go Team at Google:
    - id: golang.go
      url: https://marketplace.visualstudio.com/items?itemName=golang.go
      install: true
```

### Minimal Configuration

```yaml
# minimal.yaml - Essential extensions only
authors:
  Microsoft:
    - id: ms-python.python
      url: https://marketplace.visualstudio.com/items?itemName=ms-python.python
      install: true

  GitHub:
    - id: github.copilot
      url: https://marketplace.visualstudio.com/items?itemName=github.copilot
      install: true
```

## Validation and Testing

### YAML Syntax Validation

```bash
# Test YAML syntax
python3 -c "import yaml; print('Valid YAML' if yaml.safe_load(open('whitelist.yaml')) else 'Invalid YAML')"

# Detailed syntax check
python3 -c "
import yaml
try:
    with open('whitelist.yaml') as f:
        yaml.safe_load(f)
    print('✅ YAML syntax is valid')
except yaml.YAMLError as e:
    print(f'❌ YAML syntax error: {e}')
"
```

### VSX-Bastion Configuration Validation

```bash
# Test configuration loading
python3 main.py --config whitelist.yaml --list-all

# Check install flags
python3 main.py --config whitelist.yaml --list-installable

# Validate specific extension
python3 main.py --config whitelist.yaml --status ms-python.python
```

### Common Validation Errors

#### Indentation Errors
```yaml
# ❌ INCORRECT - Inconsistent indentation
authors:
  Microsoft:
  - id: ms-python.python    # Should be indented 4 spaces
    url: https://...
     install: true           # Should be indented 6 spaces

# ✅ CORRECT - Consistent 2-space indentation
authors:
  Microsoft:
    - id: ms-python.python
      url: https://...
      install: true
```

#### Missing Required Fields
```yaml
# ❌ INCORRECT - Missing URL
authors:
  Microsoft:
    - id: ms-python.python
      install: true

# ✅ CORRECT - All required fields
authors:
  Microsoft:
    - id: ms-python.python
      url: https://marketplace.visualstudio.com/items?itemName=ms-python.python
      install: true
```

#### Invalid Boolean Values
```yaml
# ❌ INCORRECT - String instead of boolean
authors:
  Microsoft:
    - id: ms-python.python
      url: https://...
      install: "true"

# ✅ CORRECT - Boolean value
authors:
  Microsoft:
    - id: ms-python.python
      url: https://...
      install: true
```

## Migration from Text Format

### Conversion Process

#### Step 1: Analyze Current Extensions
```bash
# List current extensions
cat whitelist.txt
cat extensions-to-install.txt
```

#### Step 2: Research Publisher Information
For each extension, find:
- Official publisher name
- Official marketplace URL
- Current version and status

#### Step 3: Create YAML Structure
```yaml
# Start with template
authors:
  # Group extensions by publisher
```

#### Step 4: Convert Extensions
```bash
# Old format:
# ms-python.python
# github.copilot

# New format:
authors:
  Microsoft:
    - id: ms-python.python
      url: https://marketplace.visualstudio.com/items?itemName=ms-python.python
      install: true
  GitHub:
    - id: github.copilot
      url: https://marketplace.visualstudio.com/items?itemName=github.copilot
      install: true
```

### Automated Conversion Script

```python
#!/usr/bin/env python3
"""
Convert legacy text whitelist to YAML format
Usage: python3 convert_whitelist.py whitelist.txt extensions-to-install.txt
"""

import sys
import yaml
import requests

def get_extension_info(extension_id):
    """Fetch extension information from marketplace"""
    url = f"https://marketplace.visualstudio.com/items?itemName={extension_id}"
    # This is a placeholder - actual implementation would parse marketplace data
    return {
        'publisher': extension_id.split('.')[0],
        'url': url
    }

def convert_whitelist(whitelist_file, install_file):
    """Convert text files to YAML format"""
    
    # Read whitelist
    with open(whitelist_file) as f:
        whitelisted = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    # Read install list
    with open(install_file) as f:
        to_install = set(line.strip() for line in f if line.strip() and not line.startswith('#'))
    
    # Build YAML structure
    authors = {}
    
    for ext_id in whitelisted:
        info = get_extension_info(ext_id)
        publisher = info['publisher']
        
        if publisher not in authors:
            authors[publisher] = []
        
        authors[publisher].append({
            'id': ext_id,
            'url': info['url'],
            'install': ext_id in to_install
        })
    
    # Output YAML
    config = {'authors': authors}
    print(yaml.dump(config, default_flow_style=False, sort_keys=False, indent=2))

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python3 convert_whitelist.py whitelist.txt extensions-to-install.txt")
        sys.exit(1)
    
    convert_whitelist(sys.argv[1], sys.argv[2])
```

## Best Practices Summary

### Configuration Management
1. **Version Control**: Store YAML files in git with proper commit messages
2. **Review Process**: Require peer review for whitelist changes
3. **Testing**: Validate changes before deployment
4. **Documentation**: Comment rationale for install flag decisions

### Security Considerations
1. **URL Verification**: Always use official marketplace URLs
2. **Publisher Verification**: Verify publisher identity before adding
3. **Regular Audits**: Review extensions quarterly for security updates
4. **Blacklist Monitoring**: Monitor security blacklist for blocked extensions

### Maintenance
1. **Regular Updates**: Keep extension metadata current
2. **Cleanup**: Remove unused extensions periodically
3. **Organization**: Maintain consistent author naming
4. **Performance**: Balance comprehensive lists with install speed

### Team Workflow
1. **Shared Standards**: Establish team conventions for configuration
2. **Role-Based Access**: Limit whitelist modification permissions
3. **Change Management**: Document all configuration changes
4. **Training**: Ensure team understands YAML format and security implications

---

## 📚 Related Documentation

- **[Main README](../README.md)** - Overview, quick start, and basic usage
- **[Quick Reference](QUICK_REFERENCE.md)** - At-a-glance commands and format reference
- **[Blacklist System](BLACKLIST_SYSTEM.md)** - Security architecture and blacklist management

## 🔗 Quick Links

- **[YAML File Structure](#yaml-file-structure)** - Basic format and required fields
- **[Configuration Strategies](#configuration-strategies)** - Install flag philosophy and author organization
- **[Team Configurations](#team-specific-configurations)** - Frontend, backend, and minimal examples
- **[Migration Guide](#migration-from-text-format)** - Converting from legacy text format
- **[Validation](#validation-and-testing)** - Testing and troubleshooting YAML configurations

This guide provides comprehensive YAML configuration management. For basic usage, see the [Main README](../README.md). For quick commands, see the [Quick Reference](QUICK_REFERENCE.md).