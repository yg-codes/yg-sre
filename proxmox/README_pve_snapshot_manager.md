# Proxmox Snapshot Management Script

A comprehensive **Python script** for managing Proxmox VE snapshots. This script provides both interactive and command-line interfaces for efficient snapshot operations, with advanced bulk capabilities and enhanced user experience.

## Scripts Overview

- **`pve_snapshot_manager.py`** - **Comprehensive snapshot management tool** with unified interface for all snapshot operations, advanced bulk capabilities, and enhanced user experience

## ✨ Features

### Unified Snapshot Management (`pve_snapshot_manager.py`) ⭐

#### **Comprehensive Snapshot Operations**
- **Create snapshots** with intelligent naming and vmstate options
- **Rollback to snapshots** with configuration comparison and safety checks
- **Delete snapshots** with individual or bulk deletion capabilities
- **List snapshots** with detailed information and timestamps
- **Multi-node cluster support** with automatic VM location detection

#### **Advanced VM Selection**
- **Multiple selection methods**:
  - **Ranges**: `7301-7305` (all VMs in range)
  - **Lists**: `7301,7303,7305` (specific VMs)
  - **Patterns**: `73*` (all VMs starting with 73)
  - **VM names**: Support for both VM IDs and VM names
  - **Keywords**: `running`, `stopped`, `all`
  - **Interactive**: Checkbox-style selection interface

#### **Bulk Snapshot Operations**
- **Bulk creation** - Create snapshots across multiple VMs concurrently
- **Bulk deletion** - Delete snapshots by patterns or selective cleanup
- **Bulk rollback** - Roll back multiple VMs to specified snapshots simultaneously
- **Bulk listing** - List snapshots across multiple VMs with detailed information
- **Progress tracking** - Real-time monitoring of bulk operations
- **Concurrent execution** - Multiple snapshot operations running simultaneously

#### **CLI Interface**

**Subcommands and Options:**
- **`create`** - Create VM snapshots
  - `--vmid <id>` | `--vmname <name>` (mutually exclusive, required)
  - `--prefix <prefix>` (default: "snapshot")
  - `--snapshot_name <name>` (full snapshot name, max 40 chars)
  - `--vmstate {0,1}` (0=no vmstate default, 1=with vmstate)
  - `--yes` (skip confirmation prompts)

- **`list`** - List VM snapshots (supports multiple VMs)
  - `--vmid <id> [<id> ...]` | `--vmname <name> [<name> ...]` (mutually exclusive, required)

- **`rollback`** - Rollback VM(s) to snapshot
  - `--vmid <id> [<id> ...]` | `--vmname <name> [<name> ...]` (mutually exclusive, required, supports multiple VMs)
  - `<snapshot_name>` (positional argument)
  - `--yes` (skip confirmation prompts)

- **`delete`** - Delete VM snapshot(s)
  - `--vmid <id> [<id> ...]` | `--vmname <name> [<name> ...]` (mutually exclusive, required, supports multiple VMs)
  - `--snapshot_name <name> [<name> ...]` (snapshot name(s) to delete, space-separated)
  - `--all` (delete all snapshots for specified VM(s))
  - `--yes` (skip confirmation prompts)

**Help System:**
```bash
./pve_snapshot_manager.py --help              # Main help
./pve_snapshot_manager.py create --help       # Create command help
./pve_snapshot_manager.py list --help         # List command help
./pve_snapshot_manager.py rollback --help     # Rollback command help
./pve_snapshot_manager.py delete --help       # Delete command help
```

#### **Enhanced User Experience**
- **VM name resolution** - Works with both VM IDs and VM names
- **Pattern matching** - Support for wildcards and partial names
- **Interactive selection** - Checkbox-style VM selection
- **Real-time monitoring** - Live status updates and progress tracking
- **Enhanced safety checks** - Multiple confirmation levels for destructive operations

## 🚀 Installation

### ⚠️ Prerequisites for Scripts

**IMPORTANT: Token Permissions Must Be Set BEFORE Using Scripts**

If you plan to use the scripts, you **MUST** configure proper permissions first, or the scripts will fail with "Permission check failed" errors.

```bash
# After creating your API token, IMMEDIATELY run this command:
pveum aclmod / -token 'your-username@pam!your-token-name' -role PVEVMAdmin

# Example:
pveum aclmod / -token 'admin@pam!vm-management' -role PVEVMAdmin
```

#### **Requirements**

**Option 1: Using uv (Modern Python Package Manager - Recommended)**
```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies using uv
uv sync

# Run scripts with uv
uv run ./pve_snapshot_manager.py
```

**Option 2: Using pip (Traditional Method)**
```bash
# Install required Python packages
pip install requests urllib3

# Or using virtual environment (recommended)
python3 -m venv proxmox-env
source proxmox-env/bin/activate
pip install requests urllib3
```

#### **Authentication Setup**

**Option 1: API Token (Recommended)**
1. **Create API Token in Proxmox Web UI:**
   - Go to Datacenter → Permissions → API Tokens
   - Click "Add" and create token for your user
   - Copy the token value (shown only once!)

2. **⚠️ CRITICAL: Grant Required Permissions (MUST DO FIRST):**
```bash
# This step is REQUIRED - the token won't work without proper permissions
pveum aclmod / -token 'your-username@pam!your-token-name' -role PVEVMAdmin

# Example with actual values:
pveum aclmod / -token 'admin@pam!vm-management' -role PVEVMAdmin
```

3. **Set Environment Variables:**
```bash
export PVE_HOST=your-proxmox-host.com
export PVE_USER=your-username@pam
export PVE_TOKEN_NAME=your-token-name
export PVE_TOKEN_VALUE=your-token-value
```

**Option 2: Password Authentication**
- Scripts will prompt for credentials if environment variables are not set
- Less secure but simpler for testing

#### **Installation Steps**
```bash
# 1. Transfer scripts to a workstation
scp pve_snapshot_manager.py root@proxmox-host:/root/

# 2. Make executable
chmod +x pve_snapshot_manager.py

# 3. Test connection
./pve_snapshot_manager.py --help
```

### System Requirements
- **Proxmox VE environment**
- **Python 3.6+** (Python 3.11.2+ recommended)
- **Python packages**: `requests` and `urllib3`
- **Access to VM management operations**

## 📖 Usage

### Unified Snapshot Management

#### **Interactive Mode - Complete Snapshot Management**
```bash
./pve_snapshot_manager.py
```

**Main Menu Options:**
- **View Available VMs** - Comprehensive list with status and snapshot counts
- **Manage Single VM** - Complete snapshot operations for individual VMs
- **Bulk Operations** - Multi-VM snapshot operations with advanced selection

#### **Command Line Mode**

##### Create Snapshot
```bash
# Single VM snapshots
./pve_snapshot_manager.py create --vmid 7301 --prefix daily-backup --yes
./pve_snapshot_manager.py create --vmname web-server --snapshot_name backup-20250101 --vmstate 1
./pve_snapshot_manager.py create --vmid 7304 --prefix pre-maintenance --vmstate 0

# Bulk create - create snapshots across multiple VMs
./pve_snapshot_manager.py create --vmid 7301 7302 7303 pre-maintenance-snapshot --yes
./pve_snapshot_manager.py create --vmname web-server database-server api-server --snapshot_name daily-backup-20250101
```
##### List Snapshot
```bash
# List snapshots (supports multiple VMs)
./pve_snapshot_manager.py list --vmid 7301
./pve_snapshot_manager.py list --vmname web-server database-server
./pve_snapshot_manager.py list --vmid 7301 7303 7304
```
##### Rollback Snapshot
```bash
# Rollback to snapshot
./pve_snapshot_manager.py rollback --vmid 7301 daily-backup-vm7301-20250109-1430 --yes

# Bulk rollback - rollback multiple VMs to the same snapshot
./pve_snapshot_manager.py rollback --vmid 7301 7302 7303 pre-maintenance-snapshot --yes
./pve_snapshot_manager.py rollback --vmname web-server database-server api-server --snapshot_name daily-backup-20250101
```

##### Delete Snapshot
```bash
# Delete snapshot
./pve_snapshot_manager.py delete --vmid 7301 test-snapshot-vm7301-20250109-1045 --yes
./pve_snapshot_manager.py delete --vmname web-server backup-20250101-1200
# Delete specific snapshots from multiple VMs
./pve_snapshot_manager.py delete --vmid 7301 7303 7304 --snapshot_name test-snapshot --yes
./pve_snapshot_manager.py delete --vmname web-server database-server --snapshot_name old-backup temp-backup

# Delete all snapshots from multiple VMs
./pve_snapshot_manager.py delete --vmid 7301 7303 7304 --all --yes
./pve_snapshot_manager.py delete --vmname web-server database-server api-server --all

# Delete multiple specific snapshots from multiple VMs
./pve_snapshot_manager.py delete --vmid 7301 7303 --snapshot_name backup1 backup2 test-snap --yes
./pve_snapshot_manager.py delete --vmname web-server database-server --snapshot_name daily-old weekly-old monthly-old

# Bulk delete - delete specific snapshots from multiple VMs
./pve_snapshot_manager.py delete --vmid 7301 7302 7303 --snapshot_name test-snapshot old-backup --yes
./pve_snapshot_manager.py delete --vmname web-server database-server --snapshot_name temp-backup dev-snapshot

# Bulk delete all - delete all snapshots from multiple VMs
./pve_snapshot_manager.py delete --vmid 7301 7302 7303 --all --yes
./pve_snapshot_manager.py delete --vmname web-server database-server api-server --all

```

## ⚙️ Configuration

### API Scripts Configuration

#### **Environment Variables**
```bash
# Required for token authentication
export PVE_HOST=proxmox.company.com       # Proxmox host/IP
export PVE_USER=snapshot@pve              # Username@realm
export PVE_TOKEN_NAME=automation          # Token name
export PVE_TOKEN_VALUE=abc123...          # Token value

# Optional: Create .env file
cat > ~/.proxmox-env << EOF
export PVE_HOST=proxmox.company.com
export PVE_USER=snapshot@pve
export PVE_TOKEN_NAME=automation
export PVE_TOKEN_VALUE=your-token-here
EOF

# Load environment
source ~/.proxmox-env
```

#### **Token Permissions**
Minimum required roles for the API token:
- **PVEVMAdmin** - Full VM management (recommended for all operations)

```bash
# Grant permissions for all operations (VM management, snapshots, backups)
pveum aclmod / -token 'username@pam!token-name' -role PVEVMAdmin
```

#### **Bulk Operations Configuration**
```bash
# Concurrent operation limits (can be adjusted in scripts)
MAX_CONCURRENT_SNAPSHOTS=2     # Snapshot operations
```

### General Configuration

#### **Prefix Length Limits**
- **Maximum prefix length**: 20 characters
- **Automatic validation** and cleanup of invalid characters
- This ensures space for VM names and timestamps within Proxmox's 40-character limit

#### **VM State Configuration**
- **Automatic detection** of VM running status
- **Smart handling** - vmstate option ignored for stopped VMs
- **Clear warnings** about performance implications
- **Description integration** for easy identification of vmstate snapshots

## 🛡️ Enhanced Safety Features

### Snapshot Manager Safety Features
- **Real-time task monitoring** prevents silent failures
- **Multi-node validation** ensures VMs exist on selected nodes
- **Enhanced error messages** with specific API error codes
- **Permission validation** before attempting operations
- **Configuration comparison** (rollback) to show exactly what will change
- **VM state detection** with appropriate warnings for vmstate snapshots
- **Post-operation verification** to ensure operations completed successfully
- **Different confirmation levels** for single vs. bulk operations

### Common Safety Features
- **VM state warnings** with comprehensive information about performance implications
- **Automatic VM status detection** prevents vmstate errors on stopped VMs
- **Multi-level confirmation prompts** for all operations
- **Graceful interruption** handling (Ctrl+C)
- **Input sanitization** removes invalid characters from prefixes
- **Consistent behavior** across both scripts for vmstate handling

## 📋 Examples

### Snapshot Manager Examples

#### **Interactive Snapshot Management**
```bash
# Start the snapshot manager
./pve_snapshot_manager.py

# Example workflow:
# 1. View Available VMs (option 1)
# 2. Manage Single VM (option 2) - enter VM ID like 7301
#    - Create snapshots with custom prefixes
#    - Rollback to previous snapshots
#    - Delete individual or multiple snapshots
# 3. Bulk Operations (option 3)
#    - Bulk create snapshots across multiple VMs
#    - Bulk delete snapshots by pattern
```
#### **Command Line Mode**

##### Create Snapshot
```bash
# Create snapshot with prefix
./pve_snapshot_manager.py create --vmid 7301 --prefix daily-backup --yes

# Create snapshot with full name and vmstate
./pve_snapshot_manager.py create --vmname web-server --snapshot_name backup-20250101 --vmstate 1

# Create snapshot with prefix and no vmstate
./pve_snapshot_manager.py create --vmid 7304 --prefix pre-maintenance --vmstate 0

# Bulk create - create multiple VMs to the same snapshot
./pve_snapshot_manager.py create --vmid 7301 7302 7303 pre-maintenance-snapshot --yes
./pve_snapshot_manager.py create --vmname web-server database-server api-server --snapshot_name daily-backup-20250101
```
##### List Snapshot
```bash
# List snapshots (supports multiple VMs)
./pve_snapshot_manager.py list --vmid 7301
./pve_snapshot_manager.py list --vmname web-server database-server
./pve_snapshot_manager.py list --vmid 7301 7303 7304
```
##### Rollback Snapshot
```bash
# Rollback to snapshot
./pve_snapshot_manager.py rollback --vmid 7301 daily-backup-vm7301-20250109-1430 --yes

# Bulk rollback - rollback multiple VMs to the same snapshot
./pve_snapshot_manager.py rollback --vmid 7301 7302 7303 pre-maintenance-snapshot --yes
./pve_snapshot_manager.py rollback --vmname web-server database-server api-server --snapshot_name daily-backup-20250101
```

##### Delete Snapshot
```bash
# Delete snapshot
./pve_snapshot_manager.py delete --vmid 7301 test-snapshot-vm7301-20250109-1045 --yes
./pve_snapshot_manager.py delete --vmname web-server backup-20250101-1200
# Delete specific snapshots from multiple VMs
./pve_snapshot_manager.py delete --vmid 7301 7303 7304 --snapshot_name test-snapshot --yes
./pve_snapshot_manager.py delete --vmname web-server database-server --snapshot_name old-backup temp-backup

# Delete all snapshots from multiple VMs
./pve_snapshot_manager.py delete --vmid 7301 7303 7304 --all --yes
./pve_snapshot_manager.py delete --vmname web-server database-server api-server --all

# Delete multiple specific snapshots from multiple VMs
./pve_snapshot_manager.py delete --vmid 7301 7303 --snapshot_name backup1 backup2 test-snap --yes
./pve_snapshot_manager.py delete --vmname web-server database-server --snapshot_name daily-old weekly-old monthly-old

# Bulk delete - delete specific snapshots from multiple VMs
./pve_snapshot_manager.py delete --vmid 7301 7302 7303 --snapshot_name test-snapshot old-backup --yes
./pve_snapshot_manager.py delete --vmname web-server database-server --snapshot_name temp-backup dev-snapshot

# Bulk delete all - delete all snapshots from multiple VMs
./pve_snapshot_manager.py delete --vmid 7301 7302 7303 --all --yes
./pve_snapshot_manager.py delete --vmname web-server database-server api-server --all

```

## 🛠️ Troubleshooting

### Common Issues

**"API request failed: 403 Permission check failed" - MOST COMMON ISSUE**
- **ROOT CAUSE:** Token permissions not properly configured
- **SOLUTION:** Run the permission command immediately after creating your token:
```bash
# Replace with your actual username and token name
pveum aclmod / -token 'your-username@pam!your-token-name' -role PVEVMAdmin

# Examples:
pveum aclmod / -token 'admin@pam!vm-management' -role PVEVMAdmin
pveum aclmod / -token 'automation@pve!snapshots' -role PVEVMAdmin
```

**"No VMs found on selected nodes"**
- Check API permissions for VM listing
- Verify VMs exist on selected nodes
- Run debug mode if available

**"Task failed" (for any operation)**
- Check VM status matches operation requirements
- Verify sufficient disk space on nodes
- Check for locked VMs or ongoing operations

**"Cannot connect to API"**
- Verify PVE_HOST environment variable
- Check network connectivity to Proxmox host
- Verify API service is running (port 8006)

**"externally-managed-environment error"**
- **With uv**: `uv sync && uv run ./script_name.py` (recommended)
- **With pip**: Use virtual environment: `python3 -m venv proxmox-env && source proxmox-env/bin/activate`
- Or install system packages: `sudo apt install python3-requests`

### Best Practices

**Authentication security:**
- Use API tokens instead of passwords for automation
- Set appropriate token permissions (principle of least privilege)
- Store credentials in environment variables, not in scripts

**Performance optimization:**
- Use vmstate only when necessary (exact point-in-time recovery)
- Consider network and storage impact for large VMs
- Schedule bulk operations during maintenance windows
- Adjust concurrent operation limits based on hardware capabilities

**Operation safety:**
- Always review configurations before destructive operations
- Use bulk operations carefully with appropriate confirmations
- Test operations in non-production environments first
- Create snapshots before major changes
- Monitor bulk operation progress and results

**Maintenance best practices:**
- Regularly clean up old snapshots and backups to save storage
- Document snapshot naming conventions
- Use consistent prefixes for easy identification
- Monitor storage space usage
- Set up automated cleanup for old backups
