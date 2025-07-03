# Proxmox VM Management Script

A comprehensive **Python script** for managing Proxmox VE environments. This script provides an interactive menu for efficient VM management, including start/stop operations, backup creation/restoration, snapshot management, and powerful bulk operations with enhanced error handling and user experience.

## 🚀 Quick Start

For the most comprehensive experience, start with the unified VM management script:

```bash
# Set up API authentication
export PVE_HOST=your-proxmox-host.com
export PVE_USER=your-username@pam
export PVE_TOKEN_NAME=your-token-name
export PVE_TOKEN_VALUE=your-token-value

# Grant permissions
pveum aclmod / -token 'your-username@pam!your-token-name' -role PVEVMAdmin

# Run the unified manager
./pve_vm_manager_api.py
```

### What You Can Do:
- **📋 View all VMs** with real-time status across your cluster
- **🔧 Manage individual VMs** - start, stop, backup, restore, snapshot operations
- **⚡ Bulk operations** - start/stop/backup/snapshot multiple VMs concurrently
- **🎯 Quick actions** - start all stopped VMs, backup all VMs, etc.
- **🔍 Smart VM selection** - ranges, patterns, interactive selection
- **📊 Real-time monitoring** - task progress, resource usage, status updates

## ✨ Features

### Unified VM Management (`pve_vm_manager_api.py`) ⭐

#### **Comprehensive VM Operations**
- **Start/Stop VMs** with safety checks and confirmation prompts
- **Real-time VM monitoring** with CPU/RAM usage and status indicators
- **Protection mode handling** - Automatic detection and safe removal when needed
- **Multi-node cluster support** with automatic VM location detection

#### **Advanced Backup Management**
- **Create VM backups** with multiple modes (snapshot, suspend, stop)
- **Storage selection** with space availability checking
- **Backup restoration** with configuration comparison and target storage selection
- **Backup deletion** with safety confirmations and space reclamation tracking
- **Backup verification** with size and creation date information

#### **Enhanced Snapshot Operations**
- **Complete snapshot lifecycle** - create, rollback, delete with full safety checks
- **Bulk snapshot operations** - Create or delete snapshots across multiple VMs
- **Pattern-based deletion** - Delete snapshots by name patterns
- **Configuration comparison** - See exactly what will change during rollbacks
- **VM state handling** - Smart vmstate detection and warnings

#### **Powerful Bulk Operations**
- **Concurrent execution** - Multiple operations running simultaneously with progress tracking
- **Smart VM selection** with multiple methods:
  - **Ranges**: `7201-7205` (all VMs in range)
  - **Lists**: `7201,7203,7205` (specific VMs)
  - **Patterns**: `72*` (all VMs starting with 72)
  - **Keywords**: `running`, `stopped`, `all`
  - **Interactive**: Checkbox-style selection interface
- **Bulk operations available**:
  - **Start/Stop VMs** - Concurrent VM state changes
  - **Create backups** - Multiple VM backups with storage and mode selection
  - **Create snapshots** - Bulk snapshot creation with custom prefixes
  - **Delete snapshots** - Pattern-based or selective snapshot cleanup

#### **Quick Actions**
- **Quick Start All** - Start all stopped VMs with one command
- **Quick Stop All** - Emergency stop for all running VMs
- **Quick Backup All** - Backup entire environment to selected storage

#### **User Experience Features**
- **Interactive menus** with comprehensive help and guidance
- **Real-time progress tracking** for all operations
- **Enhanced error handling** with recovery suggestions
- **Safety confirmations** appropriate to operation risk level
- **Status indicators** with emoji icons for quick visual feedback
- **Resource monitoring** showing disk space, VM resources, and cluster health

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
uv run ./pve_vm_manager_api.py
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
# 1. Transfer scripts to Proxmox host
scp pve_vm_manager_api.py root@proxmox-host:/root/

# 2. Make executable
chmod +x pve_vm_manager_api.py

# 3. Test connection
./pve_vm_manager_api.py --help
```

### System Requirements
- **Proxmox VE environment**
- **Python 3.6+** (Python 3.11.2+ recommended)
- **Python packages**: `requests` and `urllib3`
- **Access to VM management operations**

## 📖 Usage

### Unified VM Management (Recommended)

#### **Interactive Mode - Complete VM Management**
```bash
./pve_vm_manager_api.py
```

**Main Menu Options:**
- **View Available VMs** - Comprehensive list with status and snapshot counts
- **Manage Single VM** - Complete operations menu for individual VMs
- **Bulk Operations** - Multi-VM operations with progress tracking
- **Quick Actions** - Start all stopped, stop all running, backup all VMs

#### **Single VM Management**
```bash
# Direct VM management (enter VM ID at main menu)
./pve_vm_manager_api.py
# Then enter VM ID: 7201
```

**Per-VM Operations:**
- **Start/Stop VM** with status verification
- **Create/Restore Backups** with storage selection
- **Create/Rollback/Delete Snapshots** with safety checks
- **View detailed VM information** with resource usage

#### **Bulk Operations Examples**

**Bulk VM Selection Methods:**
```bash
# Range selection
VMs to manage: 7201-7205

# Specific VMs
VMs to manage: 7201,7203,7205

# Pattern matching
VMs to manage: 72*

# Keywords
VMs to manage: running    # All running VMs
VMs to manage: stopped    # All stopped VMs
VMs to manage: all        # All VMs

# Interactive selection
VMs to manage: i          # Checkbox-style selection
```

**Bulk Operations Available:**
- **Bulk Start VMs** - Start multiple VMs concurrently
- **Bulk Stop VMs** - Stop multiple VMs with confirmation
- **Bulk Create Backups** - Backup multiple VMs to selected storage
- **Bulk Create Snapshots** - Snapshot multiple VMs with custom prefix
- **Bulk Delete Snapshots** - Pattern-based or selective cleanup

#### **Quick Actions**
```bash
# Start all stopped VMs at once
Select option: 4

# Emergency stop all running VMs
Select option: 5

# Backup all VMs to selected storage
Select option: 6
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
MAX_CONCURRENT_START_STOP=3    # VM start/stop operations
MAX_CONCURRENT_BACKUPS=2       # Backup operations
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

### Unified VM Manager Safety Features
- **Operation-appropriate confirmations** - Simple "y/N" for low-risk, "yes" for medium-risk, "DELETE ALL" for high-risk operations
- **Protection mode detection** - Automatic handling of VM protection settings
- **Concurrent operation limits** - Prevents system overload during bulk operations
- **Real-time progress monitoring** - Shows operation status and catches failures early
- **Pre-operation validation** - Checks VM state, storage availability, and permissions
- **Post-operation verification** - Confirms operations completed successfully
- **Smart error recovery** - Provides specific guidance for common issues
- **Resource monitoring** - Shows available storage space and VM resource usage

### Common Safety Features
- **VM state warnings** with comprehensive information about performance implications
- **Automatic VM status detection** prevents vmstate errors on stopped VMs
- **Multi-level confirmation prompts** for all operations
- **Graceful interruption** handling (Ctrl+C)
- **Input sanitization** removes invalid characters from prefixes
- **Consistent behavior** across both scripts for vmstate handling

## 🔧 Architecture & Code Quality

### **Inheritance Structure**
```
ProxmoxAPI
├── Low-level API communication
├── Authentication handling
├── Request/response management
└── Error handling

ProxmoxSnapshotManager
├── Core API functionality (25+ methods)
├── Configurable vmstate keywords
├── Enhanced error handling
├── Multi-node cluster support
├── Real-time task monitoring
└── Base methods for all operations

ProxmoxVMManager (extends ProxmoxSnapshotManager)
├── Inherits all snapshot functionality ⭐
├── VM lifecycle management
├── Backup operations
├── Bulk operations with concurrency
├── Advanced UI/UX features
└── Complete VM administration ⭐
```

## 📋 Examples

### VM Manager Examples

#### **Complete VM Environment Management**
```bash
# Start the unified manager
./pve_vm_manager_api.py

# Example workflow:
# 1. View all VMs and their current status
# 2. Start all stopped VMs for the day
# 3. Create daily snapshots for all production VMs
# 4. Create backups for critical VMs
# 5. Monitor operations with real-time progress
```

#### **Bulk Operations Workflow**
```bash
# In VM Manager main menu:
# Select option 3: Bulk Operations

# Bulk snapshot example:
# Select: 5. Bulk Create Snapshots
# VM selection: 7200-7299  (all VMs in range)
# Prefix: daily-backup
# Include RAM: Yes
# Confirmation: y
# Result: 15 VMs processed, 14 successful, 1 failed

# Bulk backup example:
# Select: 4. Bulk Create Backups
# VM selection: running  (all running VMs)
# Storage: Select from available list
# Mode: snapshot (fastest)
# Confirmation: y
# Result: Concurrent backups with progress tracking
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

### VM Manager Issues

**"No VMs found"**
- Check API permissions: `pveum aclmod / -token 'user@realm!token' -role PVEVMAdmin`
- Verify network connectivity to Proxmox nodes
- Check if VMs are on different nodes than expected

**"Bulk operation failed for some VMs"**
- Review the detailed failure summary displayed after bulk operations
- Check individual VM status and error messages
- Common causes: VM already in target state, insufficient resources, locked VMs

**"Cannot access storage"**
- Verify storage is online and accessible from current node
- Check storage permissions and content type settings
- Try different node if storage is shared

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
