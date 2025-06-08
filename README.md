# Proxmox VM Management & Snapshot Scripts

A comprehensive collection of **Python scripts** for managing Proxmox VE environments. These scripts provide both interactive and command-line interfaces for efficient VM management, snapshot operations, backup management, and bulk operations with enhanced error handling and user experience.

## Scripts Overview

### Unified VM Management Script (New!)
- **`pve_vm_manager_api.py`** - **Complete VM management solution** with interactive menus for start/stop operations, backup creation/restoration, snapshot management, and powerful bulk operations

### CLI-Based Snapshot Scripts (Original)
- **`pve_snapshot_create_cli.py`** - Create VM snapshots using qm commands with configurable prefixes and optional VM state saving
- **`pve_snapshot_delete_cli.py`** - Delete VM snapshots with safety confirmations
- **`pve_snapshot_rollback_cli.py`** - Rollback VMs to specific snapshots with comprehensive safety checks

### API-Based Snapshot Scripts (Enhanced)
- **`pve_snapshot_create_api.py`** - API-based snapshot creation with multi-node cluster support, real-time monitoring, and enhanced permissions
- **`pve_snapshot_rollback_api.py`** - API-based snapshot rollback with comprehensive safety checks, configuration comparison, and real-time task monitoring
- **`pve_snapshot_delete_api.py`** - API-based snapshot deletion with bulk operations, task monitoring, and enhanced safety features
- **`pve_snapshot_delete_interactive.py`** - Interactive snapshot deletion and management interface for viewing and deleting snapshots across VMs

## 🚀 Quick Start - Unified VM Manager

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

## 🔄 Recent Improvements (v2.5)

### **NEW: Interactive Snapshot Deletion & Enhanced UI (v2.5)**
- **✅ Interactive snapshot deletion tool** - Focused tool for snapshot viewing and deletion operations across VMs
- **✅ Enhanced display formatting** - Wider tables (135 chars) with expanded name columns (50 chars) for better readability
- **✅ Independent API implementations** - All API scripts now self-contained with complete Proxmox API classes
- **✅ Improved user experience** - Better snapshot name visibility and cleaner interface layouts
- **✅ Standalone script architecture** - Each script includes full API functionality for independent operation

### **Unified VM Management Script (v2.4)**
- **✅ Complete VM lifecycle management** - All operations in one interactive tool
- **✅ Bulk operations with concurrency** - Start/stop/backup/snapshot multiple VMs simultaneously
- **✅ Advanced VM selection** - Ranges (7201-7205), patterns (72*), interactive selection
- **✅ Backup management** - Create backups, restore from backups, delete old backups
- **✅ Enhanced snapshot operations** - Full lifecycle management with bulk operations
- **✅ Real-time monitoring** - Progress tracking for all operations
- **✅ Smart error handling** - Comprehensive error recovery and user guidance
- **✅ Protection handling** - Automatic detection and handling of VM protection mode

### **CLI Scripts Enhancement - Unified User Experience (v2.3)**
- **✅ Enhanced pve_snapshot_delete_cli.py** to match display patterns from create and rollback scripts
- **✅ Unified snapshot display** - Single formatted table with integrated selection numbers
- **✅ Consistent VM listing** with emoji status indicators (🟢 running 🔴 stopped)
- **✅ Improved snapshot tables** sorted by date (newest first) with type indicators
- **✅ Enhanced user flow** - "q" from snapshot selection now exits completely
- **✅ Eliminated duplicate displays** - No more redundant snapshot listings

### **Complete API Migration Achieved! (v2.2)**
- **✅ All three scripts now available in API version** - create, rollback, and delete
- **✅ Consistent architecture** across all API scripts with shared base classes
- **✅ Unified user experience** - same authentication, monitoring, and error handling
- **✅ Feature parity plus enhancements** - all CLI features preserved and improved

## ✨ Features

### Unified VM Management (`pve_vm_manager_api.py`) ⭐ **NEW**

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

### API-Based Snapshot Scripts

#### **Interactive Snapshot Deletion (`pve_snapshot_delete_interactive.py`)** ⭐ **Updated**
- **Focused interface** for snapshot deletion and viewing operations across VMs
- **Enhanced display formatting** with wider tables (135 characters) and expanded name columns (50 characters)
- **Improved user experience** with better snapshot name visibility and deletion management
- **Comprehensive deletion capabilities** with bulk operations and safety confirmations
- **Standalone implementation** with independent API classes for reliable operation

#### **Snapshot Creation (`pve_snapshot_create_api.py`)**
- **Native Proxmox REST API** integration for better performance and reliability
- **Multi-node cluster support** with interactive node selection and enhanced debugging
- **Real-time task monitoring** with progress tracking during snapshot creation
- **Enhanced authentication** supporting both API tokens and password authentication
- **Environment variable configuration** for automation and security
- **Comprehensive debugging** with detailed API access analysis and permission validation
- **Enhanced error handling** with structured API responses
- **Live VM resource monitoring** showing CPU/RAM usage during operations
- **Enhanced VM list display** with snapshot counts matching other scripts
- **Improved interactive experience** with better VM status indicators
- **Configurable vmstate detection** with unified keyword management

#### **Snapshot Rollback (`pve_snapshot_rollback_api.py`)**
- **Native Proxmox REST API** integration for reliable rollback operations
- **Multi-node cluster support** with automatic VM node detection
- **Real-time task monitoring** with progress tracking during rollback operations
- **Comprehensive safety checks** with multiple confirmation levels
- **Configuration comparison** between current VM state and snapshot state
- **VM state detection and warnings** for snapshots with/without vmstate
- **Enhanced snapshot listing** sorted by creation date (newest first)
- **Automatic VM startup handling** with intelligent prompts
- **Multiple operation modes** (interactive, VM-specific, direct rollback)
- **Enhanced authentication** supporting both API tokens and password authentication
- **Post-rollback verification** with VM status monitoring

#### **Snapshot Deletion (`pve_snapshot_delete_api.py`)**
- **Native Proxmox REST API** integration for reliable deletion operations
- **Multi-node cluster support** with automatic VM node detection
- **Real-time task monitoring** with progress tracking during deletion
- **Bulk deletion capability** with enhanced safety confirmations
- **Configuration display** showing snapshot details before deletion
- **VM status verification** before and after deletion operations
- **Enhanced snapshot listing** sorted by creation date (newest first)
- **Multiple operation modes** (interactive, VM-specific, direct deletion)
- **Consistent authentication** matching other API scripts
- **Post-deletion verification** ensuring snapshot removal

### CLI-Based Scripts (Enhanced - Still Available)
All original CLI-based scripts remain available for environments where API access is not suitable or where minimal dependencies are preferred. Recent enhancements include:
- **Unified display formatting** across all three CLI scripts
- **Enhanced VM listing** with emoji status indicators (🟢 running 🔴 stopped)
- **Improved snapshot display** with formatted tables, sorted by date (newest first)
- **VM state type indicators** (🧠 with vmstate / 💾 disk only)
- **Consistent user experience** matching API script interfaces
- Direct qm command execution
- Interactive and command-line modes
- VM state (vmstate) support
- Bulk operations
- Safety confirmations
- No external dependencies

## 🚀 Installation

### ⚠️ Prerequisites for API Scripts

**IMPORTANT: Token Permissions Must Be Set BEFORE Using API Scripts**

If you plan to use the API-based scripts, you **MUST** configure proper permissions first, or the scripts will fail with "Permission check failed" errors.

```bash
# After creating your API token, IMMEDIATELY run this command:
pveum aclmod / -token 'your-username@pam!your-token-name' -role PVEVMAdmin

# Example:
pveum aclmod / -token 'admin@pam!snapshots' -role PVEVMAdmin
```

### API-Based Scripts (Recommended for New Deployments)

#### **Requirements**
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
pveum aclmod / -token 'admin@pam!snapshots' -role PVEVMAdmin
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
# 1. Transfer all API scripts to Proxmox host
scp pve_vm_manager_api.py root@proxmox-host:/root/
scp pve_snapshot_*_api.py root@proxmox-host:/root/
scp pve_snapshots/pve_snapshot_delete_interactive.py root@proxmox-host:/root/

# 2. Make executable
chmod +x pve_vm_manager_api.py
chmod +x pve_snapshot_create_api.py
chmod +x pve_snapshot_rollback_api.py
chmod +x pve_snapshot_delete_api.py
chmod +x pve_snapshot_delete_interactive.py

# 3. Test connection
./pve_vm_manager_api.py --help
./pve_snapshot_create_api.py --help
```

### CLI-Based Scripts (Original Method)

1. **Transfer the Python scripts** to your Proxmox host using SCP/SFTP

2. **Make them executable**:
```bash
chmod +x pve_snapshot_create_cli.py
chmod +x pve_snapshot_delete_cli.py
chmod +x pve_snapshot_rollback_cli.py
```

3. **Create a convenient `python` command** (if not already available):
```bash
# Create symbolic link (recommended)
sudo ln -s /usr/bin/python3 /usr/local/bin/python
```

4. **Verify installation**:
```bash
python3 --version  # Should show Python 3.11.2 or higher
python --version   # Should now also show Python 3.x
```

### System Requirements
- **Proxmox VE environment**
- **Python 3.6+** (Python 3.11.2+ recommended)
- **For API scripts**: `requests` and `urllib3` Python packages
- **For CLI scripts**: Appropriate permissions to execute `qm` commands
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

### API-Based Snapshot Scripts

#### **Interactive Snapshot Deletion (Delete Operations Only)**
```bash
# Interactive snapshot deletion and management interface
./pve_snapshot_delete_interactive.py

# Features:
# - View all snapshots across VMs in a comprehensive table
# - Delete individual snapshots with safety confirmations
# - Bulk deletion operations per VM
# - Enhanced display formatting with wider tables
```

#### **Snapshot Creation**
```bash
# Interactive mode with enhanced features
./pve_snapshot_create_api.py

# Command line mode
./pve_snapshot_create_api.py maintenance 7201 7203 7204
./pve_snapshot_create_api.py pre-release
```

#### **Snapshot Rollback**
```bash
# Interactive mode
./pve_snapshot_rollback_api.py

# VM-specific mode
./pve_snapshot_rollback_api.py 7201

# Direct rollback
./pve_snapshot_rollback_api.py 7201 pre-release-storage01-20250603-1430
```

#### **Snapshot Deletion**
```bash
# Interactive mode
./pve_snapshot_delete_api.py

# VM-specific mode
./pve_snapshot_delete_api.py 7201

# Direct deletion
./pve_snapshot_delete_api.py 7201 pre-release-storage01-20250603-1430
```

### CLI-Based Scripts (Enhanced Method)

All CLI scripts remain available with significant UI/UX improvements. See previous documentation for detailed CLI usage examples.

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
- **PVEVMUser** - Basic VM operations
- **PVEVMAdmin** - Full VM management (recommended for all operations)
- **Sys.Audit** - Optional, for enhanced node information

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
- **Maximum prefix length**: 25 characters
- **Automatic validation** and cleanup of invalid characters
- This ensures space for VM names and timestamps within Proxmox's 40-character limit

#### **VM State Configuration**
- **Automatic detection** of VM running status
- **Smart handling** - vmstate option ignored for stopped VMs
- **Clear warnings** about performance implications
- **Description integration** for easy identification of vmstate snapshots
- **Unified detection logic** across all API scripts

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

### API Scripts Safety Features
- **Real-time task monitoring** prevents silent failures
- **Multi-node validation** ensures VMs exist on selected nodes
- **Enhanced error messages** with specific API error codes
- **Permission validation** before attempting operations
- **Structured debugging** for troubleshooting access issues
- **Configuration comparison** (rollback script) to show exactly what will change
- **Configuration display** (delete script) to verify what will be removed
- **VM state detection** with appropriate warnings for vmstate snapshots
- **Post-operation verification** to ensure operations completed successfully
- **Unified vmstate detection** prevents inconsistencies between scripts
- **Different confirmation levels** for single vs. bulk operations

### CLI Scripts Safety Features
- **Enhanced length validation** prevents snapshot names exceeding 40 characters
- **Intelligent truncation** preserves meaningful parts of VM names
- **Preview confirmation** shows exactly what will be created
- **Comprehensive error handling** for invalid VMs or failed operations

### Common Safety Features (All Scripts)
- **VM state warnings** with comprehensive information about performance implications
- **Automatic VM status detection** prevents vmstate errors on stopped VMs
- **Multi-level confirmation prompts** for all operations
- **Graceful interruption** handling (Ctrl+C)
- **Input sanitization** removes invalid characters from prefixes
- **Consistent behavior** across all scripts for vmstate handling

## 🎯 Script Comparison

| Feature | CLI Scripts | API Scripts | VM Manager |
|---------|-------------|-------------|------------|
| **Performance** | Subprocess overhead | Direct API calls ⭐ | Direct API calls ⭐ |
| **User Interface** | Command line only | Command line only | Interactive menus ⭐ |
| **Bulk Operations** | Basic | Enhanced | Advanced with concurrency ⭐ |
| **VM Management** | Snapshots only | Snapshots only | Complete lifecycle ⭐ |
| **Backup Management** | None | None | Full backup lifecycle ⭐ |
| **Error Handling** | Text parsing | Structured responses ⭐ | Enhanced with guidance ⭐ |
| **Cluster Support** | Single node | Multi-node selection ⭐ | Multi-node selection ⭐ |
| **Real-time Monitoring** | Basic | Task progress tracking ⭐ | Enhanced progress tracking ⭐ |
| **Authentication** | Local permissions | API tokens + passwords ⭐ | API tokens + passwords ⭐ |
| **Resource Monitoring** | Limited | Live CPU/RAM stats ⭐ | Enhanced resource display ⭐ |
| **VM Selection** | Manual IDs | Manual IDs | Advanced selection methods ⭐ |
| **Safety Features** | Basic confirmations | Enhanced safety checks ⭐ | Operation-appropriate safety ⭐ |
| **Dependencies** | None | requests library | requests library |

**Recommendation:** Use `pve_vm_manager_api.py` for comprehensive VM management, API snapshot scripts for automation, CLI scripts for minimal dependency environments.

## 🔧 Architecture & Code Quality

### **Inheritance Structure (API Scripts)**
```
ProxmoxAPI (pve_vm_manager_api.py)
├── Low-level API communication
├── Authentication handling
├── Request/response management
└── Error handling

ProxmoxSnapshotManager (pve_vm_manager_api.py)
├── Core API functionality (25+ methods)
├── Configurable vmstate keywords
├── Enhanced error handling
├── Multi-node cluster support
├── Real-time task monitoring
└── Base methods for all operations

ProxmoxVMManager (pve_vm_manager_api.py)
├── Inherits all snapshot functionality ⭐
├── VM lifecycle management
├── Backup operations
├── Bulk operations with concurrency
├── Advanced UI/UX features
└── Complete VM administration ⭐

ProxmoxSnapshotRollback (pve_snapshot_rollback_api.py)
├── Inherits all parent functionality ⭐
├── Rollback-specific methods
├── Configuration comparison
└── Enhanced safety checks

ProxmoxSnapshotDeleter (pve_snapshot_delete_api.py)
├── Inherits all parent functionality ⭐
├── Deletion-specific methods
├── Bulk deletion support
└── Enhanced confirmations
```

### **Code Quality Improvements**
- **✅ Complete VM management ecosystem** - All operations available in unified interface
- **✅ Eliminated duplication** - Single source of truth for shared functionality
- **✅ Improved maintainability** - Changes to parent class automatically benefit all scripts
- **✅ Consistent behavior** - All scripts use identical core logic
- **✅ Better architecture** - Clean separation between core and specialized functionality
- **✅ Enhanced reliability** - Shared code is thoroughly tested and proven

## 📋 Examples

### Unified VM Manager Examples

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
# Select: 4. Bulk Create Snapshots
# VM selection: 7200-7299  (all VMs in range)
# Prefix: daily-backup
# Include RAM: Yes
# Confirmation: y
# Result: 15 VMs processed, 14 successful, 1 failed

# Bulk backup example:
# Select: 3. Bulk Create Backups
# VM selection: running  (all running VMs)
# Storage: Select from available list
# Mode: snapshot (fastest)
# Confirmation: y
# Result: Concurrent backups with progress tracking
```

#### **Emergency Operations**
```bash
# Quick stop all VMs (emergency maintenance)
./pve_vm_manager_api.py
# Select option 5: Quick Stop All Running VMs
# Confirmation: yes
# Result: All VMs stopped safely

# Quick start after maintenance
./pve_vm_manager_api.py
# Select option 4: Quick Start All Stopped VMs
# Confirmation: y
# Result: All VMs started with concurrent execution
```

### API Scripts Examples

#### **Automated Operations with Enhanced Features**
```bash
# Set authentication once
export PVE_HOST=cluster.company.com
export PVE_USER=admin@pam
export PVE_TOKEN_NAME=snapshots
export PVE_TOKEN_VALUE=your-token

# 1. Create snapshots before maintenance
./pve_snapshot_create_api.py pre-maintenance 7201 7203 7204
# Monitor real-time progress
# Review vmstate options

# 2. Perform maintenance work...

# 3. If issues arise, rollback with safety checks
./pve_snapshot_rollback_api.py 7201
# Review configuration differences
# Confirm rollback with warnings
# Monitor rollback progress

# 4. Clean up old snapshots after successful maintenance
./pve_snapshot_delete_api.py 7201
# View sorted snapshots
# Delete specific or all snapshots
# Monitor deletion progress
```

### CLI Scripts Examples

All CLI script examples remain valid. See previous documentation for detailed CLI usage examples.

## 🛠️ Troubleshooting

### VM Manager Issues

**"No VMs found"**
- Check API permissions: `pveum aclmod / -token 'user@realm!token' -role PVEVMAdmin`
- Verify network connectivity to Proxmox nodes
- Check if VMs are on different nodes than expected

**"Bulk operation failed for some VMs"**
- Review the detailed failure summary displayed after bulk operations
- Check individual VM status and error messages
- Common causes: VM already in target state, insufficient resources, locked VMs

**"Backup restoration failed"**
- Ensure target storage has sufficient space
- Check VM protection mode (script will help disable if needed)
- Verify backup file integrity and permissions

**"Cannot access storage"**
- Verify storage is online and accessible from current node
- Check storage permissions and content type settings
- Try different node if storage is shared

### API Scripts Issues

**"API request failed: 403 Permission check failed" - MOST COMMON ISSUE**
- **ROOT CAUSE:** Token permissions not properly configured
- **SOLUTION:** Run the permission command immediately after creating your token:
```bash
# Replace with your actual username and token name
pveum aclmod / -token 'your-username@pam!your-token-name' -role PVEVMAdmin

# Examples:
pveum aclmod / -token 'admin@pam!snapshots' -role PVEVMAdmin
pveum aclmod / -token 'automation@pve!vm-management' -role PVEVMAdmin
```

**"No VMs found on selected nodes"**
- Run debug mode: Answer 'y' to "Run API debug analysis?"
- Check API permissions for VM listing
- Verify VMs exist on selected nodes

**"Task failed" (for any operation)**
- Check VM status matches operation requirements
- Verify sufficient disk space on nodes
- Review task logs in Proxmox web interface
- Check for locked VMs or ongoing operations

**"Cannot connect to API"**
- Verify PVE_HOST environment variable
- Check network connectivity to Proxmox host
- Verify API service is running (port 8006)

**"externally-managed-environment error"**
- Use virtual environment: `python3 -m venv proxmox-env && source proxmox-env/bin/activate`
- Or install system packages: `sudo apt install python3-requests`

### CLI Scripts Issues

**"Cannot execute 'qm list'"**
- Ensure you're running on a Proxmox host
- Check user permissions for VM management
- Verify Proxmox VE is properly installed

**"python: command not found"**
- Use `python3 pve_snapshot_create_cli.py` directly
- Or create symlink: `sudo ln -s /usr/bin/python3 /usr/local/bin/python`

### Common Issues (All Scripts)

**"Snapshot name too long"**
- Use shorter prefixes (max 25 characters)
- The script will automatically truncate VM names intelligently

**"VM does not exist"**
- Verify VMID with `qm list` (CLI) or check API debug output
- Check VM accessibility and permissions

**"vmstate ignored - VM stopped"**
- This is normal behavior - vmstate can only be saved for running VMs
- Start the VM if you need to save its state

### Best Practices

**Choose the right script:**
- **Use VM Manager** for: Interactive management, bulk operations, comprehensive VM lifecycle
- **Use API scripts** for: Automation, specific snapshot operations, remote management
- **Use CLI scripts** for: Simple setups, minimal dependencies, direct server access

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

## 📈 Version History

### **v2.5** - Interactive Snapshot Deletion & Enhanced UI
- **✅ NEW: Interactive Snapshot Deletion Tool** - Focused tool for snapshot viewing and deletion operations with enhanced user interface
- **✅ Enhanced display formatting** - Wider tables (135 chars) with expanded name columns (50 chars) for better readability
- **✅ Independent API implementations** - All API scripts now self-contained with complete Proxmox API classes
- **✅ Improved user experience** - Better snapshot name visibility and cleaner interface layouts
- **✅ Standalone script architecture** - Each script includes full API functionality for independent operation

### **v2.4** - Unified VM Management & Enhanced Capabilities
- **✅ NEW: Complete VM Management Script** with interactive menus and bulk operations
- **✅ Advanced bulk operations** with concurrent execution and progress tracking
- **✅ Enhanced VM selection methods** - ranges, patterns, interactive selection
- **✅ Complete backup lifecycle** - create, restore, delete with safety checks
- **✅ Smart error handling** with specific guidance and recovery suggestions
- **✅ Protection mode handling** - automatic detection and safe removal
- **✅ Real-time monitoring** for all operations with detailed progress tracking

### **v2.3** - CLI Scripts Enhancement & UI/UX Unification
- **✅ Enhanced pve_snapshot_delete_cli.py** to match display patterns from other CLI scripts
- **✅ Unified snapshot display format** across all CLI scripts with integrated selection numbers
- **✅ Consistent VM listing** with emoji status indicators and proper formatting
- **✅ Improved user experience** - "q" from snapshot selection now exits completely
- **✅ Eliminated duplicate displays** - Single comprehensive table for snapshot selection
- **✅ VM state type indicators** (🧠 with vmstate / 💾 disk only) across all CLI scripts
- **✅ Date sorting consistency** - All scripts now sort snapshots by newest first

### **v2.2** - Complete API Migration
- **✅ Added API-based deletion script** completing the API migration
- **✅ Feature parity achieved** across all three operations
- **✅ Consistent architecture** with shared inheritance model
- **✅ Enhanced bulk operations** with appropriate safety checks
- **✅ Unified user experience** across create, rollback, and delete

### **v2.1** - Code Unification & Quality Improvements
- **✅ Eliminated code duplication** between API scripts
- **✅ Unified vmstate detection logic** with configurable keywords
- **✅ Improved inheritance structure** for better maintainability
- **✅ Enhanced code quality** with single source of truth
- **✅ Consistent behavior** across all vmstate operations

### **v2.0** - API Scripts Introduction
- Added comprehensive API-based alternatives to CLI scripts
- Multi-node cluster support with enhanced debugging
- Real-time task monitoring and progress tracking
- Configuration comparison features for rollback operations

### **v1.x** - CLI Scripts Foundation
- Original qm command-based implementations
- Interactive and command-line modes
- Basic vmstate support and safety features

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:

- **New features** - Additional VM management capabilities
- **Bug fixes** - Error handling improvements
- **Documentation** - Usage examples and troubleshooting guides
- **Performance optimizations** - Bulk operation improvements
- **UI/UX enhancements** - Better user experience features

## 📄 License

This project is provided as-is for educational and operational purposes. Please test thoroughly in non-production environments before using in production.

## 🆘 Support

For support:

1. **Check the troubleshooting section** above for common issues
2. **Review error messages** carefully - they often contain specific guidance
3. **Test with debug mode** enabled for API connection issues
4. **Verify permissions** are correctly set for API tokens
5. **Check Proxmox logs** for additional error details

## 🏷️ Tags

`proxmox` `virtualization` `vm-management` `snapshots` `backups` `automation` `python` `api` `bulk-operations` `infrastructure` `homelab` `enterprise`