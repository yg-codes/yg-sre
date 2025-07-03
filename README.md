# YG-SRE: Multi-Cloud Infrastructure Management Tools

A comprehensive SRE toolkit for managing hybrid cloud environments, featuring specialized tools for both on-premise Proxmox VE and AWS public cloud infrastructure. Designed for Site Reliability Engineers who manage diverse infrastructure environments.

## 🏗️ Architecture Overview

```
YG-SRE Multi-Cloud Environment
├── 🏢 On-Premise Infrastructure (Proxmox VE)
│   ├── VM Lifecycle Management
│   ├── Snapshot Operations
│   ├── Backup Management
│   └── Bulk Operations
│
└── ☁️ Public Cloud Infrastructure (AWS)
    ├── EC2 Instance Management
    ├── EBS Snapshot Automation
    ├── Cross-Region Backup
    └── Cost Optimization
```

## 📂 Repository Structure

```
yg-sre/
├── 🏢 proxmox/                          # On-premise infrastructure tools
│   ├── pve_vm_manager_api.py           # Complete VM lifecycle management
│   ├── pve_snapshot_manager.py         # Advanced snapshot operations
│   └── pve_snapshots/                  # Modular snapshot components
│       ├── pve_snapshot_create_api.py  # API-based snapshot creation
│       ├── pve_snapshot_create_cli.py  # CLI snapshot creation
│       ├── pve_snapshot_delete_api.py  # API-based snapshot deletion
│       ├── pve_snapshot_delete_cli.py  # CLI snapshot deletion
│       ├── pve_snapshot_delete_interactive.py # Interactive deletion
│       ├── pve_snapshot_rollback_api.py # API-based rollback
│       └── pve_snapshot_rollback_cli.py # CLI rollback
│
└── ☁️ aws/                              # Public cloud infrastructure tools
    └── aws_ec2_snapshot_manager.sh     # EC2/EBS snapshot automation
```

## 🚀 Quick Start

### Prerequisites
- **For Proxmox:** Python 3.6+, Proxmox VE API access
- **For AWS:** AWS CLI configured, appropriate IAM permissions
- Network access to respective infrastructure endpoints

### 🏢 Proxmox Environment Setup

**⚠️ CRITICAL: Configure permissions FIRST!**

```bash
# 1. Create API token in Proxmox Web UI (Datacenter → Permissions → API Tokens)
# 2. Grant permissions (REQUIRED):
pveum aclmod / -token 'your-username@pam!your-token-name' -role PVEVMAdmin

# 3. Set environment variables
export PVE_HOST=your-proxmox-host.com
export PVE_USER=your-username@pam
export PVE_TOKEN_NAME=your-token-name
export PVE_TOKEN_VALUE=your-token-value

# 4. Install dependencies
pip install requests urllib3

# 5. Start managing VMs
cd proxmox
./pve_vm_manager_api.py
```

### ☁️ AWS Environment Setup

```bash
# 1. Configure AWS CLI
aws configure

# 2. Verify permissions for EC2/EBS operations
aws sts get-caller-identity

# 3. Make script executable
cd aws
chmod +x aws_ec2_snapshot_manager.sh

# 4. Run snapshot manager
./aws_ec2_snapshot_manager.sh
```

## 🏢 Proxmox Tools Overview

> **Note:** For detailed documentation on Proxmox tools, including comprehensive usage examples, advanced features, and troubleshooting, see the [Proxmox README](./proxmox/README.md).

### Primary Scripts

#### 🎛️ `pve_vm_manager_api.py` - Unified VM Management Hub
The central command center for all Proxmox operations, providing a comprehensive interface for VM lifecycle management.

**Key Capabilities:**
- 📊 **Real-time Monitoring:** CPU/RAM usage, VM status across clusters
- ⚡ **VM Operations:** Start, stop, restart with safety validations
- 💾 **Backup Management:** Create, restore, delete with storage selection
- 📸 **Snapshot Lifecycle:** Complete snapshot operations with rollback
- 🚀 **Bulk Operations:** Concurrent operations across multiple VMs

#### 📸 `pve_snapshot_manager.py` - Advanced Snapshot Specialist
Dedicated tool for sophisticated snapshot workflows with both interactive and CLI automation capabilities.

**Advanced Features:**
- 🔄 **Complete Lifecycle:** Create, list, rollback, delete operations
- 📝 **Dual Interface:** Interactive menus + command-line automation
- 🧹 **Smart Cleanup:** Pattern-based bulk deletion

## ☁️ AWS Tools Overview

> **Note:** For detailed documentation on AWS tools, including comprehensive usage examples, advanced features, and troubleshooting, see the [AWS README](./aws/README.md).

### `aws_ec2_snapshot_manager.sh` - EC2/EBS Automation

A robust shell script for automating EC2 instance and EBS volume snapshot operations in AWS environments.

**Core Features:**
- 📸 **Automated Snapshots:** EC2 instances and individual EBS volumes
- 🕐 **Scheduled Operations:** Cron-compatible for automated backups
- 🏷️ **Tag-Based Management:** Organize and filter resources efficiently
- 🔄 **Cross-Region Support:** Multi-region backup strategies
- 🧹 **Retention Policies:** Automated cleanup of old snapshots

## 🛡️ SRE Best Practices & Safety Features

### Multi-Environment Safety
- ✅ **Environment Isolation:** Clear separation between Proxmox and AWS operations
- ✅ **Cross-Platform Consistency:** Similar workflow patterns across environments
- ✅ **Unified Monitoring:** Consistent logging and reporting across platforms

### Proxmox Safety Features
- ✅ **Multi-level confirmations** for destructive operations
- ✅ **VM protection mode detection** and automatic handling
- ✅ **Real-time task monitoring** prevents silent failures

### AWS Safety Features
- ✅ **IAM permission validation** before operations
- ✅ **Cross-region verification** for data protection
- ✅ **Tag-based safety checks** prevent accidental operations

---

**🎯 SRE Philosophy:** *"Minimize toil, maximize reliability, automate everything that can be automated safely."*

*Built by SREs, for SREs managing complex multi-cloud environments.*
