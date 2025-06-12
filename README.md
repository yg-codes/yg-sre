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

## 🏢 Proxmox Tools - On-Premise Infrastructure

### Primary Scripts

#### 🎛️ `pve_vm_manager_api.py` - Unified VM Management Hub
The central command center for all Proxmox operations, providing a comprehensive interface for VM lifecycle management.

**Key Capabilities:**
- 📊 **Real-time Monitoring:** CPU/RAM usage, VM status across clusters
- ⚡ **VM Operations:** Start, stop, restart with safety validations
- 💾 **Backup Management:** Create, restore, delete with storage selection
- 📸 **Snapshot Lifecycle:** Complete snapshot operations with rollback
- 🚀 **Bulk Operations:** Concurrent operations across multiple VMs
- 🎯 **Quick Actions:** Emergency stops, mass backups, cluster-wide operations

#### 📸 `pve_snapshot_manager.py` - Advanced Snapshot Specialist
Dedicated tool for sophisticated snapshot workflows with both interactive and CLI automation capabilities.

**Advanced Features:**
- 🔄 **Complete Lifecycle:** Create, list, rollback, delete operations
- 📝 **Dual Interface:** Interactive menus + command-line automation
- 🧹 **Smart Cleanup:** Pattern-based bulk deletion
- 🔍 **Configuration Preview:** See exactly what changes during rollbacks
- ⚙️ **vmstate Handling:** Intelligent RAM state management

### Modular Components (`pve_snapshots/`)

The `pve_snapshots` directory contains specialized, focused scripts for specific snapshot operations:

```bash
# API-based operations (programmatic integration)
pve_snapshot_create_api.py      # Snapshot creation via API
pve_snapshot_delete_api.py      # Snapshot deletion via API  
pve_snapshot_rollback_api.py    # Snapshot rollback via API

# CLI operations (automation & scripting)
pve_snapshot_create_cli.py      # Command-line snapshot creation
pve_snapshot_delete_cli.py      # Command-line snapshot deletion
pve_snapshot_rollback_cli.py    # Command-line snapshot rollback

# Interactive operations (guided workflows)
pve_snapshot_delete_interactive.py  # Interactive deletion with safety
```

### Proxmox Usage Examples

#### Interactive VM Management
```bash
cd proxmox
./pve_vm_manager_api.py

# Navigate through:
# 1. View Available VMs - Cluster-wide status overview
# 2. Manage Single VM - Individual VM operations
# 3. Bulk Operations - Multi-VM concurrent operations
# 4. Quick Actions - Emergency and mass operations
```

#### Advanced Snapshot Operations
```bash
# Command-line snapshot creation
./pve_snapshot_manager.py create daily-backup 7201-7210

# Interactive snapshot management
./pve_snapshot_manager.py
# Select: Manage Single VM → Enter VM ID → Snapshot Operations

# Bulk snapshot cleanup
./pve_snapshot_manager.py
# Select: Bulk Operations → Bulk Delete Snapshots → Pattern: test-*
```

#### VM Selection Methods
```bash
# Range selection
VMs to manage: 7200-7299

# Specific VMs  
VMs to manage: 7201,7203,7205,7207

# Pattern matching
VMs to manage: web*        # All VMs starting with "web"
VMs to manage: db*         # All database VMs

# State-based selection
VMs to manage: running     # All running VMs
VMs to manage: stopped     # All stopped VMs
VMs to manage: all         # All VMs in cluster

# Interactive checkbox selection
VMs to manage: i
```

## ☁️ AWS Tools - Public Cloud Infrastructure

### `aws_ec2_snapshot_manager.sh` - EC2/EBS Automation

A robust shell script for automating EC2 instance and EBS volume snapshot operations in AWS environments.

**Core Features:**
- 📸 **Automated Snapshots:** EC2 instances and individual EBS volumes
- 🕐 **Scheduled Operations:** Cron-compatible for automated backups
- 🏷️ **Tag-Based Management:** Organize and filter resources efficiently
- 🔄 **Cross-Region Support:** Multi-region backup strategies
- 🧹 **Retention Policies:** Automated cleanup of old snapshots
- 📊 **Cost Optimization:** Monitor and manage snapshot storage costs

### AWS Usage Examples

#### Basic Snapshot Operations
```bash
cd aws

# Create snapshot of specific volume
./aws_ec2_snapshot_manager.sh --volume-id vol-1234567890abcdef0

# Create snapshot of all volumes in instance
./aws_ec2_snapshot_manager.sh --instance-id i-1234567890abcdef0

# List snapshots with filtering
./aws_ec2_snapshot_manager.sh --list --tag Environment=Production

# Cleanup old snapshots (older than 30 days)
./aws_ec2_snapshot_manager.sh --cleanup --retention-days 30
```

#### Advanced Operations
```bash
# Cross-region snapshot copy
./aws_ec2_snapshot_manager.sh --copy-to-region us-east-1 \
  --source-snapshot snap-1234567890abcdef0

# Tag-based bulk operations
./aws_ec2_snapshot_manager.sh --bulk-snapshot \
  --tag-filter "Environment=Production,Backup=true"

# Schedule daily backups (add to crontab)
0 2 * * * /path/to/aws_ec2_snapshot_manager.sh --auto-backup
```

## 🛡️ SRE Best Practices & Safety Features

### Multi-Environment Safety
- ✅ **Environment Isolation:** Clear separation between Proxmox and AWS operations
- ✅ **Cross-Platform Consistency:** Similar workflow patterns across environments
- ✅ **Unified Monitoring:** Consistent logging and reporting across platforms

### Proxmox Safety Features
- ✅ **Multi-level confirmations** for destructive operations
- ✅ **VM protection mode detection** and automatic handling
- ✅ **Real-time task monitoring** prevents silent failures
- ✅ **Resource validation** before operations
- ✅ **Graceful error recovery** with specific guidance

### AWS Safety Features
- ✅ **IAM permission validation** before operations
- ✅ **Cross-region verification** for data protection
- ✅ **Tag-based safety checks** prevent accidental operations
- ✅ **Retention policy enforcement** prevents data loss
- ✅ **Cost monitoring integration** prevents budget overruns

## 🔧 Advanced Configuration

### Proxmox Configuration
```bash
# Concurrency limits (adjust based on hardware)
MAX_CONCURRENT_START_STOP=3    # VM operations
MAX_CONCURRENT_BACKUPS=2       # Backup operations
MAX_CONCURRENT_SNAPSHOTS=2     # Snapshot operations

# Snapshot naming conventions
PREFIX_MAX_LENGTH=20           # Ensures space for timestamps
NAMING_FORMAT="{prefix}-vm{vmid}-{timestamp}"
```

### AWS Configuration
```bash
# Default regions and availability zones
export AWS_DEFAULT_REGION=us-west-2
export AWS_BACKUP_REGION=us-east-1

# Snapshot retention policies
SNAPSHOT_RETENTION_DAYS=30     # Default retention
CRITICAL_RETENTION_DAYS=90     # Critical system retention
ARCHIVE_AFTER_DAYS=365         # Archive to cold storage

# Cost optimization
ENABLE_COST_MONITORING=true
BUDGET_ALERT_THRESHOLD=80      # Alert at 80% of budget
```

## 📊 Multi-Cloud Monitoring & Reporting

### Unified Dashboard Approach
```bash
# Proxmox cluster health
./pve_vm_manager_api.py --cluster-status

# AWS resource summary  
./aws_ec2_snapshot_manager.sh --account-summary

# Cross-platform backup report
./generate-backup-report.sh --all-environments
```

### SRE Metrics & KPIs
- **Recovery Time Objective (RTO):** Target restoration times per environment
- **Recovery Point Objective (RPO):** Maximum acceptable data loss
- **Backup Success Rate:** Percentage of successful backup operations
- **Cross-Region Replication:** Data protection across geographic regions
- **Cost Per GB:** Storage optimization metrics across platforms

## 🐛 Troubleshooting Guide

### Proxmox Common Issues
```bash
# Permission errors (most common)
pveum aclmod / -token 'user@pam!token' -role PVEVMAdmin

# API connectivity issues
curl -k https://$PVE_HOST:8006/api2/json/version

# Node communication problems
ping $PVE_HOST && telnet $PVE_HOST 8006
```

### AWS Common Issues
```bash
# IAM permission validation
aws sts get-caller-identity
aws iam get-user

# Region/AZ verification
aws ec2 describe-regions
aws ec2 describe-availability-zones

# Snapshot status check
aws ec2 describe-snapshots --owner-ids self
```

### Cross-Platform Issues
```bash
# Network connectivity between environments
./network-diagnostic.sh --test-all

# Backup consistency validation
./backup-verification.sh --cross-platform-check

# Resource tagging audit
./tag-audit.sh --proxmox --aws
```

## 📚 SRE Operational Runbooks

### Daily Operations
1. **Morning Health Check**
   - Verify all VM/instance states
   - Check overnight backup status
   - Review resource utilization

2. **Backup Validation**
   - Test restoration procedures weekly
   - Verify cross-region replication
   - Monitor storage consumption

3. **Incident Response**
   - Snapshot before major changes
   - Document all operational changes
   - Maintain change logs across environments

### Emergency Procedures
```bash
# Emergency VM shutdown (Proxmox)
./pve_vm_manager_api.py --emergency-stop-all

# Emergency instance protection (AWS)
./aws_ec2_snapshot_manager.sh --emergency-snapshot-all

# Disaster recovery initiation
./disaster-recovery.sh --environment [proxmox|aws|all]
```

## 🤝 Contributing to SRE Excellence

This toolkit thrives on contributions from the SRE community. Areas for enhancement:

- **Monitoring Integration:** Prometheus, Grafana, CloudWatch
- **Automation Workflows:** Ansible playbooks, Terraform modules
- **ChatOps Integration:** Slack/Teams bot operations
- **Cost Optimization:** Advanced analytics and recommendations
- **Security Hardening:** Enhanced access controls and audit trails

## 📄 License & Compliance

This project is provided as-is for educational and operational purposes. Ensure compliance with:
- Your organization's infrastructure policies
- Proxmox VE licensing terms
- AWS service agreements and pricing
- Industry compliance requirements (SOC2, HIPAA, etc.)

---

**🎯 SRE Philosophy:** *"Minimize toil, maximize reliability, automate everything that can be automated safely."*

*Built by SREs, for SREs managing complex multi-cloud environments.*
