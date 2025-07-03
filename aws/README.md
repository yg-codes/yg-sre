# AWS Tools - YG-SRE Cloud Infrastructure Management

This directory contains specialized tools for managing AWS cloud infrastructure as part of the YG-SRE multi-cloud toolkit. These tools are designed for Site Reliability Engineers who need robust, automated solutions for AWS resource management.

## 📸 `aws_ec2_snapshot_manager.sh` - EC2/EBS Snapshot Automation

A comprehensive shell script for managing EC2 instance and EBS volume snapshots with advanced features for automation, retention management, and safety.

### 🔑 Key Features

- 📸 **Complete Snapshot Lifecycle:** Create, list, rollback, and delete snapshots
- 🔄 **Instance-Level Operations:** Manage all volumes attached to an EC2 instance
- 🕒 **Time-Based Filtering:** Target snapshots older than specified days
- 🧪 **Dry Run Mode:** Preview operations without making changes
- 🔒 **Safety Confirmations:** Multi-level verification for destructive operations
- 🏷️ **Tag Management:** Copy volume tags to snapshots and add custom tags
- 🔄 **Volume Property Preservation:** Maintain encryption, IOPS, and throughput settings during rollbacks
- 🧹 **Automatic Cleanup:** Temporary volume handling with trap-based error recovery

### 🚀 Quick Start

```bash
# Make the script executable
chmod +x aws_ec2_snapshot_manager.sh

# Create snapshots for all volumes attached to an instance
./aws_ec2_snapshot_manager.sh create i-0123456789abcdef0

# List snapshots for an instance
./aws_ec2_snapshot_manager.sh list i-0123456789abcdef0

# List snapshots older than 30 days
./aws_ec2_snapshot_manager.sh list i-0123456789abcdef0 --older-than 30

# Delete snapshots older than 30 days
./aws_ec2_snapshot_manager.sh delete i-0123456789abcdef0 --older-than 30

# Rollback to latest snapshots (instance must be stopped)
./aws_ec2_snapshot_manager.sh rollback i-0123456789abcdef0

# Preview operations without making changes
./aws_ec2_snapshot_manager.sh create i-0123456789abcdef0 --dry-run
```

### ⚙️ Configuration

The script supports configuration through a `config.env` file in the same directory:

```bash
# config.env example
AWS_PROFILE=your-profile
AWS_REGION=us-east-1
CUSTOM_TAGS_JSON='[{"Key":"Environment","Value":"Production"}]'
VOLUME_TYPE=gp3
COPY_TAGS=true
RETENTION_DAYS=30
```

#### Configuration Options

| Option | Description | Default |
|--------|-------------|--------|
| `AWS_PROFILE` | AWS CLI profile to use | `default` |
| `AWS_REGION` | AWS region for operations | `us-east-1` |
| `CUSTOM_TAGS_JSON` | JSON array of tags to add to snapshots | `""` |
| `VOLUME_TYPE` | EBS volume type for rollback operations | `gp3` |
| `COPY_TAGS` | Whether to copy volume tags to snapshots | `false` |
| `RETENTION_DAYS` | Default retention period in days | `30` |

### 🔐 Security Best Practices

- **File Permissions:** Keep your `config.env` file secure with `chmod 600 config.env`
- **IAM Permissions:** Use the principle of least privilege for AWS credentials
- **Encryption:** Maintain EBS volume encryption settings during operations
- **Dry Run:** Test operations with `--dry-run` before executing
- **Confirmation:** The script requires explicit confirmation for destructive operations

### 📋 Command Reference

#### Create Snapshots
```bash
./aws_ec2_snapshot_manager.sh create i-0123456789abcdef0 [--dry-run]
```
Creates snapshots of all volumes attached to the specified EC2 instance.

#### List Snapshots
```bash
./aws_ec2_snapshot_manager.sh list i-0123456789abcdef0 [--older-than DAYS]
```
Lists snapshots for all volumes attached to the specified EC2 instance, with optional time filtering.

#### Rollback to Snapshots
```bash
./aws_ec2_snapshot_manager.sh rollback i-0123456789abcdef0 [--dry-run]
```
Restores volumes from the latest snapshots. The instance must be stopped for this operation.

#### Delete Snapshots
```bash
./aws_ec2_snapshot_manager.sh delete i-0123456789abcdef0 [--older-than DAYS] [--dry-run]
```
Deletes snapshots for all volumes attached to the specified EC2 instance, with optional time filtering.

### 🔄 Automation Examples

#### Daily Snapshot Cron Job
```bash
# Create daily snapshots at 2 AM
0 2 * * * /path/to/aws_ec2_snapshot_manager.sh create i-0123456789abcdef0 >> /var/log/snapshots.log 2>&1
```

#### Weekly Cleanup Cron Job
```bash
# Delete snapshots older than 30 days every Sunday at 3 AM
0 3 * * 0 /path/to/aws_ec2_snapshot_manager.sh delete i-0123456789abcdef0 --older-than 30 >> /var/log/snapshots.log 2>&1
```

### 🐛 Troubleshooting

#### Common Issues

1. **Permission Denied**
   - Ensure the script is executable: `chmod +x aws_ec2_snapshot_manager.sh`
   - Check AWS CLI credentials: `aws sts get-caller-identity`

2. **AWS CLI Not Configured**
   - Run `aws configure` to set up credentials
   - Or specify a profile: `AWS_PROFILE=your-profile ./aws_ec2_snapshot_manager.sh ...`

3. **Instance Not Found**
   - Verify the instance ID is correct
   - Check that you have permission to access the instance
   - Ensure you're in the correct AWS region

4. **Rollback Failures**
   - Ensure the instance is stopped before rollback
   - Check for sufficient EBS volume limits in your account
   - Verify snapshot completion status before rollback

### 🔍 Advanced Usage

#### Custom Tags

Add custom tags to snapshots by setting the `CUSTOM_TAGS_JSON` variable:

```bash
CUSTOM_TAGS_JSON='[{"Key":"Environment","Value":"Production"},{"Key":"Backup","Value":"Daily"}]'
```

#### Cross-Account Operations

For cross-account operations, configure appropriate IAM roles and profiles:

```bash
# In config.env
AWS_PROFILE=cross-account-role
```

#### Error Handling

The script includes robust error handling with:
- Automatic retry for transient AWS API failures
- Trap-based cleanup of temporary resources
- Detailed logging with timestamps
- Validation of inputs before operations

## 🔄 Integration with YG-SRE Toolkit

This AWS tool complements the Proxmox tools in the YG-SRE toolkit, providing a consistent approach to infrastructure management across on-premise and cloud environments.

### Cross-Platform Workflows

- **Unified Backup Strategy:** Coordinate backups across Proxmox and AWS
- **Consistent Naming:** Use similar naming conventions for snapshots
- **Centralized Reporting:** Combine logs for comprehensive backup reporting

## 🤝 Contributing

Contributions to improve the AWS tools are welcome. Areas for enhancement include:

- Additional AWS services support (RDS, EFS, etc.)
- Integration with monitoring systems
- Enhanced reporting capabilities
- Multi-region and multi-account support improvements

---

**🎯 SRE Philosophy:** *"Minimize toil, maximize reliability, automate everything that can be automated safely."*

*Built by SREs, for SREs managing complex multi-cloud environments.*