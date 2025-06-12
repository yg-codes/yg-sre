#!/bin/bash

# AWS EC2 Snapshot Manager (Final Clean Version)

set -euo pipefail

# Default Config
CONFIG_FILE="config.env"
AWS_PROFILE="default"
AWS_REGION="us-east-1"
CUSTOM_TAGS_JSON=""
VOLUME_TYPE="gp3"
COPY_TAGS="false"
DRY_RUN=false
OLDER_THAN_DAYS=""
RETENTION_DAYS=30

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
    # Cross-platform stat check
    local perms=$(stat -c "%a" "$CONFIG_FILE" 2>/dev/null || stat -f "%A" "$CONFIG_FILE" 2>/dev/null || echo "unknown")
    [[ "$perms" == "600" ]] || log "⚠️ Warning: $CONFIG_FILE permissions are $perms (should be 600)"
  fi
}

validate_instance_id() {
  [[ "$INSTANCE_ID" =~ ^i-[0-9a-f]{8,17}$ ]] || { log "❌ Invalid Instance ID: $INSTANCE_ID"; exit 1; }
  
  # Check if instance exists
  if ! aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null 2>&1; then
    log "❌ Instance $INSTANCE_ID not found or not accessible"
    exit 1
  fi
}

validate_volume_type() {
  local types=("gp2" "gp3" "io1" "io2" "st1" "sc1")
  [[ " ${types[*]} " =~ " ${VOLUME_TYPE} " ]] || { log "❌ Invalid volume type: $VOLUME_TYPE"; exit 1; }
}

retry() {
  local tries=3 delay=5 count=0
  until "$@"; do
    ((count++))
    ((count>=tries)) && { log "❌ Command failed after $tries attempts: $*"; return 1; }
    log "⚠️ Retry $count/$tries in $delay sec..."
    sleep $delay
  done
}

confirm_action() {
  [[ "$DRY_RUN" == true ]] && { log "🚫 Dry-run: skipping confirmation."; return; }
  read -rp "⚠️ Confirm '$1'? (yes/no): " confirm
  [[ "$confirm" == "yes" ]] || { log "❌ Aborted."; exit 1; }
}

calculate_cutoff_date() {
  if [[ -n "$OLDER_THAN_DAYS" ]]; then
    CUTOFF=$(date -d "$OLDER_THAN_DAYS days ago" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || \
             date -v-"${OLDER_THAN_DAYS}d" '+%Y-%m-%dT%H:%M:%S')
    log "📅 Cutoff date: $CUTOFF"
  fi
}

get_attached_volumes() {
  log "🔍 Fetching attached volumes for instance: $INSTANCE_ID"
  VOLUME_INFO=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --query 'Reservations[].Instances[].BlockDeviceMappings[].{VolumeId:Ebs.VolumeId,DeviceName:DeviceName}' --output json)
  
  if [[ "$VOLUME_INFO" == "[]" ]]; then
    log "⚠️ No EBS volumes found for instance $INSTANCE_ID"
    exit 1
  fi
  
  VOLUME_IDS=($(echo "$VOLUME_INFO" | jq -r '.[].VolumeId'))
  DEVICE_NAMES=($(echo "$VOLUME_INFO" | jq -r '.[].DeviceName'))
  log "✅ Found ${#VOLUME_IDS[@]} volumes: ${VOLUME_IDS[*]}"
}

copy_tags() {
  [[ "$COPY_TAGS" != "true" ]] && return
  local src_id=$1 tgt_id=$2
  log "🔖 Copying tags from $src_id to $tgt_id..."
  
  tags=$(aws ec2 describe-tags --filters "Name=resource-id,Values=$src_id" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --query 'Tags[?Key!=`Name`].[Key,Value]' --output json)
  
  if [[ "$tags" != "[]" ]]; then
    aws ec2 create-tags --resources "$tgt_id" --tags "$tags" \
      --profile "$AWS_PROFILE" --region "$AWS_REGION" 2>/dev/null || true
    log "✅ Tags copied to $tgt_id"
  fi
}

create_snapshots() {
  log "📸 Creating snapshots for ${#VOLUME_IDS[@]} volumes..."
  local pids=()
  
  for VOL in "${VOLUME_IDS[@]}"; do
    (
      if [[ "$DRY_RUN" == true ]]; then
        log "🚫 Dry-run: Would create snapshot for volume $VOL"
        exit 0
      fi
      
      log "➡️ Starting snapshot for volume: $VOL"
      SNAP=$(retry aws ec2 create-snapshot --volume-id "$VOL" \
        --description "Automated snapshot of $VOL from instance $INSTANCE_ID" \
        --profile "$AWS_PROFILE" --region "$AWS_REGION" --query 'SnapshotId' --output text)
      
      log "⏳ Waiting for snapshot $SNAP to complete..."
      retry aws ec2 wait snapshot-completed --snapshot-ids "$SNAP" \
        --profile "$AWS_PROFILE" --region "$AWS_REGION"
      
      # Add custom tags if specified
      if [[ -n "$CUSTOM_TAGS_JSON" ]]; then
        aws ec2 create-tags --resources "$SNAP" --tags "$CUSTOM_TAGS_JSON" \
          --profile "$AWS_PROFILE" --region "$AWS_REGION" 2>/dev/null || true
      fi
      
      copy_tags "$VOL" "$SNAP"
      log "✅ Snapshot completed: $SNAP for volume $VOL"
    ) &
    pids+=($!)
  done
  
  # Wait for all background jobs
  local failed=0
  for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
      ((failed++))
    fi
  done
  
  if [[ $failed -gt 0 ]]; then
    log "❌ $failed snapshot jobs failed!"
    exit 1
  fi
  
  log "🎉 All snapshots created successfully!"
}

list_snapshots() {
  log "📋 Listing snapshots..."
  
  for VOL in "${VOLUME_IDS[@]}"; do
    log "Snapshots for volume: $VOL"
    
    local query='Snapshots[].[SnapshotId,State,StartTime,Description]'
    if [[ -n "$OLDER_THAN_DAYS" ]]; then
      calculate_cutoff_date
      query='Snapshots[?StartTime<=`'"$CUTOFF"'`].[SnapshotId,State,StartTime,Description]'
    fi
    
    aws ec2 describe-snapshots --filters Name=volume-id,Values="$VOL" \
      --query "$query" --output table --profile "$AWS_PROFILE" --region "$AWS_REGION"
  done
}

cleanup_volumes() {
  if [[ $# -gt 0 ]]; then
    log "🧹 Cleaning up temporary volumes..."
    for vol in "$@"; do
      if aws ec2 describe-volumes --volume-ids "$vol" --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null 2>&1; then
        aws ec2 delete-volume --volume-id "$vol" --profile "$AWS_PROFILE" --region "$AWS_REGION" 2>/dev/null || true
        log "✅ Deleted temp volume: $vol"
      fi
    done
  fi
}

rollback_snapshot() {
  # Check instance state
  STATE=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --query 'Reservations[].Instances[].State.Name' --output text)
  
  if [[ "$STATE" != "stopped" ]]; then
    log "❌ CRITICAL: Instance must be stopped for safe rollback!"
    log "Current state: $STATE"
    if [[ "$DRY_RUN" == false ]]; then
      read -rp "Stop instance now? (yes/no): " stop_choice
      if [[ "$stop_choice" == "yes" ]]; then
        log "🛑 Stopping instance..."
        aws ec2 stop-instances --instance-ids "$INSTANCE_ID" \
          --profile "$AWS_PROFILE" --region "$AWS_REGION"
        aws ec2 wait instance-stopped --instance-ids "$INSTANCE_ID" \
          --profile "$AWS_PROFILE" --region "$AWS_REGION"
        log "✅ Instance stopped"
      else
        log "❌ Rollback aborted for safety"
        exit 1
      fi
    else
      log "🚫 Dry-run: Would stop instance for rollback"
    fi
  fi

  confirm_action "rollback to latest snapshots"
  log "🚀 Starting rollback operation..."

  local temp_volumes=()
  trap 'cleanup_volumes "${temp_volumes[@]}"' ERR

  for i in "${!VOLUME_IDS[@]}"; do
    VOL="${VOLUME_IDS[$i]}"
    DEV="${DEVICE_NAMES[$i]}"
    
    # Find latest completed snapshot
    SNAP=$(aws ec2 describe-snapshots --filters Name=volume-id,Values="$VOL" \
      --profile "$AWS_PROFILE" --region "$AWS_REGION" \
      --query 'Snapshots[?State==`completed`]|sort_by(@, &StartTime)[-1].SnapshotId' --output text)
    
    if [[ -z "$SNAP" || "$SNAP" == "None" ]]; then
      log "⚠️ No completed snapshots found for volume $VOL, skipping..."
      continue
    fi

    # Get original volume properties
    PROPS=$(aws ec2 describe-volumes --volume-ids "$VOL" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
      --query 'Volumes[0].[VolumeType,Encrypted,KmsKeyId,Iops,Throughput]' --output json)
    
    VTYPE=$(echo "$PROPS" | jq -r '.[0]')
    ENCRYPTED=$(echo "$PROPS" | jq -r '.[1]')
    KMS=$(echo "$PROPS" | jq -r '.[2]')
    IOPS=$(echo "$PROPS" | jq -r '.[3]')
    THROUGHPUT=$(echo "$PROPS" | jq -r '.[4]')

    if [[ "$DRY_RUN" == true ]]; then
      log "🚫 Dry-run: Would restore snapshot $SNAP as $VTYPE (encrypted=$ENCRYPTED) to $DEV"
      continue
    fi

    # Get instance availability zone
    AZ=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
      --query 'Reservations[].Instances[].Placement.AvailabilityZone' \
      --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")

    # Build create-volume command
    CMD="aws ec2 create-volume --snapshot-id $SNAP --volume-type $VTYPE --availability-zone $AZ"
    [[ "$ENCRYPTED" == "true" ]] && CMD+=" --encrypted"
    [[ "$KMS" != "null" && -n "$KMS" ]] && CMD+=" --kms-key-id $KMS"
    [[ "$IOPS" != "null" && -n "$IOPS" && "$VTYPE" =~ ^io ]] && CMD+=" --iops $IOPS"
    [[ "$THROUGHPUT" != "null" && -n "$THROUGHPUT" && "$VTYPE" == "gp3" ]] && CMD+=" --throughput $THROUGHPUT"

    log "🔧 Creating new volume from snapshot $SNAP..."
    NEWVOL=$(eval "$CMD --query 'VolumeId' --output text --profile $AWS_PROFILE --region $AWS_REGION")
    temp_volumes+=("$NEWVOL")
    
    log "⏳ Waiting for new volume $NEWVOL to become available..."
    aws ec2 wait volume-available --volume-ids "$NEWVOL" --profile "$AWS_PROFILE" --region "$AWS_REGION"
    
    # Copy tags from original volume
    copy_tags "$VOL" "$NEWVOL"

    # Detach current volume and attach new one
    log "🔌 Detaching current volume $VOL from $DEV..."
    aws ec2 detach-volume --volume-id "$VOL" --profile "$AWS_PROFILE" --region "$AWS_REGION"
    aws ec2 wait volume-available --volume-ids "$VOL" --profile "$AWS_PROFILE" --region "$AWS_REGION"
    
    log "🔌 Attaching new volume $NEWVOL to $DEV..."
    aws ec2 attach-volume --volume-id "$NEWVOL" --instance-id "$INSTANCE_ID" --device "$DEV" \
      --profile "$AWS_PROFILE" --region "$AWS_REGION"
    
    log "✅ Successfully restored $DEV with volume $NEWVOL from snapshot $SNAP"
  done
  
  log "🎉 Rollback completed! Remember to start your instance when ready."
}

delete_snapshots() {
  confirm_action "delete snapshots"
  log "🗑️ Deleting snapshots..."
  
  local total_deleted=0
  for VOL in "${VOLUME_IDS[@]}"; do
    local query='Snapshots[?State==`completed`].SnapshotId'
    
    # Apply date filter if specified
    if [[ -n "$OLDER_THAN_DAYS" ]]; then
      calculate_cutoff_date
      query='Snapshots[?State==`completed`&&StartTime<=`'"$CUTOFF"'`].SnapshotId'
      log "🔍 Filtering snapshots older than $CUTOFF for volume $VOL"
    fi
    
    SNAPS=$(aws ec2 describe-snapshots --filters Name=volume-id,Values="$VOL" \
      --profile "$AWS_PROFILE" --region "$AWS_REGION" \
      --query "$query" --output text)
    
    for SNAP in $SNAPS; do
      if [[ "$SNAP" != "None" && -n "$SNAP" ]]; then
        if [[ "$DRY_RUN" == true ]]; then
          log "🚫 Dry-run: Would delete snapshot $SNAP"
        else
          aws ec2 delete-snapshot --snapshot-id "$SNAP" --profile "$AWS_PROFILE" --region "$AWS_REGION"
          log "✅ Deleted snapshot: $SNAP"
          ((total_deleted++))
        fi
      fi
    done
  done
  
  if [[ "$DRY_RUN" == false ]]; then
    log "🎉 Deleted $total_deleted snapshots!"
  fi
}

usage() {
  cat << EOF
AWS EC2 Snapshot Manager

Usage: $0 <action> <instance-id> [options]

Actions:
  create    Create snapshots of all attached volumes
  list      List existing snapshots
  rollback  Restore volumes from latest snapshots (requires stopped instance)
  delete    Delete snapshots

Options:
  --dry-run           Show what would be done without making changes
  --older-than DAYS   For list/delete: filter snapshots older than N days

Examples:
  $0 create i-0123456789abcdef0
  $0 list i-0123456789abcdef0 --older-than 30
  $0 rollback i-0123456789abcdef0 --dry-run
  $0 delete i-0123456789abcdef0 --older-than 30

Config file (config.env):
  AWS_PROFILE=your-profile
  AWS_REGION=us-east-1
  CUSTOM_TAGS_JSON='[{"Key":"Environment","Value":"Production"}]'
  VOLUME_TYPE=gp3
  COPY_TAGS=true
  RETENTION_DAYS=30
EOF
  exit 1
}

main() {
  # Check minimum arguments
  if [[ $# -lt 2 ]]; then
    usage
  fi
  
  ACTION="$1"
  INSTANCE_ID="$2"
  shift 2
  
  # Parse options
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run) 
        DRY_RUN=true
        log "🚫 Dry-run mode enabled"
        ;;
      --older-than) 
        shift
        OLDER_THAN_DAYS="$1"
        if ! [[ "$OLDER_THAN_DAYS" =~ ^[0-9]+$ ]]; then
          log "❌ Invalid --older-than value: $OLDER_THAN_DAYS (must be a number)"
          exit 1
        fi
        ;;
      --help|-h)
        usage
        ;;
      *)
        log "❌ Unknown option: $1"
        usage
        ;;
    esac
    shift
  done
  
  # Validate action
  case "$ACTION" in
    create|list|rollback|delete) ;;
    *) log "❌ Unknown action: $ACTION"; usage ;;
  esac
  
  # Load config and validate
  load_config
  validate_instance_id
  validate_volume_type
  get_attached_volumes
  
  # Execute action
  case "$ACTION" in
    create) create_snapshots ;;
    list) list_snapshots ;;
    rollback) rollback_snapshot ;;
    delete) delete_snapshots ;;
  esac
  
  log "🎉 Operation '$ACTION' completed successfully!"
}

main "$@"