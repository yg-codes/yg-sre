#!/usr/bin/env python3

"""
Enhanced Proxmox VM Snapshot Management Script
Usage: ./pve_snapshot_create.py [prefix] [vmid1] [vmid2] ... [vmidN]
If no arguments provided, it will run in interactive mode

Enhancements:
- Shows VM status with colored indicators (🟢 running 🔴 stopped)
- Checks VM config before snapshot creation
- Verifies snapshot config after creation
"""

import sys
import subprocess
import re
from datetime import datetime
from typing import List, Optional, Tuple, Dict
import time

class ProxmoxSnapshotManager:
    """Manages Proxmox VM snapshots with intelligent naming and validation."""

    def __init__(self):
        self.max_snapshot_name_length = 40
        self.max_prefix_length = 25
        self.save_vmstate = False  # Default to not saving vmstate

    def display_usage(self):
        """Display usage information."""
        usage_text = """
Usage: python3 pve_snapshot_create.py [prefix] [vmid1] [vmid2] ... [vmidN]

Creates snapshots with format: <PREFIX>-<3RD_SECTION>-YYYYMMDD-HHMM
The 3RD_SECTION is extracted from VM name using '-' as separator (3rd part onwards)

Examples:
  python3 pve_snapshot_create.py pre-release 7201 7203 7204    # Snapshot specific VMs with 'pre-release' prefix
  python3 pve_snapshot_create.py maintenance                   # Snapshot all VMs with 'maintenance' prefix
  python3 pve_snapshot_create.py                               # Interactive mode - prompts for prefix and VM selection

Sample snapshot names that will be created:
  VM 7201 (xsf-dev-storage01) -> pre-release-storage01-20250530-1430
  VM with xaj-prod-apps02 -> maintenance-apps02-20250530-1430

Features:
  - Interactive mode with VM state saving option
  - Intelligent VM name extraction and truncation
  - Snapshot validation and preview
  - VM status checking with colored indicators (🟢 running 🔴 stopped)
  - Configuration verification before and after snapshot creation
  - Optional VM state (RAM) saving with --vmstate option
"""
        print(usage_text)

    def run_qm_command(self, command: List[str], capture_output: bool = True, check: bool = True) -> subprocess.CompletedProcess:
        """Run a qm command and return the result."""
        try:
            if capture_output:
                result = subprocess.run(command, capture_output=True, text=True, check=check)
            else:
                result = subprocess.run(command, check=check)
            return result
        except subprocess.CalledProcessError as e:
            if check:
                raise
            return e
        except FileNotFoundError:
            print("ERROR: 'qm' command not found. Make sure you're running this on a Proxmox server.")
            sys.exit(1)

    def check_permissions(self) -> bool:
        """Check if we have proper permissions to run qm commands."""
        try:
            self.run_qm_command(['qm', 'list'])
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("ERROR: Cannot execute 'qm list'. Make sure you have proper permissions.")
            return False

    def check_vm_exists(self, vmid: str) -> bool:
        """Check if a VM exists and is accessible."""
        try:
            result = self.run_qm_command(['qm', 'status', vmid], check=False)
            return result.returncode == 0
        except Exception:
            return False

    def get_vm_status_detailed(self, vmid: str) -> Tuple[bool, str, str]:
        """Get detailed VM status with colored indicator."""
        try:
            result = self.run_qm_command(['qm', 'status', vmid], check=False)
            if result.returncode == 0:
                status_output = result.stdout.strip()
                is_running = 'status: running' in status_output.lower()
                if is_running:
                    return True, "🟢 running", status_output
                else:
                    return False, "🔴 stopped", status_output
            else:
                # Treat errors as stopped
                return False, "🔴 stopped", f"Failed to get status: {result.stderr}"
        except Exception as e:
            return False, "🔴 stopped", f"Exception: {str(e)}"

    def check_vm_running(self, vmid: str) -> bool:
        """Check if a VM is currently running."""
        is_running, _, _ = self.get_vm_status_detailed(vmid)
        return is_running

    def get_vm_config(self, vmid: str, snapshot_name: str = None) -> Dict[str, str]:
        """Get VM configuration, optionally from a specific snapshot."""
        try:
            if snapshot_name:
                cmd = ['qm', 'config', vmid, '--snapshot', snapshot_name]
            else:
                cmd = ['qm', 'config', vmid, '--current']

            result = self.run_qm_command(cmd, check=False)

            config = {}
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        config[key.strip()] = value.strip()
            return config
        except Exception as e:
            print(f"  ⚠ Error getting config: {e}")
            return {}

    def display_vm_config_summary(self, config: Dict[str, str], title: str):
        """Display a summary of important VM configuration values."""
        if not config:
            print(f"  {title}: No config data available")
            return

        print(f"  {title}:")

        # Key configuration items to display
        important_keys = [
            'name', 'memory', 'cores', 'sockets', 'ostype', 'bootdisk',
            'scsi0', 'ide2', 'net0', 'agent', 'onboot'
        ]

        displayed_items = []
        for key in important_keys:
            if key in config:
                value = config[key]
                # Truncate long values
                if len(value) > 50:
                    value = value[:47] + "..."
                displayed_items.append(f"{key}={value}")

        if displayed_items:
            # Display in pairs for better readability
            for i in range(0, len(displayed_items), 2):
                if i + 1 < len(displayed_items):
                    print(f"    {displayed_items[i]:<35} {displayed_items[i+1]}")
                else:
                    print(f"    {displayed_items[i]}")
        else:
            print("    No important config items found")

    def get_vm_name(self, vmid: str) -> Optional[str]:
        """Get VM name from qm list and clean it according to the rules."""
        try:
            result = self.run_qm_command(['qm', 'list'])
            lines = result.stdout.strip().split('\n')

            for line in lines[1:]:  # Skip header
                parts = line.split()
                if parts and parts[0] == vmid:
                    full_name = parts[1] if len(parts) > 1 else ""

                    # Extract the 3rd section separated by hyphens
                    name_parts = full_name.split('-')
                    if len(name_parts) >= 3:
                        clean_name = '-'.join(name_parts[2:])
                    else:
                        # Fall back to removing common prefixes
                        clean_name = full_name
                        if clean_name.startswith('xsf-dev-'):
                            clean_name = clean_name[8:]
                        elif clean_name.startswith('xaj-prod-'):
                            clean_name = clean_name[9:]

                    return clean_name if clean_name else full_name
            return None
        except Exception as e:
            print(f"Error getting VM name for {vmid}: {e}")
            return None

    def get_full_vm_name(self, vmid: str) -> Optional[str]:
        """Get the full VM name from qm list."""
        try:
            result = self.run_qm_command(['qm', 'list'])
            lines = result.stdout.strip().split('\n')

            for line in lines[1:]:  # Skip header
                parts = line.split()
                if parts and parts[0] == vmid:
                    return parts[1] if len(parts) > 1 else ""
            return None
        except Exception:
            return None

    def truncate_vm_name_intelligently(self, vm_name: str, max_length: int) -> str:
        """Intelligently truncate VM name while preserving meaningful parts."""
        if len(vm_name) <= max_length:
            return vm_name

        # Strategy 1: Try to keep the last number/identifier (like "02" in "apps02")
        number_match = re.search(r'^(.+)([0-9]+)$', vm_name)
        if number_match:
            base_part = number_match.group(1)
            number_part = number_match.group(2)
            base_length = max_length - len(number_part)

            if base_length > 0:
                return base_part[:base_length] + number_part

        # Strategy 2: Try to break at word boundaries (hyphens)
        temp_name = vm_name
        while len(temp_name) > max_length and '-' in temp_name:
            temp_name = temp_name.rsplit('-', 1)[0]

        # If we found a good break point and it's not too short, use it
        if len(temp_name) <= max_length and len(temp_name) > max_length // 2:
            return temp_name

        # Strategy 3: Simple truncation
        return vm_name[:max_length]

    def prompt_vmstate_option(self) -> bool:
        """Prompt user for VM state saving option with appropriate warning."""
        print("\n" + "=" * 60)
        print("VM STATE SAVING OPTION")
        print("=" * 60)
        print("⚠️  WARNING: Saving VM state (RAM) has important implications:")
        print("   • Snapshot will include the current RAM state of the VM")
        print("   • Snapshot creation will take SIGNIFICANTLY longer")
        print("   • Larger storage space will be required")
        print("   • VM must be running for vmstate to be saved")
        print("   • Restoring vmstate snapshot will resume VM from exact point")
        print("=" * 60)

        while True:
            try:
                choice = input("Save VM state (RAM) with snapshots? (y/N): ").strip().lower()
                if choice in ['', 'n', 'no']:
                    print("✓ Snapshots will be created WITHOUT VM state (faster)")
                    return False
                elif choice in ['y', 'yes']:
                    print("✓ Snapshots will be created WITH VM state (slower, includes RAM)")
                    return True
                else:
                    print("Please enter 'y' for yes or 'n' for no (default: no)")
            except KeyboardInterrupt:
                print("\nDefaulting to no VM state saving")
                return False

    def create_snapshot(self, vmid: str, prefix: str) -> bool:
        """Create a snapshot for a VM with intelligent naming and status checking."""
        timestamp = datetime.now().strftime('%Y%m%d-%H%M')
        vm_name = self.get_vm_name(vmid)

        if not vm_name:
            print(f"  ✗ Could not retrieve VM name for VMID {vmid}")
            return False

        # Create initial snapshot name
        full_snapshot_name = f"{prefix}-{vm_name}-{timestamp}"

        # Handle name length limits
        if len(full_snapshot_name) > self.max_snapshot_name_length:
            print(f"  ⚠ Snapshot name too long ({len(full_snapshot_name)} chars), truncating VM name...")

            # Calculate available space for VM name
            prefix_suffix_length = len(prefix) + 1 + 1 + 13  # "prefix-" + "-" + "YYYYMMDD-HHMM"
            max_vm_name_length = self.max_snapshot_name_length - prefix_suffix_length

            if max_vm_name_length <= 0:
                print(f"  ✗ Prefix '{prefix}' is too long. Maximum prefix length is {self.max_snapshot_name_length - 14} characters")
                return False

            # Intelligently truncate the VM name
            truncated_vm_name = self.truncate_vm_name_intelligently(vm_name, max_vm_name_length)
            full_snapshot_name = f"{prefix}-{truncated_vm_name}-{timestamp}"

            print(f"  📝 Truncated VM name: '{vm_name}' -> '{truncated_vm_name}'")

        print(f"Creating snapshot for VM {vmid}...")
        full_vm_name = self.get_full_vm_name(vmid)
        if full_vm_name:
            print(f"  Full VM Name: {full_vm_name}")
        print(f"  Clean VM Name: {vm_name}")
        print(f"  Snapshot: {full_snapshot_name} ({len(full_snapshot_name)} chars)")

        # Check VM status before snapshot creation
        print(f"  📊 Checking VM status before snapshot creation...")
        is_running, status_display, status_details = self.get_vm_status_detailed(vmid)
        print(f"  Status: {status_display}")

        # Get current configuration before snapshot
        print(f"  📋 Getting current VM configuration...")
        current_config = self.get_vm_config(vmid)
        self.display_vm_config_summary(current_config, "Current Config")

        # Determine vmstate behavior
        if self.save_vmstate and not is_running:
            print(f"  ⚠ VM {vmid} is not running - vmstate will be ignored")

        print(f"  VM State: {'WITH vmstate (RAM)' if self.save_vmstate and is_running else 'WITHOUT vmstate'}")

        try:
            # Build the qm snapshot command
            cmd = ['qm', 'snapshot', vmid, full_snapshot_name]

            # Add description to identify vmstate snapshots
            if self.save_vmstate and is_running:
                cmd.extend(['--description', f'Snapshot created with vmstate (RAM) included - {timestamp}'])
                cmd.extend(['--vmstate', '1'])
            else:
                cmd.extend(['--description', f'Snapshot created without vmstate - {timestamp}'])

            print(f"  🔄 Creating snapshot...")
            self.run_qm_command(cmd)
            print(f"  ✓ Snapshot created successfully")

            # Verify snapshot by checking its configuration
            print(f"  🔍 Verifying snapshot configuration...")
            snapshot_config = self.get_vm_config(vmid, full_snapshot_name)
            self.display_vm_config_summary(snapshot_config, "Snapshot Config")

            # Check VM status after snapshot creation
            print(f"  📊 Checking VM status after snapshot creation...")
            is_running_after, status_display_after, _ = self.get_vm_status_detailed(vmid)
            print(f"  Status: {status_display_after}")

            # Compare status before and after
            if is_running == is_running_after:
                print(f"  ✓ VM status unchanged (as expected)")
            else:
                prev = 'running' if is_running else 'stopped'
                aft = 'running' if is_running_after else 'stopped'
                print(f"  ⚠ VM status changed from {prev} to {aft}")

            return True

        except subprocess.CalledProcessError as e:
            print(f"  ✗ Failed to create snapshot: {e}")
            return False


    def list_snapshots(self, vmid: str):
        """List snapshots for a VM, sorted by date (newest first) with formatted table."""
        vm_name = self.get_vm_name(vmid) or ""
        print(f"\nSnapshots for VM {vmid} ({vm_name}) - Sorted by Date (Newest First):")
        print("=" * 90)
        header = f"{'#':<3} {'Name':<36} {'Created':<20} {'Type':<14} {'Description'}"
        print(header)
        print("-" * 90)

        snapshots = []
        current_snapshot_present = False
        try:
            result = self.run_qm_command(['qm', 'listsnapshot', vmid], check=False)
            if result.returncode != 0 or not result.stdout.strip():
                print("No snapshots found or error listing snapshots")
                print()
                return
            lines = result.stdout.strip().split('\n')
            # Skip the header (first line)
            for line in lines[1:]:
                raw = line.strip()
                # Check for 'current'
                if raw.startswith("current"):
                    current_snapshot_present = True
                    continue

                # Remove leading tree markers (e.g., `->, `-->, etc.) and parse fields
                import re as __re
                m = __re.match(r"^[^a-zA-Z0-9]*(?P<name>[^ ]+)\s+(?P<created>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*(?P<desc>.*)", raw)
                if not m:
                    continue
                name = m.group('name')
                created_str = m.group('created')
                desc = m.group('desc').strip() or ""
                # Determine type
                if 'vmstate' in desc.lower():
                    snap_type = "🧠 with vmstate"
                else:
                    snap_type = "💾 disk only"
                # Parse created datetime for sorting
                try:
                    created_dt = datetime.strptime(created_str, "%Y-%m-%d %H:%M:%S")
                except Exception:
                    continue
                snapshots.append((created_dt, name, created_str, snap_type, desc))

            # Sort descending by created_dt
            snapshots.sort(key=lambda x: x[0], reverse=True)

            # Print each snapshot
            for idx, (_, name, created_str, snap_type, desc) in enumerate(snapshots, start=1):
                # Truncate description to fit
                desc_disp = desc if len(desc) <= 30 else desc[:27] + "..."
                print(f"{idx:<3} {name:<36} {created_str:<20} {snap_type:<14} {desc_disp}")

            print("-" * 90)
            total = len(snapshots)
            print(f"Total snapshots: {total} (excluding current state)")
            if current_snapshot_present:
                print("🎯 Note: A 'current' state exists but is not counted above.")
            print("💡 Tip: #1 is the most recent snapshot")
            print()
        except Exception as e:
            print(f"Error listing snapshots: {e}")
            print()

    def get_all_vmids(self) -> List[str]:
        """Get all VM IDs from the system."""
        try:
            result = self.run_qm_command(['qm', 'list'])
            lines = result.stdout.strip().split('\n')
            vmids = []

            for line in lines[1:]:  # Skip header
                parts = line.split()
                if parts:
                    vmids.append(parts[0])

            return vmids
        except Exception as e:
            print(f"Error getting VM list: {e}")
            return []

    def validate_and_clean_prefix(self, prefix: str) -> Optional[str]:
        """Validate and clean the prefix."""
        # Remove spaces and keep only alphanumeric, hyphens, and underscores
        cleaned = re.sub(r'[^a-zA-Z0-9\-_]', '', prefix.replace(' ', ''))

        if not cleaned:
            return None

        if len(cleaned) > self.max_prefix_length:
            return None

        return cleaned

    def preview_snapshots(self, prefix: str, vmids: List[str]):
        """Show what snapshots will be created with enhanced status display."""
        print("\nSnapshot Preview:")
        print("=" * 70)
        timestamp = datetime.now().strftime('%Y%m%d-%H%M')

        running_vms = 0
        stopped_vms = 0

        for vmid in vmids:
            if self.check_vm_exists(vmid):
                vm_name = self.get_vm_name(vmid)
                is_running, status_display, _ = self.get_vm_status_detailed(vmid)

                if is_running:
                    running_vms += 1
                else:
                    stopped_vms += 1

                if vm_name:
                    snapshot_name = f"{prefix}-{vm_name}-{timestamp}"

                    # Check if name needs truncation
                    if len(snapshot_name) > self.max_snapshot_name_length:
                        prefix_suffix_length = len(prefix) + 1 + 1 + 13
                        max_vm_name_length = self.max_snapshot_name_length - prefix_suffix_length

                        if max_vm_name_length > 0:
                            truncated_vm_name = self.truncate_vm_name_intelligently(vm_name, max_vm_name_length)
                            snapshot_name = f"{prefix}-{truncated_vm_name}-{timestamp}"
                            status_text = "[TRUNCATED]"
                        else:
                            status_text = "[ERROR - Prefix too long]"
                    else:
                        status_text = ""

                    vmstate_info = ""
                    if self.save_vmstate:
                        if is_running:
                            vmstate_info = " + vmstate"
                        else:
                            vmstate_info = " (vmstate ignored - VM stopped)"

                    print(f"  VM {vmid} ({status_display}): {snapshot_name}{vmstate_info}")
                    if status_text:
                        print(f"    Status: {status_text}")
                else:
                    print(f"  VM {vmid} ({status_display}): ERROR - Could not get VM name")
            else:
                print(f"  VM {vmid}: 🔴 stopped")

        print("\n" + "=" * 70)
        print(f"Summary: {len(vmids)} VMs total")
        print(f"  🟢 Running VMs: {running_vms}")
        print(f"  🔴 Stopped VMs: {stopped_vms}")
        if self.save_vmstate:
            print(f"  🧠 VMs with vmstate: {running_vms} (only running VMs can save vmstate)")
            print(f"  📄 VMs without vmstate: {stopped_vms}")
        print("=" * 70)

    def create_snapshots_process(self, prefix: str, vmids: List[str]) -> bool:
        """Handle the complete snapshot creation process."""
        print("\nStarting snapshot process...")
        print(f"Snapshot format: {prefix}-<3RD_SECTION>-YYYYMMDD-HHMM")
        print(f"VMs to process: {' '.join(vmids)}")
        print()

        # Show preview
        self.preview_snapshots(prefix, vmids)

        # Confirmation
        try:
            confirm = input("\nProceed with creating snapshots? (y/N): ").strip().lower()
            if confirm not in ['y', 'yes']:
                print("Operation cancelled")
                return False
        except KeyboardInterrupt:
            print("\nOperation cancelled")
            return False

        # Process each VM
        success_count = 0
        fail_count = 0

        print(f"\n{'='*60}")
        print("SNAPSHOT CREATION IN PROGRESS")
        print(f"{'='*60}")

        for i, vmid in enumerate(vmids, 1):
            print(f"\n[{i}/{len(vmids)}] Processing VM {vmid}...")

            # Check if VM exists
            if not self.check_vm_exists(vmid):
                print(f"ERROR: VM {vmid} does not exist or is not accessible")
                fail_count += 1
                continue

            # Create snapshot
            if self.create_snapshot(vmid, prefix):
                success_count += 1
            else:
                fail_count += 1

            # Small delay to avoid overwhelming the system
            if i < len(vmids):  # Don't sleep after the last VM
                time.sleep(2)

        print("\n" + "=" * 60)
        print("SNAPSHOT CREATION COMPLETED!")
        print("=" * 60)
        print(f"✓ Successful: {success_count}")
        print(f"✗ Failed: {fail_count}")
        print(f"📊 Total processed: {len(vmids)}")
        if self.save_vmstate:
            print("🧠 VM state (RAM) was saved for running VMs")
        print("=" * 60)

        # Ask if user wants to see snapshot listings
        try:
            show_snapshots = input("\nShow snapshot listings for processed VMs? (y/N): ").strip().lower()
            if show_snapshots in ['y', 'yes']:
                for vmid in vmids:
                    if self.check_vm_exists(vmid):
                        self.list_snapshots(vmid)
        except KeyboardInterrupt:
            print("\nSkipping snapshot listings")

        return True

    
    def interactive_mode(self):
        """Run the script in interactive mode (VM selection → prefix → vmstate → snapshot)."""
        print("Enhanced Proxmox VM Snapshot Tool")
        print("=" * 35)

        while True:
            try:
                # 1) Show Available VMs with emoji status
                print("\nAvailable VMs:")
                header_printed = False
                try:
                    result = self.run_qm_command(['qm', 'list'])
                    lines = result.stdout.strip().split('\n')
                    for i, line in enumerate(lines):
                        if i == 0:
                            # Header line
                            print(line)
                            header_printed = True
                        else:
                            parts = line.split()
                            if len(parts) >= 6:
                                vmid, name, status, mem, bootdisk, pid = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
                                # Get emoji status
                                _, status_display, _ = self.get_vm_status_detailed(vmid)
                                # Print with columns
                                print(f"  {vmid:>4} {name:<20} {status_display:<10} {mem:>7} {bootdisk:>14} {pid:>6}")
                            else:
                                print(line)
                except Exception as e:
                    print(f"Error listing VMs: {e}")
                    # If we can't list VMs, abort this iteration
                    continue

                # 2) Prompt for VM IDs (or all)
                vm_input = input(
                    "\nEnter VM IDs (space-separated), 'q' to quit, or press Enter for all VMs: "
                ).strip()
                if vm_input.lower() in ['q', 'quit']:
                    print("Goodbye!")
                    break

                if not vm_input:
                    # If blank, use all VMIDs
                    vmids = self.get_all_vmids()
                    if not vmids:
                        print("No VMs found")
                        continue
                else:
                    vmids = vm_input.split()

                # 3) Prompt for snapshot prefix
                prefix_input = input("\nEnter snapshot prefix (default: pre-release): ").strip()
                if not prefix_input:
                    prefix_input = "pre-release"

                cleaned_prefix = self.validate_and_clean_prefix(prefix_input)
                if not cleaned_prefix:
                    if len(prefix_input) > self.max_prefix_length:
                        print(f"ERROR: Prefix too long. Maximum length is {self.max_prefix_length} characters.")
                    else:
                        print("ERROR: Invalid prefix after cleanup")
                    # restart the loop
                    continue

                # 4) Ask about saving VM state
                self.save_vmstate = self.prompt_vmstate_option()

                # 5) Run the snapshot-creation process
                self.create_snapshots_process(cleaned_prefix, vmids)

                # 6) After finishing, ask whether to continue or quit
                continue_choice = input("\nPress Enter to snapshot again or 'q' to quit: ").strip().lower()
                if continue_choice in ['q', 'quit']:
                    print("Goodbye!")
                    break

            except KeyboardInterrupt:
                print("\nGoodbye!")
                break

    def run_command_line_mode(self, prefix: str, vmids: List[str]):
        """Run the script in command line mode."""
        # Validate and clean prefix
        cleaned_prefix = self.validate_and_clean_prefix(prefix)
        if not cleaned_prefix:
            if len(prefix) > self.max_prefix_length:
                print(f"ERROR: Prefix too long. Maximum length is {self.max_prefix_length} characters.")
            else:
                print("ERROR: Invalid prefix after cleanup")
            sys.exit(1)

        if not vmids:
            # No specific VMIDs provided, use all
            vmids = self.get_all_vmids()
            if not vmids:
                print("No VMs found")
                sys.exit(1)

        # Ask about VM state saving in command line mode too
        print(f"\nCommand line mode: Creating snapshots for VMs: {' '.join(vmids)}")
        self.save_vmstate = self.prompt_vmstate_option()

        # Run the snapshot creation process
        success = self.create_snapshots_process(cleaned_prefix, vmids)
        sys.exit(0 if success else 1)


def main():
    """Main function to handle command line arguments and run the appropriate mode."""
    manager = ProxmoxSnapshotManager()

    # Check for help
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        manager.display_usage()
        sys.exit(0)

    # Check permissions
    if not manager.check_permissions():
        sys.exit(1)

    # Parse arguments
    if len(sys.argv) == 1:
        # Interactive mode
        manager.interactive_mode()
    else:
        # Command line mode - first argument is prefix, rest are VM IDs
        prefix = sys.argv[1]
        vmids = sys.argv[2:] if len(sys.argv) > 2 else []
        manager.run_command_line_mode(prefix, vmids)


if __name__ == "__main__":
    main()
