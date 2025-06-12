#!/usr/bin/env python3

"""
Proxmox VM Snapshot Rollback Script
Usage: ./pve_snapshot_rollback.py [vmid] [snapname]
If no arguments provided, it will run in interactive mode
"""

import sys
import subprocess
import re
import argparse
from datetime import datetime
from typing import List, Optional, Tuple, Dict
import time

class ProxmoxSnapshotRollback:
    """Manages Proxmox VM snapshot rollbacks with intelligent validation and safety checks."""
    
    def __init__(self):
        self.vmstate_keywords = ['vmstate', 'RAM', 'with vmstate', 'RAM included']
        
    def display_usage(self):
        """Display usage information."""
        usage_text = """
Usage: python3 pve_snapshot_rollback.py [vmid] [snapname]

Rollback VM to a specific snapshot with comprehensive safety checks and status monitoring.

Examples:
  python3 pve_snapshot_rollback.py 7201 pre-release-storage01-20250603-1430    # Direct rollback
  python3 pve_snapshot_rollback.py 7201                                        # Show snapshots for VM 7201
  python3 pve_snapshot_rollback.py                                             # Interactive mode

Features:
  - Interactive snapshot selection with detailed information
  - VM status monitoring before and after rollback
  - Snapshot configuration preview
  - VM state detection with appropriate warnings
  - Optional VM startup after rollback
  - Comprehensive safety confirmations
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
            
    def get_vm_status(self, vmid: str) -> Optional[str]:
        """Get VM status (running, stopped, etc.)."""
        try:
            result = self.run_qm_command(['qm', 'status', vmid], check=False)
            if result.returncode == 0:
                # Extract status from output like "status: running"
                for line in result.stdout.split('\n'):
                    if line.strip().startswith('status:'):
                        return line.split(':', 1)[1].strip()
            return None
        except Exception:
            return None
            
    def get_vm_name(self, vmid: str) -> Optional[str]:
        """Get VM name from qm list."""
        try:
            result = self.run_qm_command(['qm', 'list'])
            lines = result.stdout.strip().split('\n')
            
            for line in lines[1:]:  # Skip header
                parts = line.split()
                if parts and parts[0] == vmid:
                    return parts[1] if len(parts) > 1 else f"VM-{vmid}"
            return None
        except Exception:
            return None
            
    def get_snapshots(self, vmid: str) -> List[Dict[str, str]]:
        """Get list of snapshots for a VM with their details."""
        try:
            result = self.run_qm_command(['qm', 'listsnapshot', vmid], check=False)
            if result.returncode != 0:
                return []
                
            snapshots = []
            lines = result.stdout.strip().split('\n')
            
            for line in lines:
                # Skip empty lines and the "current" line
                if not line.strip() or 'You are here!' in line or line.strip() == 'current':
                    continue
                    
                # Handle lines that start with `-> (actual snapshots)
                if '`->' in line:
                    # Remove the tree characters and clean the line
                    clean_line = re.sub(r'^.*`->\s*', '', line).strip()
                    
                    if clean_line:
                        # Find the timestamp (format: YYYY-MM-DD HH:MM:SS)
                        timestamp_pattern = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'
                        timestamp_match = re.search(timestamp_pattern, clean_line)
                        
                        if timestamp_match:
                            timestamp = timestamp_match.group()
                            # Extract name (everything before timestamp)
                            name_end = clean_line.find(timestamp)
                            name = clean_line[:name_end].strip()
                            # Extract description (everything after timestamp)
                            desc_start = clean_line.find(timestamp) + len(timestamp)
                            description = clean_line[desc_start:].strip()
                            
                            if name:  # Only add if we have a valid name
                                snapshots.append({
                                    'name': name,
                                    'timestamp': timestamp,
                                    'description': description if description else 'no-description'
                                })
            
            return snapshots
        except Exception as e:
            print(f"Error getting snapshots for VM {vmid}: {e}")
            return []
            
    def check_snapshot_has_vmstate(self, description: str) -> bool:
        """Check if snapshot description indicates vmstate was saved."""
        description_lower = description.lower()
        return any(keyword.lower() in description_lower for keyword in self.vmstate_keywords)
        
    def get_snapshot_config(self, vmid: str, snapname: str) -> Optional[str]:
        """Get VM config for a specific snapshot."""
        try:
            result = self.run_qm_command(['qm', 'config', vmid, '--snapshot', snapname], check=False)
            if result.returncode == 0:
                return result.stdout
            return None
        except Exception:
            return None
            
    def display_vm_info(self, vmid: str, title: str = "VM Information"):
        """Display comprehensive VM information."""
        print(f"\n{title}")
        print("=" * len(title))
        
        # Get VM name
        vm_name = self.get_vm_name(vmid)
        if vm_name:
            print(f"VM Name: {vm_name}")
        
        # Get VM status
        status = self.get_vm_status(vmid)
        if status:
            status_icon = "🟢" if status == "running" else "🔴" if status == "stopped" else "🟡"
            print(f"Status: {status_icon} {status.upper()}")
        else:
            print("Status: ❌ Unknown/Error")
        print()
        
    def display_snapshot_info(self, vmid: str, snapname: str):
        """Display detailed snapshot information."""
        print(f"\nSnapshot Configuration Preview")
        print("=" * 35)
        
        # Get snapshot config
        config = self.get_snapshot_config(vmid, snapname)
        if config:
            # Show key configuration details
            print(f"Snapshot: {snapname}")
            
            # Extract key config items
            config_lines = config.split('\n')
            important_configs = ['memory:', 'cores:', 'sockets:', 'bootdisk:', 'net0:', 'scsi0:', 'ide2:']
            
            for line in config_lines:
                line = line.strip()
                if any(line.startswith(cfg) for cfg in important_configs):
                    print(f"  {line}")
                    
            print()
        else:
            print(f"❌ Could not retrieve configuration for snapshot: {snapname}\n")
            

    def display_snapshots_list(self, vmid: str) -> List[Dict[str, str]]:
        """Display formatted, sorted list of snapshots (newest first) with numbered table."""
        snapshots = self.get_snapshots(vmid)

        if not snapshots:
            print("❌ No snapshots found for this VM")
            return []

        vm_name = self.get_vm_name(vmid) or ""
        print(f"Snapshots for VM {vmid} ({vm_name}) - Sorted by Date (Newest First):")
        print("=" * 90)
        header = f"{'#':<3} {'Name':<36} {'Created':<20} {'Type':<14} {'Description'}"
        print(header)
        print("-" * 90)

        parsed_list = []
        for snap in snapshots:
            name = snap['name']
            created_str = snap['timestamp']
            desc = snap['description']
            has_vmstate = self.check_snapshot_has_vmstate(desc)
            snap_type = "🧠 with vmstate" if has_vmstate else "💾 disk only"
            try:
                dt = datetime.strptime(created_str, "%Y-%m-%d %H:%M:%S")
            except:
                continue
            parsed_list.append((dt, name, created_str, snap_type, desc))

        parsed_list.sort(key=lambda x: x[0], reverse=True)

        for idx, (_, name, created_str, snap_type, desc) in enumerate(parsed_list, start=1):
            desc_disp = desc if len(desc) <= 30 else desc[:27] + "..."
            print(f"{idx:<3} {name:<36} {created_str:<20} {snap_type:<14} {desc_disp}")

        # Check for 'current' state in raw snapshots
        raw = [snap for snap in snapshots if snap.get('name', '') == 'current']
        if raw:
            print("-" * 90)
            print(f"--- current{' ' * 29}---{' ' * 12}🎯 current state You are here!")
        print("-" * 90)
        total = len(parsed_list)
        print(f"Total snapshots: {total} (excluding current state)")
        print("💡 Tip: #1 is the most recent snapshot")
        print()
        return [{'name': item[1], 'timestamp': item[2], 'description': item[4]} for item in parsed_list]

    def get_vm_status_from_list(self, vmid: str) -> Tuple[bool, str]:
        """Get VM status efficiently from qm list output."""
        try:
            result = self.run_qm_command(['qm', 'list'])
            lines = result.stdout.strip().split('\n')
            
            for line in lines[1:]:  # Skip header
                parts = line.split()
                if parts and parts[0] == vmid:
                    if len(parts) >= 3:
                        status = parts[2].lower()
                        if status == 'running':
                            return True, "🟢 running"
                        elif status == 'stopped':
                            return False, "🔴 stopped"
                        else:
                            return False, f"⚠️ {status}"
            return False, "❌ not found"
        except Exception:
            return False, "❌ error"
            
    def rollback_snapshot(self, vmid: str, snapname: str) -> bool:
        """Perform the actual snapshot rollback."""
        print(f"\n{'='*60}")
        print("PERFORMING SNAPSHOT ROLLBACK")
        print(f"{'='*60}")
        print(f"VM ID: {vmid}")
        print(f"Snapshot: {snapname}")
        print("⚠️  This operation will revert the VM to the snapshot state!")
        print(f"{'='*60}")
        
        try:
            # Execute rollback
            print("🔄 Executing rollback command...")
            cmd = ['qm', 'rollback', vmid, snapname]
            self.run_qm_command(cmd, capture_output=False)
            print("✅ Rollback completed successfully!")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Rollback failed: {e}")
            return False
            
    def prompt_start_vm(self, vmid: str) -> bool:
        """Prompt user to start VM if it's stopped after rollback."""
        try:
            choice = input(f"\nVM {vmid} is stopped. Would you like to start it? (y/N): ").strip().lower()
            if choice in ['y', 'yes']:
                print("🚀 Starting VM...")
                try:
                    self.run_qm_command(['qm', 'start', vmid], capture_output=False)
                    print("✅ VM started successfully!")
                    return True
                except subprocess.CalledProcessError as e:
                    print(f"❌ Failed to start VM: {e}")
                    return False
            else:
                print("VM remains stopped")
                return False
        except KeyboardInterrupt:
            print("\nSkipping VM start")
            return False
            
    def rollback_process(self, vmid: str, snapname: str) -> bool:
        """Handle the complete rollback process with all safety checks."""
        
        # 1. Check VM exists
        if not self.check_vm_exists(vmid):
            print(f"❌ ERROR: VM {vmid} does not exist or is not accessible")
            return False
            
        # 2. Display VM info before rollback
        self.display_vm_info(vmid, "VM Status BEFORE Rollback")
        
        # 3. List and validate snapshot
        snapshots = self.get_snapshots(vmid)
        if not snapshots:
            print("❌ No snapshots found for this VM")
            return False
            
        # Find the snapshot
        target_snapshot = None
        for snapshot in snapshots:
            if snapshot['name'] == snapname:
                target_snapshot = snapshot
                break
                
        if not target_snapshot:
            print(f"❌ Snapshot '{snapname}' not found")
            return False
            
        # 4. Display snapshot configuration
        self.display_snapshot_info(vmid, snapname)
        
        # 5. Check vmstate and display warnings
        has_vmstate = self.check_snapshot_has_vmstate(target_snapshot['description'])
        
        print("⚠️  ROLLBACK WARNINGS")
        print("=" * 20)
        if has_vmstate:
            print("🧠 This snapshot includes VM state (RAM)")
            print("📝 After rollback, the VM will AUTOMATICALLY START")
            print("   and resume from the exact point when snapshot was taken")
        else:
            print("💾 This snapshot does NOT include VM state (RAM)")
            print("📝 After rollback, the VM will remain STOPPED")
            print("   You will need to manually start it if desired")
        print()
        
        # 6. Final confirmation
        print(f"You are about to rollback VM {vmid} to snapshot: {snapname}")
        print(f"Snapshot created: {target_snapshot['timestamp']}")
        print(f"VM state included: {'YES' if has_vmstate else 'NO'}")
        print("\n❗ This action cannot be undone!")
        
        try:
            confirm = input("\nProceed with rollback? (y/N): ").strip().lower()
            if confirm not in ['y', 'yes']:
                print("❌ Rollback cancelled")
                return False
        except KeyboardInterrupt:
            print("\n❌ Rollback cancelled")
            return False
            
        # 7. Perform rollback
        if not self.rollback_snapshot(vmid, snapname):
            return False
            
        # 8. Check status after rollback
        print("\n⏳ Waiting for rollback to complete...")
        time.sleep(3)  # Give some time for the rollback to settle
        
        self.display_vm_info(vmid, "VM Status AFTER Rollback")
        
        # 9. Handle VM startup if needed
        final_status = self.get_vm_status(vmid)
        if final_status == "stopped" and not has_vmstate:
            self.prompt_start_vm(vmid)
        elif final_status == "running" and has_vmstate:
            print("✅ VM automatically started due to vmstate restoration")
        elif final_status == "running":
            print("✅ VM is running")
        
        return True
        
    def interactive_mode(self):
        """Run the script in interactive mode."""
        print("Proxmox VM Snapshot Rollback Tool")
        print("=" * 33)
        
        while True:
            try:
                # Show VM list
                print("\nAvailable VMs:")
                header_printed = False
                try:
                    result = self.run_qm_command(['qm', 'list'])
                    lines = result.stdout.strip().split('\n')
                    vm_count = 0
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
                                _, status_display = self.get_vm_status_from_list(vmid)
                                # Print with columns
                                print(f"  {vmid:>4} {name:<20} {status_display:<10} {mem:>7} {bootdisk:>14} {pid:>6}")
                                vm_count += 1
                            else:
                                print(line)
                    print(f"  Total VMs: {vm_count}")
                except Exception as e:
                    print(f"Error listing VMs: {e}")
                    # If we can't list VMs, abort this iteration
                    continue
                
                # Prompt for VM ID
                vmid_input = input("\nEnter VM ID to rollback (or 'q' to quit): ").strip()
                if vmid_input.lower() in ['q', 'quit']:
                    print("Goodbye!")
                    break
                # Validate VM exists
                if not self.check_vm_exists(vmid_input):
                    print(f"❌ VM {vmid_input} does not exist or is not accessible")
                    continue
                
                # Show snapshots for the VM
                snapshots = self.display_snapshots_list(vmid_input)
                if not snapshots:
                    continue
                
                # Prompt for snapshot selection
                try:
                    choice = input("Select snapshot number to rollback (or 'q' to go back): ").strip()
                    if choice.lower() in ['q', 'quit']:
                        continue
                    snapshot_index = int(choice) - 1
                    if 0 <= snapshot_index < len(snapshots):
                        selected_snapshot = snapshots[snapshot_index]
                        self.rollback_process(vmid_input, selected_snapshot['name'])
                    else:
                        print("❌ Invalid selection")
                        continue
                except ValueError:
                    print("❌ Please enter a valid number")
                    continue
                
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break

    def vm_specific_mode(self, vmid: str):
        """Show snapshots for a specific VM and allow selection."""
        if not self.check_vm_exists(vmid):
            print(f"❌ ERROR: VM {vmid} does not exist or is not accessible")
            sys.exit(1)
            
        self.display_vm_info(vmid, f"VM {vmid} Information")
        
        snapshots = self.display_snapshots_list(vmid)
        if not snapshots:
            sys.exit(1)
            
        try:
            choice = input("\nSelect snapshot number to rollback (or 'q' to quit): ").strip()
            
            if choice.lower() in ['q', 'quit']:
                print("Operation cancelled")
                sys.exit(0)
                
            snapshot_index = int(choice) - 1
            if 0 <= snapshot_index < len(snapshots):
                selected_snapshot = snapshots[snapshot_index]
                success = self.rollback_process(vmid, selected_snapshot['name'])
                sys.exit(0 if success else 1)
            else:
                print("❌ Invalid selection")
                sys.exit(1)
                
        except ValueError:
            print("❌ Please enter a valid number")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\nOperation cancelled")
            sys.exit(0)
            
    def direct_rollback_mode(self, vmid: str, snapname: str):
        """Perform direct rollback with specified VM and snapshot."""
        success = self.rollback_process(vmid, snapname)
        sys.exit(0 if success else 1)


def main():
    """Main function to handle command line arguments and run the appropriate mode."""
    rollback_manager = ProxmoxSnapshotRollback()
    
    # Check for help
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        rollback_manager.display_usage()
        sys.exit(0)
        
    # Check permissions
    if not rollback_manager.check_permissions():
        sys.exit(1)
        
    # Parse arguments
    if len(sys.argv) == 1:
        # Interactive mode
        rollback_manager.interactive_mode()
    elif len(sys.argv) == 2:
        # VM-specific mode
        vmid = sys.argv[1]
        rollback_manager.vm_specific_mode(vmid)
    elif len(sys.argv) == 3:
        # Direct rollback mode
        vmid = sys.argv[1]
        snapname = sys.argv[2]
        rollback_manager.direct_rollback_mode(vmid, snapname)
    else:
        print("❌ Too many arguments. Use --help for usage information.")
        sys.exit(1)


if __name__ == "__main__":
    main()