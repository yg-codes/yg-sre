#!/usr/bin/env python3

"""
Enhanced Proxmox VM Snapshot Deletion Script
Usage: ./pve_snapshot_delete.py [vmid] [snapshot_name]

Enhancements:
- Shows VM status with colored indicators (🟢 running 🔴 stopped)
- Checks VM status before and after snapshot deletion
- Displays snapshot config before deletion
- Verifies current config after deletion
"""

import sys
import subprocess
import time
import re
from datetime import datetime
from typing import List, Optional, Tuple, Dict

class ProxmoxSnapshotDeleter:
    """Manages Proxmox VM snapshot deletion with interactive interface and enhanced checking."""
    
    def __init__(self):
        pass
        
    def display_usage(self):
        """Display usage information."""
        usage_text = """
Usage: python3 pve_snapshot_delete.py [vmid] [snapshot_name]

Examples:
  python3 pve_snapshot_delete.py 7302 b4-mbr-2-gpt-conversion
  python3 pve_snapshot_delete.py 7302
  python3 pve_snapshot_delete.py

Features:
  - Interactive mode with VM selection
  - VM status checking with colored indicators (🟢 running 🔴 stopped)
  - Configuration verification before and after deletion
  - Bulk deletion support for all snapshots
  - Safe confirmation prompts
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
            
    def get_vm_status_detailed(self, vmid: str) -> Tuple[bool, str, str]:
        """Get detailed VM status with colored indicator - used for operations."""
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
                return False, "❌ error", f"Failed to get status: {result.stderr}"
        except Exception as e:
            return False, "❌ error", f"Exception: {str(e)}"
            
    def check_vm_exists(self, vmid: str) -> bool:
        """Check if a VM exists and is accessible."""
        try:
            result = self.run_qm_command(['qm', 'status', vmid], check=False)
            if result.returncode != 0:
                print(f"ERROR: VM {vmid} does not exist")
                return False
            return True
        except Exception:
            print(f"ERROR: VM {vmid} does not exist")
            return False
            
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
        """Get VM name from qm list."""
        try:
            result = self.run_qm_command(['qm', 'list'])
            lines = result.stdout.strip().split('\n')
            
            for line in lines[1:]:  # Skip header
                parts = line.split()
                if parts and parts[0] == vmid:
                    return parts[1] if len(parts) > 1 else ""
            return None
        except Exception as e:
            print(f"Error getting VM name for {vmid}: {e}")
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
            
    def get_vm_snapshots_array(self, vmid: str) -> List[str]:
        """Get list of snapshot names for a VM (for compatibility)."""
        snapshots = self.get_snapshots(vmid)
        return [snap['name'] for snap in snapshots]
            
    def check_snapshot_has_vmstate(self, description: str) -> bool:
        """Check if snapshot description indicates vmstate was saved."""
        vmstate_keywords = ['vmstate', 'RAM', 'with vmstate', 'RAM included']
        description_lower = description.lower()
        return any(keyword.lower() in description_lower for keyword in vmstate_keywords)
        
    def list_vm_snapshots(self, vmid: str) -> bool:
        """List snapshots for a VM in formatted table, sorted by date (newest first)."""
        snapshots = self.get_snapshots(vmid)

        if not snapshots:
            print("❌ No snapshots found for this VM")
            return False

        vm_name = self.get_vm_name(vmid) or ""
        print(f"\nSnapshots for VM {vmid} ({vm_name}) - Sorted by Date (Newest First):")
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

        print("-" * 90)
        total = len(parsed_list)
        print(f"Total snapshots: {total} (excluding current state)")
        print("💡 Tip: #1 is the most recent snapshot")
        print()
        return True
            
    def delete_snapshot(self, vmid: str, snapshot_name: str) -> bool:
        """Delete a specific snapshot with enhanced status and config checking."""
        vm_name = self.get_vm_name(vmid)
        
        print(f"\n{'='*60}")
        print(f"DELETING SNAPSHOT: {snapshot_name}")
        print(f"FROM VM: {vmid} ({vm_name})")
        print(f"{'='*60}")
        
        # Check VM status before deletion
        print(f"📊 Checking VM status before snapshot deletion...")
        is_running_before, status_display_before, _ = self.get_vm_status_detailed(vmid)
        print(f"  Status: {status_display_before}")
        
        # Get snapshot configuration before deletion
        print(f"📋 Getting snapshot configuration before deletion...")
        snapshot_config = self.get_vm_config(vmid, snapshot_name)
        self.display_vm_config_summary(snapshot_config, f"Snapshot '{snapshot_name}' Config")
        
        try:
            print(f"🗑️  Deleting snapshot...")
            self.run_qm_command(['qm', 'delsnapshot', vmid, snapshot_name])
            print(f"  ✓ Snapshot deleted successfully")
            
            # Check VM status after deletion
            print(f"📊 Checking VM status after snapshot deletion...")
            is_running_after, status_display_after, _ = self.get_vm_status_detailed(vmid)
            print(f"  Status: {status_display_after}")
            
            # Compare status before and after
            if is_running_before == is_running_after:
                print(f"  ✓ VM status unchanged (as expected)")
            else:
                print(f"  ⚠ VM status changed from {'running' if is_running_before else 'stopped'} to {'running' if is_running_after else 'stopped'}")
            
            # Get current configuration after deletion
            print(f"🔍 Verifying current VM configuration after deletion...")
            current_config = self.get_vm_config(vmid)
            self.display_vm_config_summary(current_config, "Current VM Config")
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"  ✗ Failed to delete snapshot: {e}")
            return False
            
    def confirm_deletion(self, vmid: str, snapshot_name: str) -> bool:
        """Confirm snapshot deletion with user."""
        vm_name = self.get_vm_name(vmid)
        is_running, status_display = self.get_vm_status_from_list(vmid)
        
        print(f"\n{'='*60}")
        print("⚠️  SNAPSHOT DELETION CONFIRMATION")
        print(f"{'='*60}")
        print(f"VM: {vmid} ({vm_name}) - Status: {status_display}")
        print(f"Snapshot: {snapshot_name}")
        print(f"\n❌ This action cannot be undone!")
        print(f"{'='*60}")
        
        try:
            confirm = input("Are you sure you want to delete this snapshot? (y/N): ").strip().lower()
            if confirm in ['y', 'yes']:
                return True
            else:
                print("Deletion cancelled")
                return False
        except KeyboardInterrupt:
            print("\nDeletion cancelled")
            return False
            
    def show_vm_menu(self):
        """Display available VMs with enhanced formatting and status indicators."""
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
                        _, status_display = self.get_vm_status_from_list(vmid)
                        # Print with columns
                        print(f"  {vmid:>4} {name:<20} {status_display:<10} {mem:>7} {bootdisk:>14} {pid:>6}")
                    else:
                        print(line)
        except Exception as e:
            print(f"Error listing VMs: {e}")
            
    def interactive_snapshot_selection(self, vmid: str) -> bool:
        """Interactive snapshot selection and deletion with unified display."""
        snapshots_detailed = self.get_snapshots(vmid)
        
        if not snapshots_detailed:
            print(f"No snapshots found for VM {vmid}")
            return False

        vm_name = self.get_vm_name(vmid) or ""
        print(f"\nSnapshots for VM {vmid} ({vm_name}) - Sorted by Date (Newest First):")
        print("=" * 90)
        header = f"{'#':<3} {'Name':<36} {'Created':<20} {'Type':<14} {'Description'}"
        print(header)
        print("-" * 90)

        # Parse and sort snapshots
        parsed_list = []
        for snap in snapshots_detailed:
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

        # Display snapshots with selection numbers
        for idx, (_, name, created_str, snap_type, desc) in enumerate(parsed_list, start=1):
            desc_disp = desc if len(desc) <= 30 else desc[:27] + "..."
            print(f"[{idx}] {name:<36} {created_str:<20} {snap_type:<14} {desc_disp}")

        print("[a] Delete ALL snapshots")
        print("[q] Quit/Back")
        print("-" * 90)
        total = len(parsed_list)
        print(f"Total snapshots: {total} (excluding current state)")
        print("💡 Tip: #1 is the most recent snapshot")
        print()
        
        while True:
            try:
                choice = input("Select snapshot to delete (number, 'a' for all, 'q' to quit): ").strip().lower()
                
                if choice in ['q', 'quit']:
                    print("Goodbye!")
                    sys.exit(0)
                elif choice in ['a', 'all']:
                    vm_name = self.get_vm_name(vmid)
                    is_running, status_display = self.get_vm_status_from_list(vmid)
                    
                    print(f"\n{'='*60}")
                    print("⚠️  BULK DELETION WARNING")
                    print(f"{'='*60}")
                    print(f"VM: {vmid} ({vm_name}) - Status: {status_display}")
                    print(f"This will delete ALL {len(parsed_list)} snapshots!")
                    print("This action cannot be undone!")
                    print(f"{'='*60}")
                    
                    try:
                        confirm_all = input("Are you absolutely sure? (y/N): ").strip().lower()
                        if confirm_all in ['y', 'yes']:
                            success_count = 0
                            fail_count = 0
                            
                            print(f"\n🗑️  Starting bulk deletion of {len(parsed_list)} snapshots...")
                            
                            for i, (_, snapshot_name, _, _, _) in enumerate(parsed_list, 1):
                                print(f"\n[{i}/{len(parsed_list)}] Processing snapshot: {snapshot_name}")
                                if self.delete_snapshot(vmid, snapshot_name):
                                    success_count += 1
                                else:
                                    fail_count += 1
                                
                                # Small delay between deletions
                                if i < len(parsed_list):
                                    time.sleep(2)
                                
                            print(f"\n{'='*60}")
                            print("BULK DELETION COMPLETED")
                            print(f"{'='*60}")
                            print(f"✓ Successful: {success_count}")
                            print(f"✗ Failed: {fail_count}")
                            print(f"📊 Total processed: {len(parsed_list)}")
                            print(f"{'='*60}")
                    except KeyboardInterrupt:
                        print("\nBulk deletion cancelled")
                    return True
                elif choice.isdigit():
                    choice_num = int(choice)
                    if 1 <= choice_num <= len(parsed_list):
                        selected_snapshot = parsed_list[choice_num - 1][1]  # Get snapshot name from tuple
                        if self.confirm_deletion(vmid, selected_snapshot):
                            self.delete_snapshot(vmid, selected_snapshot)
                        return True
                    else:
                        print(f"Invalid selection. Please choose a number between 1 and {len(parsed_list)}")
                else:
                    print("Invalid input. Please enter a number, 'a', or 'q'")
                    
            except KeyboardInterrupt:
                print("\nOperation cancelled")
                return False
                
    def interactive_mode(self):
        """Run in interactive mode."""
        print("Enhanced Proxmox VM Snapshot Deletion Tool")
        print("=" * 45)
        
        while True:
            try:
                self.show_vm_menu()
                vmid = input("Enter VM ID to manage snapshots (or 'q' to quit): ").strip()
                
                if vmid.lower() in ['q', 'quit']:
                    print("Goodbye!")
                    break
                elif vmid.isdigit():
                    if self.check_vm_exists(vmid):
                        if self.list_vm_snapshots(vmid):
                            self.interactive_snapshot_selection(vmid)
                else:
                    print("Invalid input. Please enter a valid VM ID or 'q' to quit")
                    
                print()
                try:
                    input("Press Enter to continue...")
                except KeyboardInterrupt:
                    print("\nGoodbye!")
                    break
                    
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
                
    def run_with_vmid_only(self, vmid: str):
        """Run with only VM ID provided."""
        if self.check_vm_exists(vmid):
            if self.list_vm_snapshots(vmid):
                self.interactive_snapshot_selection(vmid)
            else:
                print(f"No snapshots to delete for VM {vmid}")
                
    def run_with_vmid_and_snapshot(self, vmid: str, snapshot_name: str):
        """Run with both VM ID and snapshot name provided."""
        if not self.check_vm_exists(vmid):
            return
            
        snapshots = self.get_vm_snapshots_array(vmid)
        
        if snapshot_name not in snapshots:
            print(f"ERROR: Snapshot '{snapshot_name}' not found on VM {vmid}")
            print("\nAvailable snapshots:")
            self.list_vm_snapshots(vmid)
            sys.exit(1)
            
        if self.confirm_deletion(vmid, snapshot_name):
            self.delete_snapshot(vmid, snapshot_name)
            
    def main(self, args: List[str]):
        """Main function to handle different argument scenarios."""
        # Check permissions first
        if not self.check_permissions():
            sys.exit(1)
            
        argc = len(args)
        
        if argc == 0:
            # Interactive mode
            self.interactive_mode()
        elif argc == 1:
            # VM ID only
            vmid = args[0]
            self.run_with_vmid_only(vmid)
        elif argc == 2:
            # VM ID and snapshot name
            vmid = args[0]
            snapshot_name = args[1]
            self.run_with_vmid_and_snapshot(vmid, snapshot_name)
        else:
            print("ERROR: Too many arguments")
            self.display_usage()
            sys.exit(1)


def main():
    """Entry point for the script."""
    deleter = ProxmoxSnapshotDeleter()
    
    # Check for help
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        deleter.display_usage()
        sys.exit(0)
        
    # Run with command line arguments (excluding script name)
    deleter.main(sys.argv[1:])


if __name__ == "__main__":
    main()