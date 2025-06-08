#!/usr/bin/env python3

"""
Proxmox VM Snapshot Interactive Manager Script
Usage: ./pve_snapshot_manager_interactive.py

Interactive snapshot management tool that allows users to:
- View all snapshots across VMs in a sorted table format
- Select specific snapshots for deletion
- Perform bulk deletion operations per VM
- View snapshots sorted by creation time per VM

Based on pve_snapshot_delete_api.py with enhanced functionality
"""

import sys
import json
import re
import time
import getpass
from datetime import datetime
from typing import List, Optional, Tuple, Dict, Any
from urllib.parse import urljoin
import urllib3

# Suppress SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not found. Install with: pip install requests")
    sys.exit(1)

class ProxmoxAPIError(Exception):
    """Custom exception for Proxmox API errors."""
    def __init__(self, message: str, status_code: int = None, response_data: Dict = None):
        self.message = message
        self.status_code = status_code
        self.response_data = response_data
        super().__init__(self.message)

class ProxmoxAPI:
    """Simple Proxmox API client without external dependencies."""
    
    def __init__(self, host: str, user: str, password: str = None, token_name: str = None, 
                 token_value: str = None, verify_ssl: bool = False, port: int = 8006):
        self.host = host
        self.port = port
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
        self.base_url = f"https://{host}:{port}/api2/json"
        
        # Authenticate
        if token_name and token_value:
            self._auth_token(user, token_name, token_value)
        else:
            if not password:
                password = getpass.getpass(f"Password for {user}: ")
            self._auth_password(user, password)
    
    def _auth_password(self, user: str, password: str):
        """Authenticate using username/password."""
        auth_data = {
            'username': user,
            'password': password
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/access/ticket",
                data=auth_data,
                timeout=10
            )
            response.raise_for_status()
            
            result = response.json()
            if result.get('data'):
                ticket = result['data']['ticket']
                csrf_token = result['data']['CSRFPreventionToken']
                
                self.session.headers.update({
                    'Cookie': f'PVEAuthCookie={ticket}',
                    'CSRFPreventionToken': csrf_token
                })
            else:
                raise ProxmoxAPIError("Authentication failed: No ticket received")
                
        except requests.exceptions.RequestException as e:
            raise ProxmoxAPIError(f"Authentication failed: {str(e)}")
    
    def _auth_token(self, user: str, token_name: str, token_value: str):
        """Authenticate using API token."""
        self.session.headers.update({
            'Authorization': f'PVEAPIToken={user}!{token_name}={token_value}'
        })
    
    def _request(self, method: str, path: str, data: Dict = None, params: Dict = None) -> Dict:
        """Make API request."""
        url = urljoin(self.base_url + '/', path.lstrip('/'))
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=30)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=data, params=params, timeout=60)
            elif method.upper() == 'PUT':
                response = self.session.put(url, data=data, params=params, timeout=60)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, params=params, timeout=30)
            else:
                raise ProxmoxAPIError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            result = response.json()
            
            if 'data' in result:
                return result['data']
            else:
                return result
                
        except requests.exceptions.Timeout:
            raise ProxmoxAPIError(f"Request timeout for {method} {path}")
        except requests.exceptions.RequestException as e:
            try:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get('errors', {}) or str(e)
            except:
                error_msg = str(e)
            raise ProxmoxAPIError(f"API request failed: {error_msg}", response.status_code if 'response' in locals() else None)

class ProxmoxSnapshotManager:
    """Manages Proxmox VM snapshots using API with intelligent naming and validation."""
    
    def __init__(self):
        self.max_snapshot_name_length = 40
        self.max_prefix_length = 25
        self.save_vmstate = False
        self.api = None
        self.nodes_cache = {}
        self.vmstate_keywords = ['vmstate', 'RAM', 'with vmstate', 'RAM included', 'with VM state', 'VM state included']
        
    def connect_to_proxmox(self) -> bool:
        """Establish connection to Proxmox API."""
        import os
        
        # Try environment variables first
        host = os.getenv('PVE_HOST')
        user = os.getenv('PVE_USER') 
        token_name = os.getenv('PVE_TOKEN_NAME')
        token_value = os.getenv('PVE_TOKEN_VALUE')
        
        # Debug: Show what environment variables are found
        print("🔍 Checking environment variables...")
        print(f"   PVE_HOST: {'✅ Set' if host else '❌ Not set'}")
        print(f"   PVE_USER: {'✅ Set' if user else '❌ Not set'}")
        print(f"   PVE_TOKEN_NAME: {'✅ Set' if token_name else '❌ Not set'}")
        print(f"   PVE_TOKEN_VALUE: {'✅ Set' if token_value else '❌ Not set'}")
        
        if host and user and token_name and token_value:
            print(f"🔗 Connecting to Proxmox API at {host} using token authentication...")
            try:
                self.api = ProxmoxAPI(host, user, token_name=token_name, token_value=token_value)
                print("✅ Connected successfully using API token")
                return True
            except ProxmoxAPIError as e:
                print(f"❌ Token authentication failed: {e.message}")
                print("🔄 Falling back to password authentication...")
        else:
            print("⚠️  Missing environment variables, using interactive authentication")
        
        # Fall back to interactive authentication
        print("🔗 Interactive Proxmox API Connection")
        print("=" * 40)
        
        try:
            if not host:
                host = input("Proxmox host (IP or FQDN): ").strip()
            if not user:
                user = input("Username (user@realm): ").strip()
            
            if not host or not user:
                print("❌ Host and username are required")
                return False
            
            print(f"🔗 Connecting to {host}...")
            self.api = ProxmoxAPI(host, user)
            print("✅ Connected successfully")
            return True
            
        except ProxmoxAPIError as e:
            print(f"❌ Connection failed: {e.message}")
            return False
        except KeyboardInterrupt:
            print("\n❌ Connection cancelled")
            return False
    
    def get_nodes(self) -> List[Dict]:
        """Get all nodes in the cluster."""
        if not self.nodes_cache:
            try:
                nodes = self.api._request('GET', '/nodes')
                self.nodes_cache = {node['node']: node for node in nodes}
            except ProxmoxAPIError as e:
                print(f"Error getting nodes: {e.message}")
                return []
        return list(self.nodes_cache.values())
    
    def find_vm_node(self, vmid: str) -> Optional[str]:
        """Find which node a VM is on."""
        nodes = self.get_nodes()
        for node in nodes:
            try:
                self.api._request('GET', f'/nodes/{node["node"]}/qemu/{vmid}/status/current')
                return node['node']
            except ProxmoxAPIError:
                continue
        return None
    
    def get_all_vms(self) -> List[Dict]:
        """Get all VMs from all nodes."""
        all_vms = []
        nodes = self.get_nodes()
        
        for node in nodes:
            try:
                vms = self.api._request('GET', f'/nodes/{node["node"]}/qemu')
                for vm in vms:
                    vm['node'] = node['node']
                    all_vms.append(vm)
            except ProxmoxAPIError as e:
                print(f"⚠️  Warning: Could not get VMs from node {node['node']}: {e.message}")
        
        return all_vms
    
    def get_vm_info(self, vmid: str) -> Optional[Dict]:
        """Get comprehensive VM information."""
        node = self.find_vm_node(vmid)
        if not node:
            return None
        
        try:
            # Get current status
            status = self.api._request('GET', f'/nodes/{node}/qemu/{vmid}/status/current')
            
            # Get configuration
            config = self.api._request('GET', f'/nodes/{node}/qemu/{vmid}/config')
            
            # Combine information
            vm_info = {
                'vmid': vmid,
                'node': node,
                'name': status.get('name', f'vm-{vmid}'),
                'status': status.get('status', 'unknown'),
                'running': status.get('status') == 'running',
                'cpu_usage': status.get('cpu', 0) * 100,
                'memory_usage': status.get('mem', 0),
                'memory_max': status.get('maxmem', 0),
                'uptime': status.get('uptime', 0),
                'pid': status.get('pid'),
                'config': config
            }
            
            return vm_info
            
        except ProxmoxAPIError:
            return None
    
    def get_vm_status_detailed(self, vmid: str) -> Tuple[bool, str, str]:
        """Get detailed VM status with colored indicator."""
        vm_info = self.get_vm_info(vmid)
        
        if not vm_info:
            return False, "❌ error", "VM not found or inaccessible"
        
        is_running = vm_info['running']
        
        if is_running:
            cpu_usage = vm_info['cpu_usage']
            memory_usage = vm_info['memory_usage'] // (1024**2)  # MB
            status_display = f"🟢 running (CPU: {cpu_usage:.1f}%, RAM: {memory_usage}MB)"
            status_details = f"Node: {vm_info['node']}, PID: {vm_info.get('pid', 'N/A')}, Uptime: {vm_info['uptime']}s"
        else:
            status_display = "🔴 stopped"
            status_details = f"Node: {vm_info['node']}"
        
        return is_running, status_display, status_details
    
    def get_vm_name(self, vmid: str) -> Optional[str]:
        """Get VM name and extract the clean name according to rules."""
        vm_info = self.get_vm_info(vmid)
        if not vm_info:
            return None
        
        full_name = vm_info['name']
        
        # Extract the 3rd section separated by hyphens
        name_parts = full_name.split('-')
        if len(name_parts) >= 3:
            clean_name = '-'.join(name_parts[2:])
        else:
            # Fall back to removing common prefixes
            clean_name = full_name
            if clean_name.startswith('xxx-dev-'):
                clean_name = clean_name[8:]
            elif clean_name.startswith('xxx-prod-'):
                clean_name = clean_name[9:]
        
        return clean_name if clean_name else full_name
    
    def get_full_vm_name(self, vmid: str) -> Optional[str]:
        """Get the full VM name."""
        vm_info = self.get_vm_info(vmid)
        return vm_info['name'] if vm_info else None
    
    def get_snapshots(self, vmid: str) -> List[Dict]:
        """Get list of snapshots for a VM."""
        node = self.find_vm_node(vmid)
        if not node:
            return []
        
        try:
            snapshots = self.api._request('GET', f'/nodes/{node}/qemu/{vmid}/snapshot')
            return snapshots
        except ProxmoxAPIError:
            return []
    
    def monitor_task(self, node: str, task_id: str, description: str = "Task") -> bool:
        """Monitor a Proxmox task until completion."""
        print(f"  🔄 {description} started (Task: {task_id})")
        
        start_time = time.time()
        last_status = ""
        
        while True:
            try:
                task_status = self.api._request('GET', f'/nodes/{node}/tasks/{task_id}/status')
                
                status = task_status.get('status', 'unknown')
                
                if status != last_status:
                    if status == 'running':
                        elapsed = int(time.time() - start_time)
                        print(f"  ⏳ {description} in progress... ({elapsed}s)")
                    last_status = status
                
                if status == 'stopped':
                    exit_status = task_status.get('exitstatus')
                    if exit_status == 'OK':
                        elapsed = int(time.time() - start_time)
                        print(f"  ✅ {description} completed successfully ({elapsed}s)")
                        return True
                    else:
                        print(f"  ❌ {description} failed: {exit_status}")
                        return False
                        
                time.sleep(2)
                
            except ProxmoxAPIError as e:
                print(f"  ⚠️  Error monitoring task: {e.message}")
                return False
            except KeyboardInterrupt:
                print(f"\n  ⏸️  Task monitoring interrupted. Task {task_id} may still be running.")
                return False
    
    def check_snapshot_has_vmstate(self, description: str) -> bool:
        """Check if snapshot description indicates vmstate was saved."""
        if not description:
            return False
        description_lower = description.lower()
        return any(keyword.lower() in description_lower for keyword in self.vmstate_keywords)
    
    def display_vm_list_interactive(self):
        """Display enhanced VM list for interactive mode with snapshot counts."""
        print("\nAvailable VMs:")
        print("=" * 100)
        print(f"{'VMID':<8} {'Name':<25} {'Status':<20} {'Node':<12} {'Snapshots'}")
        print("-" * 100)
        
        all_vms = self.get_all_vms()
        if not all_vms:
            print("No VMs found")
            return
        
        for vm in sorted(all_vms, key=lambda x: int(x['vmid'])):
            vmid = vm['vmid']
            name = vm.get('name', f'vm-{vmid}')[:24]
            
            # Get detailed status
            vm_info = self.get_vm_info(str(vmid))
            if vm_info:
                if vm_info['running']:
                    status = "🟢 running"
                else:
                    status = "🔴 stopped"
                node = vm_info['node']
            else:
                status = "❌ error"
                node = vm.get('node', 'unknown')
            
            # Count snapshots (excluding 'current' state)
            snapshots = self.get_snapshots(str(vmid))
            snapshot_count = len([s for s in snapshots if s.get('name') != 'current'])
            snapshot_info = f"{snapshot_count} snapshots" if snapshot_count > 0 else "No snapshots"
            
            print(f"{vmid:<8} {name:<25} {status:<20} {node:<12} {snapshot_info}")
        
        print("-" * 100)
        print(f"Total VMs: {len(all_vms)}")

class ProxmoxSnapshotInteractiveManager(ProxmoxSnapshotManager):
    """Interactive Proxmox VM snapshot management tool."""
    
    def __init__(self):
        super().__init__()
        
    def display_usage(self):
        """Display usage information."""
        usage_text = """
Usage: python3 pve_snapshot_manager_interactive.py

Interactive Proxmox VM Snapshot Management Tool

This tool provides an interactive interface to:
  - View all snapshots across all VMs
  - Display snapshots sorted by creation time per VM
  - Select specific snapshots for deletion
  - Perform bulk deletion operations
  - Browse snapshots in a user-friendly table format

API Authentication Options:
  1. Username/Password (prompted)
  2. API Token (set environment variables):
     export PVE_HOST=your-proxmox-host
     export PVE_USER=username@realm
     export PVE_TOKEN_NAME=token-name
     export PVE_TOKEN_VALUE=token-value

Features:
  - Real-time VM status monitoring
  - Multi-node cluster support
  - Interactive snapshot selection
  - Sorted snapshot displays by creation time
  - Bulk deletion support
  - Safe confirmation prompts
  - Comprehensive snapshot information display
"""
        print(usage_text)
    
    def get_all_snapshots_summary(self) -> Dict[str, List[Dict]]:
        """Get summary of all snapshots across all VMs."""
        all_vms = self.get_all_vms()
        vm_snapshots = {}
        
        print("🔍 Scanning VMs for snapshots...")
        
        for vm in all_vms:
            vmid = str(vm['vmid'])
            snapshots = self.get_snapshots(vmid)
            
            # Filter out 'current' snapshot and sort by timestamp
            actual_snapshots = [s for s in snapshots if s.get('name') != 'current']
            actual_snapshots.sort(key=lambda x: x.get('snaptime', 0), reverse=True)
            
            if actual_snapshots:
                vm_info = self.get_vm_info(vmid)
                vm_data = {
                    'vmid': vmid,
                    'vm_name': vm_info['name'] if vm_info else f'vm-{vmid}',
                    'vm_clean_name': self.get_vm_name(vmid) or f'vm-{vmid}',
                    'node': vm_info['node'] if vm_info else 'unknown',
                    'running': vm_info['running'] if vm_info else False,
                    'snapshots': actual_snapshots
                }
                vm_snapshots[vmid] = vm_data
        
        return vm_snapshots
    
    def display_all_snapshots_table(self, vm_snapshots: Dict[str, List[Dict]]) -> List[Tuple[str, str, Dict]]:
        """Display all snapshots in a comprehensive table format and return selection list."""
        if not vm_snapshots:
            print("\n❌ No snapshots found across all VMs")
            return []
        
        print(f"\n📋 All Snapshots Across VMs (Sorted by Creation Time)")
        print("=" * 135)
        print(f"{'#':<4} {'VMID':<6} {'VM Name':<25} {'Snapshot Name':<50} {'Created':<20} {'Type':<15} {'Node'}")
        print("-" * 135)
        
        # Create a flat list of all snapshots for selection
        all_snapshots = []
        counter = 1
        
        for vmid, vm_data in sorted(vm_snapshots.items(), key=lambda x: int(x[0])):
            vm_name = vm_data['vm_clean_name'][:24]
            node = vm_data['node']
            
            for snapshot in vm_data['snapshots']:
                snapshot_name = snapshot.get('name', 'N/A')
                description = snapshot.get('description', 'No description')
                
                # Parse timestamp
                snaptime = snapshot.get('snaptime', 0)
                if snaptime:
                    date_str = datetime.fromtimestamp(snaptime).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    date_str = 'Unknown'
                
                # Check for vmstate
                has_vmstate = self.check_snapshot_has_vmstate(description)
                vmstate_indicator = "🧠 with vmstate" if has_vmstate else "💾 disk only"
                
                # Use full snapshot name (no truncation)
                display_snapshot_name = snapshot_name
                
                print(f"{counter:<4} {vmid:<6} {vm_name:<25} {display_snapshot_name:<50} {date_str:<20} {vmstate_indicator:<15} {node}")
                
                # Store for selection (counter, vmid, snapshot_data)
                all_snapshots.append((counter, vmid, snapshot))
                counter += 1
        
        print("-" * 135)
        print(f"Total snapshots found: {len(all_snapshots)} across {len(vm_snapshots)} VMs")
        print("💡 Tip: Use snapshot numbers for individual deletion or VM-specific bulk operations")
        print()
        
        return all_snapshots
    
    def display_vm_snapshots_detailed(self, vmid: str) -> List[Dict]:
        """Display detailed snapshots for a specific VM, sorted by creation time."""
        snapshots = self.get_snapshots(vmid)
        
        if not snapshots:
            print(f"\n❌ No snapshots found for VM {vmid}")
            return []
        
        # Filter out 'current' snapshot and sort by timestamp (newest first)
        actual_snapshots = [s for s in snapshots if s.get('name') != 'current']
        actual_snapshots.sort(key=lambda x: x.get('snaptime', 0), reverse=True)
        
        if not actual_snapshots:
            print(f"\n❌ No deletable snapshots found for VM {vmid}")
            return []
        
        # Get VM info for display
        vm_info = self.get_vm_info(vmid)
        if vm_info:
            vm_display_name = self.get_vm_name(vmid) or vm_info['name']
            is_running, status_display, _ = self.get_vm_status_detailed(vmid)
        else:
            vm_display_name = f"VM-{vmid}"
            status_display = "❌ error"
        
        print(f"\n📋 Snapshots for VM {vmid} ({vm_display_name})")
        print(f"Status: {status_display}")
        print("=" * 115)
        print(f"{'#':<3} {'Name':<50} {'Created':<20} {'Type':<20} {'Description'}")
        print("-" * 115)
        
        for i, snapshot in enumerate(actual_snapshots, 1):
            name = snapshot.get('name', 'N/A')
            description = snapshot.get('description', 'No description')
            
            # Parse timestamp
            snaptime = snapshot.get('snaptime', 0)
            if snaptime:
                date_str = datetime.fromtimestamp(snaptime).strftime('%Y-%m-%d %H:%M:%S')
            else:
                date_str = 'Unknown'
            
            # Check for vmstate
            has_vmstate = self.check_snapshot_has_vmstate(description)
            vmstate_indicator = "🧠 with vmstate" if has_vmstate else "💾 disk only"
            
            # Truncate description if too long
            if len(description) > 25:
                description = description[:22] + "..."
            
            print(f"{i:<3} {name:<50} {date_str:<20} {vmstate_indicator:<20} {description}")
        
        print("-" * 115)
        print(f"Total snapshots: {len(actual_snapshots)}")
        print("💡 Tip: #1 is the most recent snapshot")
        print()
        
        return actual_snapshots
    
    def delete_snapshot(self, vmid: str, snapshot_name: str) -> bool:
        """Delete a specific snapshot (reusing enhanced logic from delete script)."""
        vm_name = self.get_full_vm_name(vmid)
        
        print(f"\n{'='*60}")
        print(f"DELETING SNAPSHOT: {snapshot_name}")
        print(f"FROM VM: {vmid} ({vm_name})")
        print(f"{'='*60}")
        
        node = self.find_vm_node(vmid)
        if not node:
            print("❌ Could not find node for VM")
            return False
        
        # Check VM status before deletion
        print(f"📊 Checking VM status before snapshot deletion...")
        is_running_before, status_display_before, status_details_before = self.get_vm_status_detailed(vmid)
        print(f"  Status: {status_display_before}")
        if status_details_before:
            print(f"  Details: {status_details_before}")
        
        try:
            print(f"🗑️  Deleting snapshot...")
            
            # Execute deletion via API
            task_id = self.api._request('DELETE', f'/nodes/{node}/qemu/{vmid}/snapshot/{snapshot_name}')
            
            # Monitor task progress
            success = self.monitor_task(node, task_id, f"Snapshot deletion for VM {vmid}")
            
            if success:
                print(f"  ✅ Snapshot deleted successfully")
                
                # Wait a moment for the system to stabilize
                time.sleep(2)
                
                # Check VM status after deletion
                print(f"📊 Checking VM status after snapshot deletion...")
                is_running_after, status_display_after, _ = self.get_vm_status_detailed(vmid)
                print(f"  Status: {status_display_after}")
                
                # Compare status before and after
                if is_running_before == is_running_after:
                    print(f"  ✅ VM status unchanged (as expected)")
                else:
                    print(f"  ⚠️  VM status changed from {'running' if is_running_before else 'stopped'} to {'running' if is_running_after else 'stopped'}")
            else:
                print(f"  ❌ Failed to delete snapshot")
            
            return success
            
        except ProxmoxAPIError as e:
            print(f"  ❌ Failed to delete snapshot: {e.message}")
            return False
    
    def confirm_snapshot_deletion(self, vmid: str, snapshot_name: str) -> bool:
        """Confirm individual snapshot deletion."""
        vm_name = self.get_full_vm_name(vmid)
        vm_info = self.get_vm_info(vmid)
        
        if vm_info:
            is_running = vm_info['running']
            status_display = "🟢 running" if is_running else "🔴 stopped"
        else:
            status_display = "❌ error"
        
        print(f"\n{'='*60}")
        print("⚠️  SNAPSHOT DELETION CONFIRMATION")
        print(f"{'='*60}")
        print(f"VM: {vmid} ({vm_name}) - Status: {status_display}")
        print(f"Node: {vm_info.get('node', 'unknown') if vm_info else 'unknown'}")
        print(f"Snapshot: {snapshot_name}")
        
        # Get snapshot details
        snapshots = self.get_snapshots(vmid)
        for snapshot in snapshots:
            if snapshot['name'] == snapshot_name:
                if snapshot.get('snaptime'):
                    created = datetime.fromtimestamp(snapshot['snaptime']).strftime('%Y-%m-%d %H:%M:%S')
                    print(f"Created: {created}")
                if snapshot.get('description'):
                    print(f"Description: {snapshot['description']}")
                    has_vmstate = self.check_snapshot_has_vmstate(snapshot['description'])
                    print(f"VM State: {'🧠 Included' if has_vmstate else '💾 Not included'}")
                break
        
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
    
    def confirm_bulk_deletion(self, vmid: str, snapshots: List[Dict]) -> bool:
        """Confirm bulk deletion of all snapshots for a VM."""
        vm_name = self.get_full_vm_name(vmid)
        vm_info = self.get_vm_info(vmid)
        
        if vm_info:
            is_running = vm_info['running']
            status_display = "🟢 running" if is_running else "🔴 stopped"
        else:
            status_display = "❌ error"
        
        print(f"\n{'='*60}")
        print("⚠️  BULK DELETION WARNING")
        print(f"{'='*60}")
        print(f"VM: {vmid} ({vm_name}) - Status: {status_display}")
        print(f"Node: {vm_info.get('node', 'unknown') if vm_info else 'unknown'}")
        print(f"This will delete ALL {len(snapshots)} snapshots!")
        print("\nSnapshots to be deleted:")
        
        for i, snapshot in enumerate(snapshots, 1):
            name = snapshot['name']
            created = ""
            if snapshot.get('snaptime'):
                created = datetime.fromtimestamp(snapshot['snaptime']).strftime('%Y-%m-%d %H:%M')
            has_vmstate = self.check_snapshot_has_vmstate(snapshot.get('description', ''))
            vmstate_indicator = "🧠" if has_vmstate else "💾"
            print(f"  {i:2d}. {name:<30} {created:<16} {vmstate_indicator}")
        
        print(f"\n❌ This action cannot be undone!")
        print(f"{'='*60}")
        
        try:
            confirm_all = input("Are you absolutely sure you want to delete ALL snapshots? (yes/N): ").strip().lower()
            if confirm_all == 'yes':  # Require full "yes" for bulk deletion
                return True
            else:
                print("Bulk deletion cancelled")
                return False
        except KeyboardInterrupt:
            print("\nBulk deletion cancelled")
            return False
    
    def vm_specific_snapshot_management(self, vmid: str):
        """Manage snapshots for a specific VM."""
        vm_info = self.get_vm_info(vmid)
        if not vm_info:
            print(f"❌ ERROR: VM {vmid} does not exist or is not accessible")
            return
        
        # Show VM details
        print(f"\nVM Details:")
        print(f"  ID: {vmid}")
        print(f"  Name: {vm_info['name']}")
        print(f"  Node: {vm_info['node']}")
        is_running, status_display, _ = self.get_vm_status_detailed(vmid)
        print(f"  Status: {status_display}")
        
        while True:
            # Display snapshots for this VM
            snapshots = self.display_vm_snapshots_detailed(vmid)
            
            if not snapshots:
                return
            
            print("Options:")
            print("  Enter snapshot number (1-{}) to delete a specific snapshot".format(len(snapshots)))
            print("  [a] Delete ALL snapshots for this VM")
            print("  [b] Back to main menu")
            print("  [q] Quit")
            print()
            
            try:
                choice = input("Select option: ").strip().lower()
                
                if choice in ['q', 'quit']:
                    return
                elif choice in ['b', 'back']:
                    return
                elif choice in ['a', 'all']:
                    if self.confirm_bulk_deletion(vmid, snapshots):
                        success_count = 0
                        fail_count = 0
                        
                        print(f"\n🗑️  Starting bulk deletion of {len(snapshots)} snapshots...")
                        print(f"{'='*60}")
                        
                        for i, snapshot in enumerate(snapshots, 1):
                            print(f"\n[{i}/{len(snapshots)}] Processing snapshot: {snapshot['name']}")
                            if self.delete_snapshot(vmid, snapshot['name']):
                                success_count += 1
                            else:
                                fail_count += 1
                            
                            # Small delay between deletions
                            if i < len(snapshots):
                                time.sleep(2)
                        
                        print(f"\n{'='*60}")
                        print("BULK DELETION COMPLETED")
                        print(f"{'='*60}")
                        print(f"✅ Successful: {success_count}")
                        print(f"❌ Failed: {fail_count}")
                        print(f"📊 Total processed: {len(snapshots)}")
                        print(f"{'='*60}")
                    break
                elif choice.isdigit():
                    choice_num = int(choice)
                    if 1 <= choice_num <= len(snapshots):
                        selected_snapshot = snapshots[choice_num - 1]
                        if self.confirm_snapshot_deletion(vmid, selected_snapshot['name']):
                            self.delete_snapshot(vmid, selected_snapshot['name'])
                        break
                    else:
                        print(f"Invalid selection. Please choose a number between 1 and {len(snapshots)}")
                else:
                    print("Invalid input. Please enter a number, 'a', 'b', or 'q'")
                    
            except KeyboardInterrupt:
                print("\nOperation cancelled")
                return
            except ValueError:
                print("Invalid input. Please enter a number, 'a', 'b', or 'q'")
    
    def global_snapshot_management(self):
        """Manage snapshots across all VMs globally."""
        # Get all snapshots
        vm_snapshots = self.get_all_snapshots_summary()
        
        if not vm_snapshots:
            print("\n❌ No snapshots found across all VMs")
            return
        
        # Display all snapshots in table format
        all_snapshots = self.display_all_snapshots_table(vm_snapshots)
        
        print("Options:")
        print("  Enter snapshot number to delete a specific snapshot")
        print("  Enter VM ID to manage all snapshots for that VM")
        print("  [q] Back to main menu")
        print()
        
        try:
            choice = input("Select option: ").strip()
            
            if choice.lower() in ['q', 'quit']:
                return
            elif choice.isdigit():
                # Check if it's a snapshot number or VM ID
                choice_num = int(choice)
                
                # First check if it's a valid snapshot number
                if 1 <= choice_num <= len(all_snapshots):
                    _, vmid, snapshot_data = all_snapshots[choice_num - 1]
                    snapshot_name = snapshot_data['name']
                    
                    if self.confirm_snapshot_deletion(vmid, snapshot_name):
                        self.delete_snapshot(vmid, snapshot_name)
                    return
                
                # Then check if it's a VM ID
                elif choice in vm_snapshots:
                    self.vm_specific_snapshot_management(choice)
                    return
                else:
                    print(f"Invalid selection. Enter a snapshot number (1-{len(all_snapshots)}) or valid VM ID")
            else:
                # Check if it's a VM ID (string)
                if choice in vm_snapshots:
                    self.vm_specific_snapshot_management(choice)
                else:
                    print("Invalid input. Please enter a snapshot number, VM ID, or 'q'")
                    
        except KeyboardInterrupt:
            print("\nOperation cancelled")
            return
        except ValueError:
            print("Invalid input. Please enter a number, VM ID, or 'q'")
    
    def interactive_mode(self):
        """Run the script in interactive mode."""
        print("Proxmox VM Snapshot Interactive Manager")
        print("=" * 45)
        
        while True:
            try:
                print("\nMain Menu:")
                print("=" * 30)
                print("1. View all snapshots across all VMs")
                print("2. Manage snapshots for a specific VM")
                print("3. Browse and delete individual snapshots")
                print("4. View VM list")
                print("5. Quit")
                print()
                
                choice = input("Select option (1-5): ").strip()
                
                if choice == '1' or choice == '3':
                    # Global snapshot view and management
                    self.global_snapshot_management()
                elif choice == '2':
                    # VM-specific management
                    print()
                    vmid = input("Enter VM ID: ").strip()
                    
                    if vmid:
                        self.vm_specific_snapshot_management(vmid)
                elif choice == '4':
                    # Display VM list
                    self.display_vm_list_interactive()
                elif choice == '5':
                    print("Goodbye!")
                    break
                else:
                    print("Invalid choice. Please select 1-5.")
                    
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break


def main():
    """Main function to handle command line arguments and run the interactive manager."""
    manager = ProxmoxSnapshotInteractiveManager()
    
    # Check for help
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        manager.display_usage()
        sys.exit(0)
    
    # Connect to Proxmox API
    if not manager.connect_to_proxmox():
        print("❌ Failed to connect to Proxmox API")
        sys.exit(1)
    
    # Verify API connection by getting cluster status
    try:
        nodes = manager.get_nodes()
        if not nodes:
            print("❌ No nodes found or insufficient permissions")
            sys.exit(1)
        
        print(f"✅ Connected to Proxmox cluster with {len(nodes)} node(s):")
        for node in nodes:
            status = "🟢 online" if node.get('status') == 'online' else "🔴 offline"
            print(f"  - {node['node']} ({status})")
        
    except Exception as e:
        print(f"❌ Error verifying connection: {e}")
        sys.exit(1)
    
    # Run interactive mode
    manager.interactive_mode()


if __name__ == "__main__":
    main()