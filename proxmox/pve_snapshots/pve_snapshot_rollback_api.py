#!/usr/bin/env python3

"""
Enhanced Proxmox VM Snapshot Rollback Script (API Version) - Optimized
Usage: ./pve_snapshot_rollback_api.py [vmid] [snapname]
If no arguments provided, it will run in interactive mode

Optimized version that reuses ProxmoxAPI and ProxmoxSnapshotManager classes
while keeping all enhanced rollback features:
- Sorted snapshot display (newest first)
- Configuration comparison between current and snapshot
- Enhanced interactive experience
- Comprehensive safety checks and confirmations
- Real-time task monitoring
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
            if clean_name.startswith('xsf-dev-'):
                clean_name = clean_name[8:]
            elif clean_name.startswith('xaj-prod-'):
                clean_name = clean_name[9:]
        
        return clean_name if clean_name else full_name
    
    def get_full_vm_name(self, vmid: str) -> Optional[str]:
        """Get the full VM name."""
        vm_info = self.get_vm_info(vmid)
        return vm_info['name'] if vm_info else None
    
    def get_vm_config_summary(self, config: Dict) -> Dict[str, str]:
        """Extract important configuration values for display."""
        important_keys = [
            'name', 'memory', 'cores', 'sockets', 'ostype', 'bootdisk',
            'scsi0', 'ide2', 'net0', 'agent', 'onboot'
        ]
        
        summary = {}
        for key in important_keys:
            if key in config:
                value = str(config[key])
                if len(value) > 50:
                    value = value[:47] + "..."
                summary[key] = value
        
        return summary
    
    def display_vm_config_summary(self, config: Dict, title: str):
        """Display a summary of important VM configuration values."""
        if not config:
            print(f"  {title}: No config data available")
            return
            
        print(f"  {title}:")
        summary = self.get_vm_config_summary(config)
        
        if summary:
            # Display in pairs for better readability
            items = list(summary.items())
            for i in range(0, len(items), 2):
                if i + 1 < len(items):
                    key1, val1 = items[i]
                    key2, val2 = items[i + 1]
                    print(f"    {key1}={val1:<35} {key2}={val2}")
                else:
                    key1, val1 = items[i]
                    print(f"    {key1}={val1}")
        else:
            print("    No important config items found")
    
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
    
    def get_snapshot_config(self, vmid: str, snapshot_name: str) -> Dict:
        """Get configuration of a specific snapshot."""
        node = self.find_vm_node(vmid)
        if not node:
            return {}
        
        try:
            config = self.api._request('GET', f'/nodes/{node}/qemu/{vmid}/snapshot/{snapshot_name}/config')
            return config
        except ProxmoxAPIError:
            return {}
    
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

class ProxmoxSnapshotRollback(ProxmoxSnapshotManager):
    """Enhanced Proxmox VM snapshot rollback manager using API with all advanced features."""
    
    def __init__(self):
        super().__init__()
        # REMOVED: self.vmstate_keywords - now inherited from parent class
        
    def display_usage(self):
        """Display enhanced usage information."""
        usage_text = """
Usage: python3 pve_snapshot_rollback_api.py [vmid] [snapname]

Rollback VM to a specific snapshot with comprehensive safety checks and status monitoring.

API Authentication Options:
  1. Username/Password (prompted)
  2. API Token (set environment variables):
     export PVE_HOST=your-proxmox-host
     export PVE_USER=username@realm
     export PVE_TOKEN_NAME=token-name
     export PVE_TOKEN_VALUE=token-value

Examples:
  python3 pve_snapshot_rollback_api.py 7201 pre-release-storage01-20250603-1430    # Direct rollback
  python3 pve_snapshot_rollback_api.py 7201                                        # Show snapshots for VM 7201
  python3 pve_snapshot_rollback_api.py                                             # Interactive mode

Features:
  - Real-time VM status and resource monitoring
  - Multi-node cluster support
  - Interactive snapshot selection with detailed information
  - Snapshots sorted by creation date (newest first)
  - VM status monitoring before and after rollback
  - Snapshot configuration preview with comparison
  - VM state detection with appropriate warnings
  - Optional VM startup after rollback
  - Task progress tracking
  - Comprehensive safety confirmations
  - Enhanced error handling
"""
        print(usage_text)
        
    # REMOVED: check_snapshot_has_vmstate method - now inherited from parent class with improved implementation
    
    def display_vm_info(self, vmid: str, title: str = "VM Information"):
        """Display comprehensive VM information."""
        print(f"\n{title}")
        print("=" * len(title))
        
        # Get VM info
        vm_info = self.get_vm_info(vmid)
        if not vm_info:
            print("❌ VM not found or inaccessible")
            return
        
        print(f"VM ID: {vmid}")
        print(f"VM Name: {vm_info['name']}")
        print(f"Node: {vm_info['node']}")
        
        # Status with detailed info
        is_running, status_display, status_details = self.get_vm_status_detailed(vmid)
        print(f"Status: {status_display}")
        
        if is_running:
            print(f"Details: {status_details}")
        
        # Configuration summary
        if vm_info.get('config'):
            self.display_vm_config_summary(vm_info['config'], "Current Configuration")
        
        print()
    
    def display_snapshot_info(self, vmid: str, snapname: str):
        """Display detailed snapshot information."""
        print(f"\nSnapshot Configuration Preview")
        print("=" * 35)
        
        # Get snapshot config
        config = self.get_snapshot_config(vmid, snapname)
        if config:
            print(f"Snapshot: {snapname}")
            self.display_vm_config_summary(config, "Snapshot Configuration")
        else:
            print(f"❌ Could not retrieve configuration for snapshot: {snapname}")
        
        print()
    
    def display_snapshots_list(self, vmid: str) -> List[Dict]:
        """Display formatted list of snapshots, sorted by creation date (newest first)."""
        snapshots = self.get_snapshots(vmid)
        
        if not snapshots:
            print("❌ No snapshots found for this VM")
            return []
        
        # Filter out 'current' snapshot and sort by timestamp (newest first)
        actual_snapshots = []
        current_snapshot = None
        
        for snapshot in snapshots:
            if snapshot.get('name') == 'current':
                current_snapshot = snapshot
            else:
                actual_snapshots.append(snapshot)
        
        # Sort by snaptime (newest first) - handle missing snaptime
        actual_snapshots.sort(key=lambda x: x.get('snaptime', 0), reverse=True)
        
        vm_name = self.get_vm_name(vmid)
        print(f"\nSnapshots for VM {vmid} ({vm_name or 'Unknown'}) - Sorted by Date (Newest First):")
        print("=" * 105)
        print(f"{'#':<3} {'Name':<50} {'Created':<20} {'Type':<15} {'Description'}")
        print("-" * 105)
        
        # Display actual snapshots
        for i, snapshot in enumerate(actual_snapshots, 1):
            name = snapshot.get('name', 'N/A')
            description = snapshot.get('description', 'No description')
            
            # Parse timestamp
            snaptime = snapshot.get('snaptime', 0)
            if snaptime:
                date_str = datetime.fromtimestamp(snaptime).strftime('%Y-%m-%d %H:%M:%S')
            else:
                date_str = 'Unknown'
            
            # Check for vmstate using inherited method
            has_vmstate = self.check_snapshot_has_vmstate(description)
            vmstate_indicator = "🧠 with vmstate" if has_vmstate else "💾 disk only"
            
            # Truncate description if too long
            if len(description) > 30:
                description = description[:27] + "..."
            
            print(f"{i:<3} {name:<50} {date_str:<20} {vmstate_indicator:<15} {description}")
        
        # Add current snapshot at the end if it exists
        if current_snapshot:
            print(f"{'---':<3} {'current':<50} {'---':<20} {'🎯 current state':<15} {'You are here!'}")
        
        print("-" * 105)
        print(f"Total snapshots: {len(actual_snapshots)} (excluding current state)")
        if len(actual_snapshots) > 0:
            print("💡 Tip: #1 is the most recent snapshot")
        
        return actual_snapshots
    
    def rollback_snapshot(self, vmid: str, snapname: str) -> bool:
        """Perform the actual snapshot rollback."""
        print(f"\n{'='*60}")
        print("PERFORMING SNAPSHOT ROLLBACK")
        print(f"{'='*60}")
        print(f"VM ID: {vmid}")
        print(f"Snapshot: {snapname}")
        print("⚠️  This operation will revert the VM to the snapshot state!")
        print(f"{'='*60}")
        
        node = self.find_vm_node(vmid)
        if not node:
            print("❌ Could not find node for VM")
            return False
        
        try:
            print("🔄 Executing rollback command...")
            
            # Execute rollback via API
            task_id = self.api._request('POST', f'/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback')
            
            # Monitor task progress
            success = self.monitor_task(node, task_id, f"Rollback for VM {vmid}")
            
            if success:
                print("✅ Rollback completed successfully!")
            else:
                print("❌ Rollback failed!")
            
            return success
            
        except ProxmoxAPIError as e:
            print(f"❌ Rollback failed: {e.message}")
            return False
    
    def start_vm(self, vmid: str) -> bool:
        """Start a VM."""
        node = self.find_vm_node(vmid)
        if not node:
            print("❌ Could not find node for VM")
            return False
        
        try:
            print("🚀 Starting VM...")
            task_id = self.api._request('POST', f'/nodes/{node}/qemu/{vmid}/status/start')
            
            # Monitor task progress
            success = self.monitor_task(node, task_id, f"VM {vmid} startup")
            
            if success:
                print("✅ VM started successfully!")
            else:
                print("❌ Failed to start VM!")
            
            return success
            
        except ProxmoxAPIError as e:
            print(f"❌ Failed to start VM: {e.message}")
            return False
    
    def prompt_start_vm(self, vmid: str) -> bool:
        """Prompt user to start VM if it's stopped after rollback."""
        try:
            choice = input(f"\nVM {vmid} is stopped. Would you like to start it? (y/N): ").strip().lower()
            if choice in ['y', 'yes']:
                return self.start_vm(vmid)
            else:
                print("VM remains stopped")
                return False
        except KeyboardInterrupt:
            print("\nSkipping VM start")
            return False
    
    def compare_configurations(self, current_config: Dict, snapshot_config: Dict):
        """Compare current VM config with snapshot config and highlight differences."""
        print("\n📋 Configuration Comparison")
        print("=" * 50)
        
        current_summary = self.get_vm_config_summary(current_config)
        snapshot_summary = self.get_vm_config_summary(snapshot_config)
        
        all_keys = set(current_summary.keys()) | set(snapshot_summary.keys())
        
        changes_found = False
        
        for key in sorted(all_keys):
            current_val = current_summary.get(key, "Not set")
            snapshot_val = snapshot_summary.get(key, "Not set")
            
            if current_val != snapshot_val:
                changes_found = True
                print(f"  🔄 {key}:")
                print(f"    Current:  {current_val}")
                print(f"    Snapshot: {snapshot_val}")
                print()
        
        if not changes_found:
            print("  ✅ No significant configuration differences detected")
        
        print()
    
    def rollback_process(self, vmid: str, snapname: str) -> bool:
        """Handle the complete rollback process with all safety checks."""
        
        # 1. Check VM exists
        vm_info = self.get_vm_info(vmid)
        if not vm_info:
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
            print("\nAvailable snapshots:")
            for snap in snapshots:
                print(f"  - {snap['name']}")
            return False
        
        # 4. Display snapshot configuration and comparison
        self.display_snapshot_info(vmid, snapname)
        
        # Compare current config with snapshot config
        snapshot_config = self.get_snapshot_config(vmid, snapname)
        if snapshot_config and vm_info.get('config'):
            self.compare_configurations(vm_info['config'], snapshot_config)
        
        # 5. Check vmstate and display warnings using inherited method
        has_vmstate = self.check_snapshot_has_vmstate(target_snapshot.get('description', ''))
        
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
        
        # Show timestamp info
        if target_snapshot.get('snaptime'):
            snap_date = datetime.fromtimestamp(target_snapshot['snaptime']).strftime('%Y-%m-%d %H:%M:%S')
            print(f"📅 Snapshot was created: {snap_date}")
        
        print()
        
        # 6. Final confirmation
        print(f"You are about to rollback VM {vmid} to snapshot: {snapname}")
        print(f"VM state included: {'YES' if has_vmstate else 'NO'}")
        print("\n❗ This action cannot be undone!")
        print("💡 Consider creating a new snapshot before proceeding if you want to preserve current state")
        
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
        final_status = self.get_vm_info(vmid)
        if final_status:
            is_running = final_status['running']
            if not is_running and not has_vmstate:
                self.prompt_start_vm(vmid)
            elif is_running and has_vmstate:
                print("✅ VM automatically started due to vmstate restoration")
            elif is_running:
                print("✅ VM is running")
        
        return True
    
    def interactive_mode(self):
        """Run the script in interactive mode with enhanced display."""
        print("Enhanced Proxmox VM Snapshot Rollback Tool (API Version)")
        print("=" * 55)
        
        while True:
            try:
                # Show VM list
                print("\nAvailable VMs:")
                print("=" * 100)
                print(f"{'VMID':<8} {'Name':<25} {'Status':<20} {'Node':<12} {'Snapshots'}")
                print("-" * 100)
                
                all_vms = self.get_all_vms()
                if not all_vms:
                    print("❌ No VMs found")
                    return
                
                for vm in sorted(all_vms, key=lambda x: int(x['vmid'])):
                    vmid = str(vm['vmid'])
                    name = vm.get('name', f'vm-{vmid}')[:24]
                    
                    # Get detailed status
                    vm_info = self.get_vm_info(vmid)
                    if vm_info:
                        if vm_info['running']:
                            status = "🟢 running"
                        else:
                            status = "🔴 stopped"
                        node = vm_info['node']
                    else:
                        status = "❌ error"
                        node = vm.get('node', 'unknown')
                    
                    # Count snapshots
                    snapshots = self.get_snapshots(vmid)
                    snapshot_count = len([s for s in snapshots if s.get('name') != 'current'])
                    snapshot_info = f"{snapshot_count} snapshots" if snapshot_count > 0 else "No snapshots"
                    
                    print(f"{vmid:<8} {name:<25} {status:<20} {node:<12} {snapshot_info}")
                
                print("-" * 100)
                print(f"Total VMs: {len(all_vms)}")
                
                print()
                vmid_input = input("Enter VM ID to rollback (or 'q' to quit): ").strip()
                
                if vmid_input.lower() in ['q', 'quit']:
                    print("Goodbye!")
                    break
                
                # Validate VM ID
                vm_info = self.get_vm_info(vmid_input)
                if not vm_info:
                    print(f"❌ VM {vmid_input} does not exist or is not accessible")
                    continue
                
                # Show snapshots for the VM
                snapshots = self.display_snapshots_list(vmid_input)
                if not snapshots:
                    continue
                
                # Get snapshot selection
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
                
                # Ask if user wants to continue
                print()
                continue_choice = input("Press Enter to continue or 'q' to quit: ").strip().lower()
                if continue_choice in ['q', 'quit']:
                    print("Goodbye!")
                    break
            
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
    
    def vm_specific_mode(self, vmid: str):
        """Show snapshots for a specific VM and allow selection."""
        vm_info = self.get_vm_info(vmid)
        if not vm_info:
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
    
    # Connect to Proxmox API
    if not rollback_manager.connect_to_proxmox():
        print("❌ Failed to connect to Proxmox API")
        sys.exit(1)
    
    # Verify API connection by getting cluster status
    try:
        nodes = rollback_manager.get_nodes()
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