#!/usr/bin/env python3

"""
Enhanced Proxmox VM Snapshot Management Script (API Version)
Usage: ./pve_snapshot_api.py [prefix] [vmid1] [vmid2] ... [vmidN]
If no arguments provided, it will run in interactive mode

Enhancements over CLI version:
- Uses Proxmox API instead of qm commands
- Real-time VM status and resource monitoring
- Multi-node cluster support
- Better error handling with structured responses
- Task progress monitoring
- Enhanced interactive experience
- VM list with snapshot counts (matching rollback script format)
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
        # UPGRADED: Added configurable vmstate keywords as instance variable
        self.vmstate_keywords = ['vmstate', 'RAM', 'with vmstate', 'RAM included', 'with VM state', 'VM state included']
        
    def display_usage(self):
        """Display usage information."""
        usage_text = """
Usage: python3 pve_snapshot_api.py [prefix] [vmid1] [vmid2] ... [vmidN]

Creates snapshots with format: <PREFIX>-<3RD_SECTION>-YYYYMMDD-HHMM
The 3RD_SECTION is extracted from VM name using '-' as separator (3rd part onwards)

API Authentication Options:
  1. Username/Password (prompted)
  2. API Token (set environment variables):
     export PVE_HOST=your-proxmox-host
     export PVE_USER=username@realm
     export PVE_TOKEN_NAME=token-name
     export PVE_TOKEN_VALUE=token-value

Examples:
  python3 pve_snapshot_api.py pre-release 7201 7203 7204    # Snapshot specific VMs
  python3 pve_snapshot_api.py maintenance                   # Snapshot all VMs
  python3 pve_snapshot_api.py                               # Interactive mode

Features:
  - Real-time VM status and resource monitoring
  - Multi-node cluster support
  - Task progress tracking
  - Enhanced error handling
  - Intelligent VM name extraction
  - Optional VM state (RAM) saving
  - Interactive VM list with snapshot counts
"""
        print(usage_text)
    
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
    
    def truncate_vm_name_intelligently(self, vm_name: str, max_length: int) -> str:
        """Intelligently truncate VM name while preserving meaningful parts."""
        if len(vm_name) <= max_length:
            return vm_name
            
        # Strategy 1: Try to keep the last number/identifier
        number_match = re.search(r'^(.+)([0-9]+)$', vm_name)
        if number_match:
            base_part = number_match.group(1)
            number_part = number_match.group(2)
            base_length = max_length - len(number_part)
            
            if base_length > 0:
                return base_part[:base_length] + number_part
                
        # Strategy 2: Break at word boundaries
        temp_name = vm_name
        while len(temp_name) > max_length and '-' in temp_name:
            temp_name = temp_name.rsplit('-', 1)[0]
            
        if len(temp_name) <= max_length and len(temp_name) > max_length // 2:
            return temp_name
            
        # Strategy 3: Simple truncation
        return vm_name[:max_length]
    
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
    
    def create_snapshot(self, vmid: str, prefix: str) -> bool:
        """Create a snapshot for a VM with intelligent naming and monitoring."""
        timestamp = datetime.now().strftime('%Y%m%d-%H%M')
        vm_name = self.get_vm_name(vmid)
        
        if not vm_name:
            print(f"  ✗ Could not retrieve VM name for VMID {vmid}")
            return False
        
        node = self.find_vm_node(vmid)
        if not node:
            print(f"  ✗ Could not find node for VM {vmid}")
            return False
        
        # Create snapshot name
        full_snapshot_name = f"{prefix}-{vm_name}-{timestamp}"
        
        # Handle name length limits
        if len(full_snapshot_name) > self.max_snapshot_name_length:
            print(f"  ⚠ Snapshot name too long ({len(full_snapshot_name)} chars), truncating VM name...")
            
            prefix_suffix_length = len(prefix) + 1 + 1 + 13
            max_vm_name_length = self.max_snapshot_name_length - prefix_suffix_length
            
            if max_vm_name_length <= 0:
                print(f"  ✗ Prefix '{prefix}' is too long. Maximum prefix length is {self.max_snapshot_name_length - 14} characters")
                return False
            
            truncated_vm_name = self.truncate_vm_name_intelligently(vm_name, max_vm_name_length)
            full_snapshot_name = f"{prefix}-{truncated_vm_name}-{timestamp}"
            print(f"  📝 Truncated VM name: '{vm_name}' -> '{truncated_vm_name}'")
        
        print(f"Creating snapshot for VM {vmid}...")
        full_vm_name = self.get_full_vm_name(vmid)
        if full_vm_name:
            print(f"  Full VM Name: {full_vm_name}")
        print(f"  Clean VM Name: {vm_name}")
        print(f"  Snapshot: {full_snapshot_name} ({len(full_snapshot_name)} chars)")
        print(f"  Node: {node}")
        
        # Check VM status
        print(f"  📊 Checking VM status...")
        is_running, status_display, status_details = self.get_vm_status_detailed(vmid)
        print(f"  Status: {status_display}")
        
        # Get current configuration
        print(f"  📋 Getting current VM configuration...")
        vm_info = self.get_vm_info(vmid)
        if vm_info and vm_info['config']:
            self.display_vm_config_summary(vm_info['config'], "Current Config")
        
        # Determine vmstate behavior
        if self.save_vmstate and not is_running:
            print(f"  ⚠ VM {vmid} is not running - vmstate will be ignored")
        
        print(f"  VM State: {'WITH vmstate (RAM)' if self.save_vmstate and is_running else 'WITHOUT vmstate'}")
        
        try:
            # Prepare snapshot data
            snapshot_data = {
                'snapname': full_snapshot_name,
                'description': f'Snapshot created {"with" if self.save_vmstate and is_running else "without"} vmstate - {timestamp}'
            }
            
            if self.save_vmstate and is_running:
                snapshot_data['vmstate'] = '1'
            
            # Create snapshot
            print(f"  🔄 Creating snapshot...")
            task_id = self.api._request('POST', f'/nodes/{node}/qemu/{vmid}/snapshot', data=snapshot_data)
            
            # Monitor task progress
            success = self.monitor_task(node, task_id, f"Snapshot creation for VM {vmid}")
            
            if success:
                # Verify snapshot
                print(f"  🔍 Verifying snapshot...")
                snapshot_config = self.get_snapshot_config(vmid, full_snapshot_name)
                if snapshot_config:
                    self.display_vm_config_summary(snapshot_config, "Snapshot Config")
                    print(f"  ✓ Snapshot verification successful")
                else:
                    print(f"  ⚠ Could not verify snapshot config")
                
                # Check VM status after snapshot
                print(f"  📊 Checking VM status after snapshot...")
                is_running_after, status_display_after, _ = self.get_vm_status_detailed(vmid)
                print(f"  Status: {status_display_after}")
                
                if is_running == is_running_after:
                    print(f"  ✓ VM status unchanged (as expected)")
                else:
                    print(f"  ⚠ VM status changed from {'running' if is_running else 'stopped'} to {'running' if is_running_after else 'stopped'}")
            
            return success
            
        except ProxmoxAPIError as e:
            print(f"  ✗ Failed to create snapshot: {e.message}")
            return False
    
    def list_snapshots(self, vmid: str):
        """List snapshots for a VM with enhanced format matching rollback script."""
        snapshots = self.get_snapshots(vmid)
        
        if not snapshots:
            print(f"\n❌ No snapshots found for VM {vmid}")
            return
        
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
        
        # Get VM name for display
        vm_info = self.get_vm_info(vmid)
        if vm_info:
            # Extract clean name (same logic as get_vm_name but for display)
            full_name = vm_info['name']
            name_parts = full_name.split('-')
            if len(name_parts) >= 3:
                clean_name = '-'.join(name_parts[2:])
            else:
                clean_name = full_name
                if clean_name.startswith('xxx-dev-'):
                    clean_name = clean_name[8:]
                elif clean_name.startswith('xxx-prod-'):
                    clean_name = clean_name[9:]
            vm_display_name = clean_name if clean_name else full_name
        else:
            vm_display_name = f"VM-{vmid}"
        
        print(f"\nSnapshots for VM {vmid} ({vm_display_name}) - Sorted by Date (Newest First):")
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
            
            # Check for vmstate using upgraded method
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
        print()
    
    def check_snapshot_has_vmstate(self, description: str) -> bool:
        """Check if snapshot description indicates vmstate was saved."""
        if not description:
            return False
        description_lower = description.lower()
        # UPGRADED: Now uses instance variable self.vmstate_keywords instead of local variable
        return any(keyword.lower() in description_lower for keyword in self.vmstate_keywords)
    
    def get_all_vmids(self) -> List[str]:
        """Get all VM IDs from all nodes."""
        all_vms = self.get_all_vms()
        return [str(vm['vmid']) for vm in all_vms]
    
    def validate_and_clean_prefix(self, prefix: str) -> Optional[str]:
        """Validate and clean the prefix."""
        cleaned = re.sub(r'[^a-zA-Z0-9\-_]', '', prefix.replace(' ', ''))
        
        if not cleaned:
            return None
        
        if len(cleaned) > self.max_prefix_length:
            return None
        
        return cleaned
    
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
    
    def preview_snapshots(self, prefix: str, vmids: List[str]):
        """Show what snapshots will be created with enhanced status display."""
        print("\nSnapshot Preview:")
        print("=" * 90)
        timestamp = datetime.now().strftime('%Y%m%d-%H%M')
        
        running_vms = 0
        stopped_vms = 0
        error_vms = 0
        
        for vmid in vmids:
            vm_info = self.get_vm_info(vmid)
            
            if vm_info:
                is_running = vm_info['running']
                if is_running:
                    running_vms += 1
                    status_display = "🟢 running"
                else:
                    stopped_vms += 1
                    status_display = "🔴 stopped"
                
                vm_name = self.get_vm_name(vmid)
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
                    
                    print(f"  VM {vmid} ({status_display}) [{vm_info['node']}]: {snapshot_name}{vmstate_info}")
                    if status_text:
                        print(f"    Status: {status_text}")
                else:
                    print(f"  VM {vmid} ({status_display}) [{vm_info['node']}]: ERROR - Could not get VM name")
            else:
                error_vms += 1
                print(f"  VM {vmid}: ❌ ERROR - VM does not exist or is inaccessible")
        
        print("\n" + "=" * 90)
        print(f"Summary: {len(vmids)} VMs total")
        print(f"  🟢 Running VMs: {running_vms}")
        print(f"  🔴 Stopped VMs: {stopped_vms}")
        print(f"  ❌ Error VMs: {error_vms}")
        if self.save_vmstate:
            print(f"  🧠 VMs with vmstate: {running_vms} (only running VMs can save vmstate)")
            print(f"  📄 VMs without vmstate: {stopped_vms}")
        print("=" * 90)
    
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
            if not self.get_vm_info(vmid):
                print(f"ERROR: VM {vmid} does not exist or is not accessible")
                fail_count += 1
                continue
            
            # Create snapshot
            if self.create_snapshot(vmid, prefix):
                success_count += 1
            else:
                fail_count += 1
            
            # Small delay to avoid overwhelming the system
            if i < len(vmids):
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
                    if self.get_vm_info(vmid):
                        self.list_snapshots(vmid)
        except KeyboardInterrupt:
            print("\nSkipping snapshot listings")
        
        return success_count > 0
    
    def interactive_mode(self):
        """Run the script in interactive mode with enhanced API features."""
        print("Enhanced Proxmox VM Snapshot Tool (API Version)")
        print("=" * 50)
        
        while True:
            try:
                # Step 1: Display VM list first
                self.display_vm_list_interactive()
                
                # Step 2: Select VMs
                print()
                vm_input = input("Enter VM IDs (space-separated), 'q' to quit, or press Enter for all VMs: ").strip()
                
                if vm_input.lower() in ['q', 'quit']:
                    print("Goodbye!")
                    break
                elif not vm_input:
                    # All VMs
                    vmids = self.get_all_vmids()
                    if not vmids:
                        print("No VMs found")
                        continue
                else:
                    # Specific VMs - validate they exist
                    requested_vmids = vm_input.split()
                    available_vmids = set(self.get_all_vmids())
                    
                    valid_vmids = []
                    invalid_vmids = []
                    
                    for vmid in requested_vmids:
                        if vmid in available_vmids:
                            valid_vmids.append(vmid)
                        else:
                            invalid_vmids.append(vmid)
                    
                    if invalid_vmids:
                        print(f"⚠️  Warning: VMs not found: {', '.join(invalid_vmids)}")
                    
                    if valid_vmids:
                        vmids = valid_vmids
                        print(f"✓ Selected {len(valid_vmids)} VMs: {', '.join(valid_vmids)}")
                    else:
                        print("❌ No valid VMs to process")
                        continue
                
                # Step 3: Ask for snapshot prefix
                print()
                prefix_input = input("Enter snapshot prefix (default: pre-release): ").strip()
                
                # Set default if empty
                if not prefix_input:
                    prefix_input = "pre-release"
                
                # Validate and clean prefix
                prefix = self.validate_and_clean_prefix(prefix_input)
                if not prefix:
                    if len(prefix_input) > self.max_prefix_length:
                        print(f"ERROR: Prefix too long. Maximum length is {self.max_prefix_length} characters.")
                    else:
                        print("ERROR: Invalid prefix after cleanup")
                    continue
                
                # Step 4: Ask about VM state saving
                self.save_vmstate = self.prompt_vmstate_option()
                
                # Step 5: Create snapshots for selected VMs
                self.create_snapshots_process(prefix, vmids)
                
                print()
                continue_choice = input("Press Enter to continue or 'q' to quit: ").strip().lower()
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
        
        print(f"Command line mode: Creating snapshots for VMs: {' '.join(vmids) if vmids else 'all VMs'}")
        
        # Get VMIDs if not provided
        if not vmids:
            vmids = self.get_all_vmids()
        
        if not vmids:
            print("No VMs found")
            sys.exit(1)
        
        # Validate provided VMIDs exist
        available_vmids = set(self.get_all_vmids())
        valid_vmids = []
        invalid_vmids = []
        
        for vmid in vmids:
            if vmid in available_vmids:
                valid_vmids.append(vmid)
            else:
                invalid_vmids.append(vmid)
        
        if invalid_vmids:
            print(f"⚠️  Warning: VMs not found: {', '.join(invalid_vmids)}")
        
        if not valid_vmids:
            print("❌ No valid VMs to process")
            sys.exit(1)
        
        # Ask about VM state saving in command line mode
        self.save_vmstate = self.prompt_vmstate_option()
        
        # Run the snapshot creation process
        success = self.create_snapshots_process(cleaned_prefix, valid_vmids)
        sys.exit(0 if success else 1)
    
    def preview_snapshots(self, prefix: str, vmids: List[str]):
        """Show what snapshots will be created with enhanced status display."""
        print("\nSnapshot Preview:")
        print("=" * 90)
        timestamp = datetime.now().strftime('%Y%m%d-%H%M')
        
        running_vms = 0
        stopped_vms = 0
        error_vms = 0
        
        for vmid in vmids:
            vm_info = self.get_vm_info(vmid)
            
            if vm_info:
                is_running = vm_info['running']
                if is_running:
                    running_vms += 1
                    status_display = "🟢 running"
                else:
                    stopped_vms += 1
                    status_display = "🔴 stopped"
                
                vm_name = self.get_vm_name(vmid)
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
                    
                    print(f"  VM {vmid} ({status_display}) [{vm_info['node']}]: {snapshot_name}{vmstate_info}")
                    if status_text:
                        print(f"    Status: {status_text}")
                else:
                    print(f"  VM {vmid} ({status_display}) [{vm_info['node']}]: ERROR - Could not get VM name")
            else:
                error_vms += 1
                print(f"  VM {vmid}: ❌ ERROR - VM does not exist or is inaccessible")
        
        print("\n" + "=" * 90)
        print(f"Summary: {len(vmids)} VMs total")
        print(f"  🟢 Running VMs: {running_vms}")
        print(f"  🔴 Stopped VMs: {stopped_vms}")
        print(f"  ❌ Error VMs: {error_vms}")
        if self.save_vmstate:
            print(f"  🧠 VMs with vmstate: {running_vms} (only running VMs can save vmstate)")
            print(f"  📄 VMs without vmstate: {stopped_vms}")
        print("=" * 90)
    
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
            if not self.get_vm_info(vmid):
                print(f"ERROR: VM {vmid} does not exist or is not accessible")
                fail_count += 1
                continue
            
            # Create snapshot
            if self.create_snapshot(vmid, prefix):
                success_count += 1
            else:
                fail_count += 1
            
            # Small delay to avoid overwhelming the system
            if i < len(vmids):
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
                    if self.get_vm_info(vmid):
                        self.list_snapshots(vmid)
        except KeyboardInterrupt:
            print("\nSkipping snapshot listings")
        
        return success_count > 0
    
    def interactive_mode(self):
        """Run the script in interactive mode with enhanced API features."""
        print("Enhanced Proxmox VM Snapshot Tool (API Version)")
        print("=" * 50)
        
        while True:
            try:
                # Step 1: Display VM list first
                self.display_vm_list_interactive()
                
                # Step 2: Select VMs
                print()
                vm_input = input("Enter VM IDs (space-separated), 'q' to quit, or press Enter for all VMs: ").strip()
                
                if vm_input.lower() in ['q', 'quit']:
                    print("Goodbye!")
                    break
                elif not vm_input:
                    # All VMs
                    vmids = self.get_all_vmids()
                    if not vmids:
                        print("No VMs found")
                        continue
                else:
                    # Specific VMs - validate they exist
                    requested_vmids = vm_input.split()
                    available_vmids = set(self.get_all_vmids())
                    
                    valid_vmids = []
                    invalid_vmids = []
                    
                    for vmid in requested_vmids:
                        if vmid in available_vmids:
                            valid_vmids.append(vmid)
                        else:
                            invalid_vmids.append(vmid)
                    
                    if invalid_vmids:
                        print(f"⚠️  Warning: VMs not found: {', '.join(invalid_vmids)}")
                    
                    if valid_vmids:
                        vmids = valid_vmids
                        print(f"✓ Selected {len(valid_vmids)} VMs: {', '.join(valid_vmids)}")
                    else:
                        print("❌ No valid VMs to process")
                        continue
                
                # Step 3: Ask for snapshot prefix
                print()
                prefix_input = input("Enter snapshot prefix (default: pre-release): ").strip()
                
                # Set default if empty
                if not prefix_input:
                    prefix_input = "pre-release"
                
                # Validate and clean prefix
                prefix = self.validate_and_clean_prefix(prefix_input)
                if not prefix:
                    if len(prefix_input) > self.max_prefix_length:
                        print(f"ERROR: Prefix too long. Maximum length is {self.max_prefix_length} characters.")
                    else:
                        print("ERROR: Invalid prefix after cleanup")
                    continue
                
                # Step 4: Ask about VM state saving
                self.save_vmstate = self.prompt_vmstate_option()
                
                # Step 5: Create snapshots for selected VMs
                self.create_snapshots_process(prefix, vmids)
                
                print()
                continue_choice = input("Press Enter to continue or 'q' to quit: ").strip().lower()
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
        
        print(f"Command line mode: Creating snapshots for VMs: {' '.join(vmids) if vmids else 'all VMs'}")
        
        # Get VMIDs if not provided
        if not vmids:
            vmids = self.get_all_vmids()
        
        if not vmids:
            print("No VMs found")
            sys.exit(1)
        
        # Validate provided VMIDs exist
        available_vmids = set(self.get_all_vmids())
        valid_vmids = []
        invalid_vmids = []
        
        for vmid in vmids:
            if vmid in available_vmids:
                valid_vmids.append(vmid)
            else:
                invalid_vmids.append(vmid)
        
        if invalid_vmids:
            print(f"⚠️  Warning: VMs not found: {', '.join(invalid_vmids)}")
        
        if not valid_vmids:
            print("❌ No valid VMs to process")
            sys.exit(1)
        
        # Ask about VM state saving in command line mode
        self.save_vmstate = self.prompt_vmstate_option()
        
        # Run the snapshot creation process
        success = self.create_snapshots_process(cleaned_prefix, valid_vmids)
        sys.exit(0 if success else 1)


def main():
    """Main function to handle command line arguments and run the appropriate mode."""
    manager = ProxmoxSnapshotManager()
    
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