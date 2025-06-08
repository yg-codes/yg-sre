#!/usr/bin/env python3

"""
Unified Proxmox VM Management Script (API Version)
Usage: ./pve_vm_manager_api.py

Provides comprehensive VM management capabilities:
- Start/Stop VMs with safety checks
- Create backups with storage selection
- Reuses common functions from snapshot management scripts
"""

import sys
import time
import re
import threading
import json
import getpass
from datetime import datetime
from typing import List, Optional, Dict, Tuple, Set, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
import urllib3

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
        
    def display_usage(self):
        """Display usage information."""
        usage_text = """
Usage: python3 pve_snapshot_api.py [prefix] [vmid1] [vmid2] ... [vmidN]

Creates snapshots with format: <PREFIX>-<3RD_SECTION>-YYYYMMDD-HHMMSS
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
            if clean_name.startswith('fsx-dev-'):
                clean_name = clean_name[8:]
            elif clean_name.startswith('jax-prod-'):
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
    
    def get_all_vmids(self) -> List[str]:
        """Get all VM IDs from all nodes."""
        all_vms = self.get_all_vms()
        return [str(vm['vmid']) for vm in all_vms]
    
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
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
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

class BulkOperationResult:
    """Result of a bulk operation on a single VM."""
    def __init__(self, vmid: str, operation: str, success: bool, message: str = "", duration: float = 0):
        self.vmid = vmid
        self.operation = operation
        self.success = success
        self.message = message
        self.duration = duration
        self.timestamp = datetime.now()

class BulkOperationManager:
    """Manages bulk operations with progress tracking and concurrent execution."""
    
    def __init__(self, max_workers: int = 3):
        self.max_workers = max_workers
        self.results: List[BulkOperationResult] = []
        self.lock = threading.Lock()
        self.cancelled = False
    
    def add_result(self, result: BulkOperationResult):
        """Thread-safe method to add operation result."""
        with self.lock:
            self.results.append(result)
    
    def get_progress(self) -> Tuple[int, int, int]:
        """Return (completed, successful, failed) counts."""
        with self.lock:
            completed = len(self.results)
            successful = sum(1 for r in self.results if r.success)
            failed = completed - successful
            return completed, successful, failed
    
    def cancel(self):
        """Cancel ongoing operations."""
        self.cancelled = True
    
    def print_progress(self, total: int, operation: str):
        """Print current progress."""
        completed, successful, failed = self.get_progress()
        queued = total - completed
        
        print(f"\r{operation} Progress: {completed}/{total} completed, {successful} successful, {failed} failed, {queued} queued", end="", flush=True)
    
    def print_summary(self, operation: str):
        """Print final operation summary."""
        print(f"\n\n{operation} Summary:")
        print("=" * 60)
        
        completed, successful, failed = self.get_progress()
        print(f"Total VMs: {len(self.results)}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {(successful/len(self.results)*100) if self.results else 0:.1f}%")
        
        if failed > 0:
            print(f"\nFailed Operations:")
            print("-" * 40)
            for result in self.results:
                if not result.success:
                    print(f"  VM {result.vmid}: {result.message}")

class VMSelector:
    """Handles VM selection parsing and filtering."""
    
    def __init__(self, vm_manager):
        self.vm_manager = vm_manager
    
    def parse_selection(self, selection: str, all_vms: List[Dict]) -> List[str]:
        """Parse VM selection string and return list of VM IDs."""
        selection = selection.strip()
        
        # Handle special keywords
        if selection.lower() == '*' or selection.lower() == 'all':
            return [vm['vmid'] for vm in all_vms]
        elif selection.lower() == 'running':
            return [vm['vmid'] for vm in all_vms if vm.get('running', False)]
        elif selection.lower() == 'stopped':
            return [vm['vmid'] for vm in all_vms if not vm.get('running', False)]
        elif selection.lower() == 'i' or selection.lower() == 'interactive':
            return self.interactive_selection(all_vms)
        
        # Handle range selection (e.g., "7201-7205")
        if '-' in selection and len(selection.split('-')) == 2:
            try:
                start, end = selection.split('-')
                start_id, end_id = int(start.strip()), int(end.strip())
                vm_ids = []
                for vm in all_vms:
                    vm_id = int(vm['vmid'])
                    if start_id <= vm_id <= end_id:
                        vm_ids.append(vm['vmid'])
                return vm_ids
            except ValueError:
                pass
        
        # Handle comma-separated list (e.g., "7201,7203,7205")
        if ',' in selection:
            vm_ids = []
            for vm_id in selection.split(','):
                vm_id = vm_id.strip()
                if vm_id and any(vm['vmid'] == vm_id for vm in all_vms):
                    vm_ids.append(vm_id)
            return vm_ids
        
        # Handle pattern matching (e.g., "72*")
        if '*' in selection:
            pattern = selection.replace('*', '.*')
            vm_ids = []
            for vm in all_vms:
                if re.match(pattern, vm['vmid']):
                    vm_ids.append(vm['vmid'])
            return vm_ids
        
        # Handle single VM ID
        if any(vm['vmid'] == selection for vm in all_vms):
            return [selection]
        
        return []
    
    def interactive_selection(self, all_vms: List[Dict]) -> List[str]:
        """Interactive checkbox-style VM selection."""
        if not all_vms:
            print("No VMs available for selection")
            return []
        
        print("\n📋 Interactive VM Selection")
        print("=" * 50)
        print("Enter VM numbers to toggle selection (space-separated)")
        print("Commands: 'all' (select all), 'none' (clear all), 'done' (finish)")
        print()
        
        selected_vms: Set[str] = set()
        
        while True:
            # Display VMs with selection status
            print("\nAvailable VMs:")
            print(f"{'#':<3} {'✓':<3} {'VM ID':<8} {'Name':<25} {'Status':<15}")
            print("-" * 60)
            
            for i, vm in enumerate(all_vms, 1):
                selected = "✓" if vm['vmid'] in selected_vms else " "
                status = "🟢 running" if vm.get('running', False) else "🔴 stopped"
                name = vm.get('name', 'Unknown')[:24]
                print(f"{i:<3} {selected:<3} {vm['vmid']:<8} {name:<25} {status:<15}")
            
            print(f"\nSelected: {len(selected_vms)} VMs")
            choice = input("\nEnter selection (numbers, 'all', 'none', 'done'): ").strip().lower()
            
            if choice == 'done':
                break
            elif choice == 'all':
                selected_vms = {vm['vmid'] for vm in all_vms}
                print(f"✅ Selected all {len(selected_vms)} VMs")
            elif choice == 'none':
                selected_vms.clear()
                print("✅ Cleared all selections")
            else:
                # Parse numbers
                for num_str in choice.split():
                    try:
                        num = int(num_str)
                        if 1 <= num <= len(all_vms):
                            vm_id = all_vms[num-1]['vmid']
                            if vm_id in selected_vms:
                                selected_vms.remove(vm_id)
                                print(f"✅ Deselected VM {vm_id}")
                            else:
                                selected_vms.add(vm_id)
                                print(f"✅ Selected VM {vm_id}")
                        else:
                            print(f"❌ Invalid number: {num}")
                    except ValueError:
                        print(f"❌ Invalid input: {num_str}")
        
        return list(selected_vms)
    
    def display_selection_help(self):
        """Display help for VM selection formats."""
        print("\n📚 VM Selection Help")
        print("=" * 40)
        print("Selection formats:")
        print("  *           - All VMs")
        print("  running     - All running VMs")
        print("  stopped     - All stopped VMs")
        print("  7201-7205   - Range of VM IDs")
        print("  7201,7203   - Specific VM IDs (comma-separated)")
        print("  72*         - Pattern matching (VMs starting with '72')")
        print("  i           - Interactive selection")
        print("  7201        - Single VM ID")
        print()

class ProxmoxVMManager(ProxmoxSnapshotManager):
    """Unified Proxmox VM management class extending snapshot capabilities."""
    
    def __init__(self):
        super().__init__()
        self.vm_selector = VMSelector(self)
        
    def display_usage(self):
        """Display usage information."""
        usage_text = """
Proxmox VM Management Tool (API Version)
========================================

This tool provides comprehensive VM management capabilities:
- View all VMs with real-time status
- Start/Stop VMs with safety checks
- Create VM backups with storage selection
- Real-time task monitoring
- Multi-node cluster support

API Authentication Options:
  1. Username/Password (prompted)
  2. API Token (set environment variables):
     export PVE_HOST=your-proxmox-host
     export PVE_USER=username@realm
     export PVE_TOKEN_NAME=token-name
     export PVE_TOKEN_VALUE=token-value

Usage: python3 pve_vm_manager_api.py
"""
        print(usage_text)
    
    def get_vm_storages(self) -> List[Dict]:
        """Get all available storages suitable for VM disks."""
        storages = []
        nodes = self.get_nodes()
        
        for node in nodes:
            try:
                node_storages = self.api._request('GET', f'/nodes/{node["node"]}/storage')
                for storage in node_storages:
                    # Check if storage supports 'images' content (VM disks)
                    storage_info = self.api._request('GET', f'/nodes/{node["node"]}/storage/{storage["storage"]}/status')
                    content = storage_info.get('content', '')
                    if 'images' in content or 'rootdir' in content:
                        storage['node'] = node['node']
                        storage['content_types'] = content
                        storages.append(storage)
            except ProxmoxAPIError:
                continue
        
        # Remove duplicates (shared storages appear on multiple nodes)
        unique_storages = {}
        for storage in storages:
            key = storage['storage']
            if key not in unique_storages:
                unique_storages[key] = storage
        
        return list(unique_storages.values())
    
    def display_vm_storage_list(self) -> List[Dict]:
        """Display available VM disk storages and return the list."""
        storages = self.get_vm_storages()
        
        if not storages:
            print("❌ No VM disk storages found")
            return []
        
        print("\nAvailable VM Disk Storages:")
        print("=" * 80)
        print(f"{'#':<3} {'Storage':<15} {'Type':<10} {'Status':<10} {'Content Types':<20} {'Free Space':<15}")
        print("-" * 80)
        
        for i, storage in enumerate(storages, 1):
            name = storage['storage']
            storage_type = storage.get('type', 'unknown')
            content_types = storage.get('content_types', 'unknown')
            
            # Get detailed status for first node that has this storage
            try:
                status_info = self.api._request('GET', f'/nodes/{storage["node"]}/storage/{name}/status')
                
                if status_info.get('active'):
                    status = "🟢 active"
                else:
                    status = "🔴 inactive"
                
                # Convert bytes to human-readable format
                avail = status_info.get('avail', 0)
                if avail > 0:
                    free_gb = avail / (1024**3)
                    free_space = f"{free_gb:.1f} GB"
                else:
                    free_space = "N/A"
                
            except ProxmoxAPIError:
                status = "❌ error"
                free_space = "N/A"
            
            print(f"{i:<3} {name:<15} {storage_type:<10} {status:<10} {content_types:<20} {free_space:<15}")
        
        print("-" * 80)
        print(f"Total VM disk storages: {len(storages)}")
        
        return storages
    
    def get_available_storages(self) -> List[Dict]:
        """Get all available backup storages from all nodes."""
        storages = []
        nodes = self.get_nodes()
        
        for node in nodes:
            try:
                node_storages = self.api._request('GET', f'/nodes/{node["node"]}/storage')
                for storage in node_storages:
                    # Check if storage supports backup content
                    storage_info = self.api._request('GET', f'/nodes/{node["node"]}/storage/{storage["storage"]}/status')
                    if storage_info.get('content', '').find('backup') != -1 or storage_info.get('content', '').find('vztmpl') != -1:
                        storage['node'] = node['node']
                        storages.append(storage)
            except ProxmoxAPIError:
                continue
        
        # Remove duplicates (shared storages appear on multiple nodes)
        unique_storages = {}
        for storage in storages:
            key = storage['storage']
            if key not in unique_storages:
                unique_storages[key] = storage
        
        return list(unique_storages.values())
    
    def display_storage_list(self) -> List[Dict]:
        """Display available backup storages and return the list."""
        storages = self.get_available_storages()
        
        if not storages:
            print("❌ No backup-capable storages found")
            return []
        
        print("\nAvailable Backup Storages:")
        print("=" * 70)
        print(f"{'#':<3} {'Storage':<15} {'Type':<10} {'Status':<10} {'Free Space':<15} {'Total Space'}")
        print("-" * 70)
        
        for i, storage in enumerate(storages, 1):
            name = storage['storage']
            storage_type = storage.get('type', 'unknown')
            
            # Get detailed status for first node that has this storage
            try:
                status_info = self.api._request('GET', f'/nodes/{storage["node"]}/storage/{name}/status')
                
                if status_info.get('active'):
                    status = "🟢 active"
                else:
                    status = "🔴 inactive"
                
                # Convert bytes to human-readable format
                avail = status_info.get('avail', 0)
                total = status_info.get('total', 0)
                
                if total > 0:
                    free_gb = avail / (1024**3)
                    total_gb = total / (1024**3)
                    free_space = f"{free_gb:.1f} GB"
                    total_space = f"{total_gb:.1f} GB"
                else:
                    free_space = "N/A"
                    total_space = "N/A"
                
            except ProxmoxAPIError:
                status = "❌ error"
                free_space = "N/A"
                total_space = "N/A"
            
            print(f"{i:<3} {name:<15} {storage_type:<10} {status:<10} {free_space:<15} {total_space}")
        
        print("-" * 70)
        print(f"Total storages: {len(storages)}")
        
        return storages
    
    def stop_vm(self, vmid: str) -> bool:
        """Stop a VM with safety checks."""
        node = self.find_vm_node(vmid)
        if not node:
            print("❌ Could not find node for VM")
            return False
        
        try:
            print("🛑 Stopping VM...")
            task_id = self.api._request('POST', f'/nodes/{node}/qemu/{vmid}/status/stop')
            
            # Monitor task progress
            success = self.monitor_task(node, task_id, f"VM {vmid} shutdown")
            
            if success:
                print("✅ VM stopped successfully!")
            else:
                print("❌ Failed to stop VM!")
            
            return success
            
        except ProxmoxAPIError as e:
            print(f"❌ Failed to stop VM: {e.message}")
            return False

    def shutdown_vm(self, vmid: str) -> bool:
        """Gracefully shutdown a VM using ACPI signal."""
        node = self.find_vm_node(vmid)
        if not node:
            print("❌ Could not find node for VM")
            return False
        
        try:
            print("🔄 Gracefully shutting down VM...")
            task_id = self.api._request('POST', f'/nodes/{node}/qemu/{vmid}/status/shutdown')
            
            # Monitor task progress
            success = self.monitor_task(node, task_id, f"VM {vmid} graceful shutdown")
            
            if success:
                print("✅ VM shutdown successfully!")
            else:
                print("❌ Failed to shutdown VM!")
            
            return success
            
        except ProxmoxAPIError as e:
            print(f"❌ Failed to shutdown VM: {e.message}")
            return False
    
    def start_vm(self, vmid: str) -> bool:
        """Start a VM (reused from parent class)."""
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
    
    def create_backup(self, vmid: str, storage: str, mode: str, compress: str = 'zstd') -> bool:
        """Create a VM backup."""
        node = self.find_vm_node(vmid)
        if not node:
            print("❌ Could not find node for VM")
            return False
        
        try:
            print(f"\n🔄 Creating backup...")
            print(f"  Storage: {storage}")
            print(f"  Mode: {mode}")
            print(f"  Compression: {compress}")
            
            # Prepare backup data
            backup_data = {
                'vmid': vmid,
                'storage': storage,
                'mode': mode,
                'compress': compress,
                'remove': '0'  # Don't remove old backups
            }
            
            # Create backup
            task_id = self.api._request('POST', f'/nodes/{node}/vzdump', data=backup_data)
            
            # Monitor task progress
            success = self.monitor_task(node, task_id, f"Backup for VM {vmid}")
            
            if success:
                print("✅ Backup completed successfully!")
                
                # Try to get backup file info
                try:
                    # List backups for this VM
                    backups = self.api._request('GET', f'/nodes/{node}/storage/{storage}/content', 
                                              params={'vmid': vmid})
                    
                    # Find the most recent backup
                    if backups:
                        latest_backup = max(backups, key=lambda x: x.get('ctime', 0))
                        if latest_backup:
                            size_gb = latest_backup.get('size', 0) / (1024**3)
                            print(f"  Backup file: {latest_backup.get('volid', 'unknown')}")
                            print(f"  Size: {size_gb:.2f} GB")
                except:
                    pass
            else:
                print("❌ Backup failed!")
            
            return success
            
        except ProxmoxAPIError as e:
            print(f"❌ Failed to create backup: {e.message}")
            return False
    
    def list_backups_for_vm(self, vmid: str, storage: str = None) -> List[Dict]:
        """List all backups for a specific VM from specified storage or all storages."""
        all_backups = []
        
        if storage:
            # Check specific storage
            storages_to_check = [{'storage': storage}]
        else:
            # Check all backup-capable storages
            storages_to_check = self.get_available_storages()
        
        for storage_info in storages_to_check:
            storage_name = storage_info['storage']
            storage_accessed = False
            
            # Try each node until we find one that can access this storage
            nodes = self.get_nodes()
            for node in nodes:
                try:
                    # Try with backup content filter first
                    contents = []
                    try:
                        contents = self.api._request('GET', f'/nodes/{node["node"]}/storage/{storage_name}/content',
                                                   params={'content': 'backup'})
                    except ProxmoxAPIError:
                        pass  # Will use fallback below
                    
                    # Always also try without filter to catch files that might not be properly tagged
                    try:
                        all_contents = self.api._request('GET', f'/nodes/{node["node"]}/storage/{storage_name}/content')
                        manual_contents = [item for item in all_contents if item.get('content') == 'backup' or 'vzdump' in item.get('volid', '')]
                        
                        # Merge results, avoiding duplicates
                        seen_volids = {item.get('volid') for item in contents}
                        for item in manual_contents:
                            if item.get('volid') not in seen_volids:
                                contents.append(item)
                    except ProxmoxAPIError:
                        # If both methods fail, we'll have an empty contents list
                        pass
                    
                    # Filter for backups of this VM
                    for item in contents:
                        # Enhanced backup identification logic
                        is_backup = False
                        item_vmid = item.get('vmid')
                        volid = item.get('volid', '')
                        
                        # Method 1: Direct VMID match (handle both string and int)
                        if item_vmid is not None and str(item_vmid) == str(vmid):
                            is_backup = True
                        
                        # Method 2: Check volid pattern for backup files
                        # More comprehensive pattern matching
                        backup_patterns = [
                            f'vzdump-qemu-{vmid}-',
                            f'vzdump-lxc-{vmid}-',
                            f'backup-{vmid}-',
                            f'vm-{vmid}-'
                        ]
                        
                        for pattern in backup_patterns:
                            if pattern in volid:
                                is_backup = True
                                # Extract VMID from volid if not set in item
                                if item_vmid is None:
                                    item['vmid'] = vmid
                                break
                        
                        # Method 3: Parse volid for VMID (backup files often contain VMID)
                        if not is_backup and 'vzdump' in volid:
                            try:
                                # Extract VMID from patterns like vzdump-qemu-123-2024_01_01-12_00_00.vma.zst
                                parts = volid.split('-')
                                if len(parts) >= 3:
                                    extracted_vmid = parts[2]
                                    if extracted_vmid == str(vmid):
                                        is_backup = True
                                        item['vmid'] = vmid
                            except (IndexError, ValueError):
                                pass
                        
                        if is_backup:
                            item['storage'] = storage_name
                            item['node'] = node['node']
                            # Ensure content type is set
                            if 'content' not in item:
                                item['content'] = 'backup'
                            # Add to list if not already present (avoid duplicates)
                            if not any(existing['volid'] == item['volid'] for existing in all_backups):
                                all_backups.append(item)
                    
                    storage_accessed = True
                    # Continue checking other nodes for local storage files
                    
                except ProxmoxAPIError as e:
                    # Only show error for debugging if specifically requested storage
                    if storage and len(storages_to_check) == 1:
                        print(f"  Debug: Could not access storage '{storage_name}' from node '{node['node']}': {e.message}")
                    continue  # Try next node
            
            # If no node could access the storage, show warning for specific storage requests
            if not storage_accessed and storage and len(storages_to_check) == 1:
                print(f"  ⚠️  Warning: Storage '{storage_name}' is not accessible from any node")
        
        # Sort by creation time (newest first)
        all_backups.sort(key=lambda x: x.get('ctime', 0), reverse=True)
        
        return all_backups
    
    def list_all_backups_in_storage(self, storage: str) -> List[Dict]:
        """List ALL backups in a storage, not filtered by VM."""
        all_backups = []
        
        # Try each node until we find one that can access this storage
        nodes = self.get_nodes()
        for node in nodes:
            try:
                # Try with backup content filter first
                contents = []
                try:
                    contents = self.api._request('GET', f'/nodes/{node["node"]}/storage/{storage}/content',
                                               params={'content': 'backup'})
                except ProxmoxAPIError:
                    pass  # Will use fallback below
                
                # Always also try without filter to catch files that might not be properly tagged
                try:
                    all_contents = self.api._request('GET', f'/nodes/{node["node"]}/storage/{storage}/content')
                    manual_contents = [item for item in all_contents if item.get('content') == 'backup' or 'vzdump' in item.get('volid', '')]
                    
                    # Merge results, avoiding duplicates
                    seen_volids = {item.get('volid') for item in contents}
                    for item in manual_contents:
                        if item.get('volid') not in seen_volids:
                            contents.append(item)
                except ProxmoxAPIError:
                    # If both methods fail, we'll have an empty contents list
                    pass
                
                # Process all backup items
                for item in contents:
                    item['storage'] = storage
                    item['node'] = node['node']
                    # Ensure content type is set
                    if 'content' not in item:
                        item['content'] = 'backup'
                    
                    # Try to extract VMID from volid if not present
                    if 'vmid' not in item or item.get('vmid') is None:
                        volid = item.get('volid', '')
                        if 'vzdump' in volid:
                            try:
                                # Extract VMID from patterns like vzdump-qemu-123-2024_01_01-12_00_00.vma.zst
                                parts = volid.split('-')
                                if len(parts) >= 3:
                                    item['vmid'] = parts[2]
                            except (IndexError, ValueError):
                                pass
                    
                    all_backups.append(item)
                
                # Continue checking other nodes for local storage files
            except ProxmoxAPIError as e:
                continue  # Try next node
        
        return all_backups
    
    def debug_backup_search(self, vmid: str, storage: str = None):
        """Enhanced diagnostic function to debug backup search issues for a specific VM."""
        print(f"\n🔍 DEBUG: Backup search for VM {vmid}")
        print("=" * 80)
        
        if storage:
            storages_to_check = [{'storage': storage}]
            print(f"Searching in specific storage: {storage}")
        else:
            storages_to_check = self.get_available_storages()
            print(f"Searching across {len(storages_to_check)} available storages")
        
        print(f"Target VM ID: {vmid} (type: {type(vmid)})")
        print("-" * 80)
        
        for storage_info in storages_to_check:
            storage_name = storage_info['storage']
            print(f"\n📦 Storage: {storage_name}")
            print("-" * 40)
            
            nodes = self.get_nodes()
            storage_accessed = False
            
            for node in nodes:
                print(f"  Trying node: {node['node']}")
                try:
                    # Try with backup content filter first
                    try:
                        contents = self.api._request('GET', f'/nodes/{node["node"]}/storage/{storage_name}/content',
                                                   params={'content': 'backup'})
                        print(f"    📋 Used content filter - found {len(contents)} backup item(s)")
                    except ProxmoxAPIError:
                        # Fallback: list all content and filter manually
                        all_contents = self.api._request('GET', f'/nodes/{node["node"]}/storage/{storage_name}/content')
                        contents = [item for item in all_contents if item.get('content') == 'backup' or 'vzdump' in item.get('volid', '')]
                        print(f"    📋 Used manual filter - found {len(contents)} backup item(s) from {len(all_contents)} total items")
                    print(f"    ✅ Accessed storage from {node['node']}")
                    
                    # Analyze each item in detail
                    vm_backups = 0
                    for i, item in enumerate(contents):
                        print(f"\n    Item {i+1}:")
                        print(f"      volid: {item.get('volid', 'N/A')}")
                        print(f"      vmid: {item.get('vmid', 'N/A')} (type: {type(item.get('vmid'))})")
                        print(f"      content: {item.get('content', 'N/A')}")
                        print(f"      size: {item.get('size', 0)} bytes")
                        
                        # Test matching logic
                        item_vmid = item.get('vmid')
                        volid = item.get('volid', '')
                        
                        matches = []
                        
                        # Test direct VMID match
                        if item_vmid is not None and str(item_vmid) == str(vmid):
                            matches.append("Direct VMID match")
                        
                        # Test volid patterns
                        backup_patterns = [
                            f'vzdump-qemu-{vmid}-',
                            f'vzdump-lxc-{vmid}-',
                            f'backup-{vmid}-',
                            f'vm-{vmid}-'
                        ]
                        
                        for pattern in backup_patterns:
                            if pattern in volid:
                                matches.append(f"Pattern match: {pattern}")
                        
                        # Test vzdump parsing
                        if 'vzdump' in volid:
                            try:
                                parts = volid.split('-')
                                if len(parts) >= 3:
                                    extracted_vmid = parts[2]
                                    if extracted_vmid == str(vmid):
                                        matches.append(f"Parsed VMID match: {extracted_vmid}")
                            except (IndexError, ValueError):
                                pass
                        
                        if matches:
                            print(f"      ✅ MATCHES: {', '.join(matches)}")
                            vm_backups += 1
                        else:
                            print(f"      ❌ No match for VM {vmid}")
                    
                    print(f"\n    🎯 Total matches for VM {vmid}: {vm_backups}")
                    storage_accessed = True
                    break
                    
                except ProxmoxAPIError as e:
                    print(f"    ❌ Failed to access from {node['node']}: {e.message}")
                    continue
            
            if not storage_accessed:
                print(f"  ⚠️  Could not access storage '{storage_name}' from any node")
        
        print(f"\n{'='*80}")
        print("Debug complete")
    
    def debug_backup_search(self, vmid: str, storage: str = None):
        """Detailed debugging function to troubleshoot backup search issues."""
        print(f"\n🔍 DEBUG: Searching for backups of VM {vmid}")
        print("=" * 80)
        
        if storage:
            storages_to_check = [{'storage': storage}]
            print(f"Target storage: {storage}")
        else:
            storages_to_check = self.get_available_storages()
            print(f"Checking all {len(storages_to_check)} available storages")
        
        print(f"Target VMID: {vmid} (type: {type(vmid)})")
        print()
        
        found_backups = []
        
        for storage_info in storages_to_check:
            storage_name = storage_info['storage']
            print(f"📁 Storage: {storage_name}")
            print("-" * 40)
            
            nodes = self.get_nodes()
            storage_accessed = False
            
            for node in nodes:
                print(f"  🖥️  Trying node: {node['node']}")
                
                try:
                    # Try content filter first
                    try:
                        print("    Attempting API call with content=backup filter...")
                        contents = self.api._request('GET', f'/nodes/{node["node"]}/storage/{storage_name}/content',
                                                   params={'content': 'backup'})
                        print(f"    ✅ Success with filter: Found {len(contents)} items")
                    except ProxmoxAPIError as e:
                        print(f"    ⚠️  Filter failed ({e.message}), trying without filter...")
                        contents = []
                    
                    # Always also try without filter for comparison
                    print("    Testing without content filter for comparison...")
                    try:
                        all_contents = self.api._request('GET', f'/nodes/{node["node"]}/storage/{storage_name}/content')
                        print(f"    📋 Total items in storage: {len(all_contents)}")
                        
                        # Show all items for debugging
                        backup_items = []
                        for item in all_contents:
                            volid = item.get('volid', '')
                            content_type = item.get('content', '')
                            print(f"      - {volid} (content: {content_type})")
                            
                            if content_type == 'backup' or 'vzdump' in volid:
                                backup_items.append(item)
                        
                        print(f"    🎯 Backup items found manually: {len(backup_items)}")
                        
                        # Use the manual filter if we found more items
                        if len(backup_items) > len(contents):
                            print("    📌 Using manual filter results (found more items)")
                            contents = backup_items
                        
                    except ProxmoxAPIError as e:
                        print(f"    ❌ Failed to list all contents: {e.message}")
                    
                    storage_accessed = True
                    
                    print(f"    🔍 Analyzing {len(contents)} items for VMID {vmid}:")
                    
                    for i, item in enumerate(contents):
                        item_vmid = item.get('vmid')
                        volid = item.get('volid', '')
                        content_type = item.get('content', '')
                        
                        print(f"      Item {i+1}:")
                        print(f"        volid: {volid}")
                        print(f"        vmid: {item_vmid} (type: {type(item_vmid)})")
                        print(f"        content: {content_type}")
                        
                        # Test all identification methods
                        matches = []
                        
                        # Method 1: Direct VMID match
                        if item_vmid is not None and str(item_vmid) == str(vmid):
                            matches.append("Direct VMID match")
                        
                        # Method 2: Pattern matching
                        backup_patterns = [f'vzdump-qemu-{vmid}-', f'vzdump-lxc-{vmid}-', f'backup-{vmid}-', f'vm-{vmid}-']
                        for pattern in backup_patterns:
                            if pattern in volid:
                                matches.append(f"Pattern: {pattern}")
                                break
                        
                        # Method 3: Extract VMID from volid
                        if 'vzdump' in volid:
                            try:
                                parts = volid.split('-')
                                if len(parts) >= 3:
                                    extracted_vmid = parts[2]
                                    if extracted_vmid == str(vmid):
                                        matches.append(f"Extracted VMID: {extracted_vmid}")
                            except:
                                pass
                        
                        if matches:
                            print(f"        ✅ MATCH: {', '.join(matches)}")
                            found_backups.append({
                                'volid': volid,
                                'vmid': item_vmid or vmid,
                                'storage': storage_name,
                                'node': node['node'],
                                'match_reason': matches
                            })
                        else:
                            print(f"        ❌ No match")
                    
                    storage_accessed = True
                    # Continue to check other nodes too (don't break)
                    
                except ProxmoxAPIError as e:
                    print(f"    ❌ Failed to access storage: {e.message}")
                    continue
            
            if not storage_accessed:
                print(f"  ❌ Storage '{storage_name}' not accessible from any node")
            
            print()
        
        print(f"🎯 SUMMARY:")
        print(f"Found {len(found_backups)} matching backup(s) for VM {vmid}")
        for backup in found_backups:
            print(f"  - {backup['volid']} ({', '.join(backup['match_reason'])})")
        
        print("=" * 80)
        return found_backups

    def check_all_backups(self):
        """Diagnostic function to check all backups across all storages."""
        print("\n🔍 Checking ALL backups across ALL storages...")
        print("=" * 80)
        
        storages = self.get_available_storages()
        total_backups = 0
        
        for storage in storages:
            storage_name = storage['storage']
            print(f"\nStorage: {storage_name}")
            print("-" * 40)
            
            backups = self.list_all_backups_in_storage(storage_name)
            
            if backups:
                print(f"Found {len(backups)} backup(s):")
                for backup in backups[:5]:  # Show first 5
                    volid = backup.get('volid', 'unknown')
                    vmid = backup.get('vmid', 'unknown')
                    size_gb = backup.get('size', 0) / (1024**3)
                    print(f"  - VM {vmid}: {volid} ({size_gb:.2f} GB)")
                
                if len(backups) > 5:
                    print(f"  ... and {len(backups) - 5} more")
                
                total_backups += len(backups)
            else:
                print("  No backups found")
        
        print(f"\n{'='*80}")
        print(f"Total backups found: {total_backups}")
        print(f"{'='*80}")
    
    def display_backup_list(self, backups: List[Dict]) -> List[Dict]:
        """Display formatted list of backups."""
        if not backups:
            print("❌ No backups found")
            return []
        
        print("\nAvailable Backups (Newest First):")
        print("=" * 110)
        print(f"{'#':<3} {'Backup File':<50} {'Size (GB)':<10} {'Created':<20} {'Storage':<15} {'Node'}")
        print("-" * 110)
        
        for i, backup in enumerate(backups, 1):
            volid = backup.get('volid', 'unknown')
            # Extract just the filename from volid
            filename = volid.split('/')[-1] if '/' in volid else volid
            
            size_gb = backup.get('size', 0) / (1024**3)
            
            # Format creation time
            ctime = backup.get('ctime', 0)
            if ctime:
                created = datetime.fromtimestamp(ctime).strftime('%Y-%m-%d %H:%M:%S')
            else:
                created = 'Unknown'
            
            storage = backup.get('storage', 'unknown')
            node = backup.get('node', 'unknown')
            
            # Truncate filename if too long
            if len(filename) > 49:
                filename = filename[:46] + "..."
            
            print(f"{i:<3} {filename:<50} {size_gb:<10.2f} {created:<20} {storage:<15} {node}")
        
        print("-" * 110)
        print(f"Total backups: {len(backups)}")
        
        return backups
    
    def get_backup_config(self, volid: str, node: str) -> Dict:
        """Extract configuration from a backup file."""
        try:
            # Get backup configuration
            config = self.api._request('GET', f'/nodes/{node}/vzdump/extractconfig', 
                                     params={'volume': volid})
            return config
        except ProxmoxAPIError as e:
            print(f"❌ Failed to extract backup configuration: {e.message}")
            return {}
    
    def check_and_handle_protection(self, vmid: str) -> bool:
        """Check if VM has protection enabled and handle it."""
        vm_info = self.get_vm_info(vmid)
        if not vm_info:
            print("❌ Could not get VM info to check protection")
            return False
        
        config = vm_info.get('config', {})
        protection = config.get('protection', '0')
        
        # Check if protection is enabled (protection = 1)
        if protection == '1' or protection == 1:
            print("\n⚠️  VM PROTECTION DETECTED")
            print("=" * 50)
            print("This VM has protection mode enabled, which prevents:")
            print("  • VM deletion")
            print("  • Configuration changes") 
            print("  • Backup restore operations")
            print("=" * 50)
            print()
            print("Options:")
            print("1. Disable protection and continue with restore")
            print("2. Cancel restore operation")
            print()
            
            choice = input("Select option (1-2): ").strip()
            
            if choice == '1':
                print("\n🔓 Disabling VM protection...")
                node = self.find_vm_node(vmid)
                if not node:
                    print("❌ Could not find VM node to disable protection")
                    return False
                
                try:
                    # Disable protection
                    self.api._request('PUT', f'/nodes/{node}/qemu/{vmid}/config', 
                                    data={'protection': '0'})
                    print("✅ VM protection disabled successfully")
                    return True
                except ProxmoxAPIError as e:
                    print(f"❌ Failed to disable protection: {e.message}")
                    return False
            else:
                print("Restore operation cancelled")
                return False
        
        # Protection not enabled or already disabled
        return True
    
    def _start_vm_silent(self, vmid: str) -> bool:
        """Start a VM without output (for bulk operations)."""
        node = self.find_vm_node(vmid)
        if not node:
            return False
        
        try:
            task_id = self.api._request('POST', f'/nodes/{node}/qemu/{vmid}/status/start')
            # Monitor task without output
            return self._monitor_task_silent(node, task_id)
        except ProxmoxAPIError:
            return False
    
    def _stop_vm_silent(self, vmid: str) -> bool:
        """Stop a VM without output (for bulk operations)."""
        node = self.find_vm_node(vmid)
        if not node:
            return False
        
        try:
            task_id = self.api._request('POST', f'/nodes/{node}/qemu/{vmid}/status/stop')
            # Monitor task without output
            return self._monitor_task_silent(node, task_id)
        except ProxmoxAPIError:
            return False

    def _shutdown_vm_silent(self, vmid: str) -> bool:
        """Gracefully shutdown a VM without output (for bulk operations)."""
        node = self.find_vm_node(vmid)
        if not node:
            return False
        
        try:
            task_id = self.api._request('POST', f'/nodes/{node}/qemu/{vmid}/status/shutdown')
            # Monitor task without output
            return self._monitor_task_silent(node, task_id)
        except ProxmoxAPIError:
            return False
    
    def _create_backup_silent(self, vmid: str, storage: str, mode: str, compress: str = 'zstd') -> bool:
        """Create a VM backup without output (for bulk operations)."""
        node = self.find_vm_node(vmid)
        if not node:
            return False
        
        try:
            backup_data = {
                'vmid': vmid,
                'storage': storage,
                'mode': mode,
                'compress': compress,
                'remove': '0'
            }
            
            task_id = self.api._request('POST', f'/nodes/{node}/vzdump', data=backup_data)
            # Monitor task without output
            return self._monitor_task_silent(node, task_id)
        except ProxmoxAPIError:
            return False
    
    def _monitor_task_silent(self, node: str, task_id: str) -> bool:
        """Monitor a Proxmox task silently (for bulk operations)."""
        while True:
            try:
                task_status = self.api._request('GET', f'/nodes/{node}/tasks/{task_id}/status')
                status = task_status.get('status', 'unknown')
                
                if status == 'stopped':
                    exit_status = task_status.get('exitstatus', '')
                    return exit_status == 'OK'
                elif status in ['error', 'cancelled']:
                    return False
                
                time.sleep(2)  # Wait 2 seconds before checking again
                
            except ProxmoxAPIError:
                return False
    
    def restore_backup(self, vmid: str, volid: str, node: str, storage: str = None) -> bool:
        """Restore a VM from backup."""
        try:
            print(f"\n🔄 Restoring VM from backup...")
            print(f"  Backup: {volid}")
            print(f"  Target VMID: {vmid}")
            
            # Prepare restore data
            restore_data = {
                'vmid': vmid,
                'archive': volid,
                'force': '1'  # Overwrite existing VM
            }
            
            # If storage is specified, use it
            if storage:
                restore_data['storage'] = storage
            
            # Execute restore
            task_id = self.api._request('POST', f'/nodes/{node}/qemu', data=restore_data)
            
            # Monitor task progress
            success = self.monitor_task(node, task_id, f"Restore for VM {vmid}")
            
            if success:
                print("✅ Restore completed successfully!")
            else:
                print("❌ Restore failed!")
            
            return success
            
        except ProxmoxAPIError as e:
            print(f"❌ Failed to restore backup: {e.message}")
            return False
    
    # ============================================================================
    # BULK OPERATIONS
    # ============================================================================
    
    def bulk_start_vms(self, vm_ids: List[str], max_workers: int = 3) -> BulkOperationManager:
        """Start multiple VMs concurrently."""
        operation_manager = BulkOperationManager(max_workers)
        
        print(f"\n🚀 Starting {len(vm_ids)} VMs (max {max_workers} concurrent)")
        print("=" * 60)
        
        def start_single_vm(vmid: str) -> BulkOperationResult:
            start_time = time.time()
            try:
                # Check if VM is already running
                vm_info = self.get_vm_info(vmid)
                if not vm_info:
                    return BulkOperationResult(vmid, "start", False, "VM not found", time.time() - start_time)
                
                if vm_info.get('running', False):
                    return BulkOperationResult(vmid, "start", True, "Already running", time.time() - start_time)
                
                # Start the VM (silent version for bulk operations)
                success = self._start_vm_silent(vmid)
                message = "Started successfully" if success else "Failed to start"
                return BulkOperationResult(vmid, "start", success, message, time.time() - start_time)
                
            except Exception as e:
                return BulkOperationResult(vmid, "start", False, str(e), time.time() - start_time)
        
        # Execute operations concurrently
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_vmid = {executor.submit(start_single_vm, vmid): vmid for vmid in vm_ids}
            
            for future in as_completed(future_to_vmid):
                if operation_manager.cancelled:
                    break
                    
                result = future.result()
                operation_manager.add_result(result)
                
                # Print progress
                operation_manager.print_progress(len(vm_ids), "Start VMs")
        
        operation_manager.print_summary("Bulk Start VMs")
        return operation_manager
    
    def bulk_shutdown_vms(self, vm_ids: List[str], max_workers: int = 3) -> BulkOperationManager:
        """Gracefully shutdown multiple VMs concurrently."""
        operation_manager = BulkOperationManager(max_workers)
        
        print(f"\n🔄 Gracefully shutting down {len(vm_ids)} VMs (max {max_workers} concurrent)")
        print("=" * 60)
        
        def shutdown_single_vm(vmid: str) -> BulkOperationResult:
            start_time = time.time()
            try:
                # Check if VM is already stopped
                vm_info = self.get_vm_info(vmid)
                if not vm_info:
                    return BulkOperationResult(vmid, "shutdown", False, "VM not found", time.time() - start_time)
                
                if not vm_info.get('running', False):
                    return BulkOperationResult(vmid, "shutdown", True, "Already stopped", time.time() - start_time)
                
                # Shutdown the VM (silent version for bulk operations)
                success = self._shutdown_vm_silent(vmid)
                message = "Shutdown successfully" if success else "Failed to shutdown"
                return BulkOperationResult(vmid, "shutdown", success, message, time.time() - start_time)
                
            except Exception as e:
                return BulkOperationResult(vmid, "shutdown", False, str(e), time.time() - start_time)
        
        # Execute operations concurrently
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_vmid = {executor.submit(shutdown_single_vm, vmid): vmid for vmid in vm_ids}
            
            for future in as_completed(future_to_vmid):
                if operation_manager.cancelled:
                    break
                    
                result = future.result()
                operation_manager.add_result(result)
                operation_manager.print_progress(len(vm_ids), "Shutdown VMs")
        
        operation_manager.print_summary("Bulk Shutdown VMs")
        return operation_manager
    
    def bulk_stop_vms(self, vm_ids: List[str], max_workers: int = 3) -> BulkOperationManager:
        """Stop multiple VMs concurrently."""
        operation_manager = BulkOperationManager(max_workers)
        
        print(f"\n🛑 Stopping {len(vm_ids)} VMs (max {max_workers} concurrent)")
        print("=" * 60)
        
        def stop_single_vm(vmid: str) -> BulkOperationResult:
            start_time = time.time()
            try:
                # Check if VM is already stopped
                vm_info = self.get_vm_info(vmid)
                if not vm_info:
                    return BulkOperationResult(vmid, "stop", False, "VM not found", time.time() - start_time)
                
                if not vm_info.get('running', False):
                    return BulkOperationResult(vmid, "stop", True, "Already stopped", time.time() - start_time)
                
                # Stop the VM (silent version for bulk operations)
                success = self._stop_vm_silent(vmid)
                message = "Stopped successfully" if success else "Failed to stop"
                return BulkOperationResult(vmid, "stop", success, message, time.time() - start_time)
                
            except Exception as e:
                return BulkOperationResult(vmid, "stop", False, str(e), time.time() - start_time)
        
        # Execute operations concurrently
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_vmid = {executor.submit(stop_single_vm, vmid): vmid for vmid in vm_ids}
            
            for future in as_completed(future_to_vmid):
                if operation_manager.cancelled:
                    break
                    
                result = future.result()
                operation_manager.add_result(result)
                
                # Print progress
                operation_manager.print_progress(len(vm_ids), "Stop VMs")
        
        operation_manager.print_summary("Bulk Stop VMs")
        return operation_manager
    
    def bulk_create_backups(self, vm_ids: List[str], storage: str, mode: str = 'snapshot', 
                           compress: str = 'zstd', max_workers: int = 2) -> BulkOperationManager:
        """Create backups for multiple VMs concurrently."""
        operation_manager = BulkOperationManager(max_workers)
        
        print(f"\n💾 Creating backups for {len(vm_ids)} VMs")
        print(f"Storage: {storage}, Mode: {mode}, Compression: {compress}")
        print(f"Max concurrent operations: {max_workers}")
        print("=" * 60)
        
        def backup_single_vm(vmid: str) -> BulkOperationResult:
            start_time = time.time()
            try:
                # Check if VM exists
                vm_info = self.get_vm_info(vmid)
                if not vm_info:
                    return BulkOperationResult(vmid, "backup", False, "VM not found", time.time() - start_time)
                
                # Create backup (silent version for bulk operations)
                success = self._create_backup_silent(vmid, storage, mode, compress)
                message = "Backup created successfully" if success else "Failed to create backup"
                return BulkOperationResult(vmid, "backup", success, message, time.time() - start_time)
                
            except Exception as e:
                return BulkOperationResult(vmid, "backup", False, str(e), time.time() - start_time)
        
        # Execute operations concurrently
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_vmid = {executor.submit(backup_single_vm, vmid): vmid for vmid in vm_ids}
            
            for future in as_completed(future_to_vmid):
                if operation_manager.cancelled:
                    break
                    
                result = future.result()
                operation_manager.add_result(result)
                
                # Print progress
                operation_manager.print_progress(len(vm_ids), "Create Backups")
        
        operation_manager.print_summary("Bulk Create Backups")
        return operation_manager
    
    def get_all_vms_info(self) -> List[Dict]:
        """Get comprehensive info for all VMs."""
        all_vms = []
        nodes = self.get_nodes()
        
        for node in nodes:
            try:
                vms = self.api._request('GET', f'/nodes/{node["node"]}/qemu')
                for vm in vms:
                    vm_info = {
                        'vmid': str(vm['vmid']),
                        'name': vm.get('name', f'VM-{vm["vmid"]}'),
                        'node': node['node'],
                        'running': vm.get('status') == 'running',
                        'status': vm.get('status', 'unknown'),
                        'cpu_usage': vm.get('cpu', 0),
                        'memory_usage': vm.get('mem', 0),
                        'memory_max': vm.get('maxmem', 0),
                        'uptime': vm.get('uptime', 0)
                    }
                    all_vms.append(vm_info)
            except ProxmoxAPIError:
                continue
        
        # Sort by VM ID
        all_vms.sort(key=lambda x: int(x['vmid']))
        return all_vms
    
    def bulk_operations_menu(self):
        """Interactive menu for bulk operations."""
        while True:
            try:
                print("\n🔧 Bulk Operations Menu")
                print("=" * 40)
                print("1. Bulk Start VMs")
                print("2. Bulk Stop VMs (Forceful)")
                print("3. Bulk Shutdown VMs (Graceful)")
                print("4. Bulk Create Backups")
                print("5. Bulk Create Snapshots")
                print("6. Bulk Delete Snapshots")
                print("7. VM Selection Help")
                print("8. Back to Main Menu")
                print()
                
                choice = input("Select operation (1-8): ").strip()
                
                if choice == '1':  # Bulk Start
                    self.handle_bulk_start()
                elif choice == '2':  # Bulk Stop
                    self.handle_bulk_stop()
                elif choice == '3':  # Bulk Shutdown
                    self.handle_bulk_shutdown()
                elif choice == '4':  # Bulk Backup
                    self.handle_bulk_backup()
                elif choice == '5':  # Bulk Create Snapshots
                    self.handle_bulk_create_snapshots()
                elif choice == '6':  # Bulk Delete Snapshots
                    self.handle_bulk_delete_snapshots()
                elif choice == '7':  # Help
                    self.vm_selector.display_selection_help()
                    input("Press Enter to continue...")
                elif choice == '8':  # Back
                    break
                else:
                    print("Invalid choice. Please select 1-8.")
                    input("Press Enter to continue...")
                    
            except KeyboardInterrupt:
                print("\nReturning to main menu...")
                break
    
    def handle_bulk_start(self):
        """Handle bulk start VM operation."""
        all_vms = self.get_all_vms_info()
        if not all_vms:
            print("❌ No VMs found")
            input("Press Enter to continue...")
            return
        
        # Show stopped VMs count
        stopped_vms = [vm for vm in all_vms if not vm['running']]
        print(f"\nFound {len(stopped_vms)} stopped VMs out of {len(all_vms)} total VMs")
        
        if len(stopped_vms) == 0:
            print("✅ All VMs are already running!")
            input("Press Enter to continue...")
            return
        
        print("\nSelect VMs to start:")
        self.vm_selector.display_selection_help()
        
        selection = input("Enter VM selection: ").strip()
        if not selection:
            return
        
        selected_vm_ids = self.vm_selector.parse_selection(selection, all_vms)
        if not selected_vm_ids:
            print("❌ No valid VMs selected")
            input("Press Enter to continue...")
            return
        
        # Filter to only stopped VMs
        stopped_selected = [vmid for vmid in selected_vm_ids if not any(vm['vmid'] == vmid and vm['running'] for vm in all_vms)]
        already_running = [vmid for vmid in selected_vm_ids if any(vm['vmid'] == vmid and vm['running'] for vm in all_vms)]
        
        if already_running:
            print(f"\n⚠️  Skipping {len(already_running)} already running VMs: {', '.join(already_running)}")
        
        if not stopped_selected:
            print("❌ No stopped VMs selected")
            input("Press Enter to continue...")
            return
        
        print(f"\n📋 Selected {len(stopped_selected)} stopped VMs to start:")
        for vmid in stopped_selected:
            vm_info = next((vm for vm in all_vms if vm['vmid'] == vmid), None)
            if vm_info:
                print(f"  - VM {vmid}: {vm_info['name']}")
        
        confirm = input(f"\nProceed to start {len(stopped_selected)} VMs? (y/N): ").strip().lower()
        if confirm in ['y', 'yes']:
            self.bulk_start_vms(stopped_selected)
            input("\nPress Enter to continue...")
    
    def handle_bulk_shutdown(self):
        """Handle bulk shutdown VM operation."""
        all_vms = self.get_all_vms_info()
        if not all_vms:
            print("❌ No VMs found")
            input("Press Enter to continue...")
            return
        
        # Show running VMs count
        running_vms = [vm for vm in all_vms if vm['running']]
        print(f"\nFound {len(running_vms)} running VMs out of {len(all_vms)} total VMs")
        
        if len(running_vms) == 0:
            print("✅ All VMs are already stopped!")
            input("Press Enter to continue...")
            return
        
        print("\nSelect VMs to gracefully shutdown:")
        self.vm_selector.display_selection_help()
        
        selection = input("Enter VM selection: ").strip()
        if not selection:
            return
        
        selected_vm_ids = self.vm_selector.parse_selection(selection, all_vms)
        if not selected_vm_ids:
            print("❌ No valid VMs selected")
            input("Press Enter to continue...")
            return
        
        # Filter to only running VMs
        running_selected = [vmid for vmid in selected_vm_ids if any(vm['vmid'] == vmid and vm['running'] for vm in all_vms)]
        already_stopped = [vmid for vmid in selected_vm_ids if not any(vm['vmid'] == vmid and vm['running'] for vm in all_vms)]
        
        if already_stopped:
            print(f"\n⚠️  Skipping {len(already_stopped)} already stopped VMs: {', '.join(already_stopped)}")
        
        if not running_selected:
            print("❌ No running VMs selected")
            input("Press Enter to continue...")
            return
        
        print(f"\n📋 Selected {len(running_selected)} running VMs to gracefully shutdown:")
        for vmid in running_selected:
            vm_info = next((vm for vm in all_vms if vm['vmid'] == vmid), None)
            if vm_info:
                print(f"  - VM {vmid}: {vm_info['name']}")
        
        print(f"\n🔄 INFO: This will send graceful shutdown signals to {len(running_selected)} VMs.")
        print("This allows the VM operating systems to properly shut down services.")
        confirm = input(f"\nAre you sure you want to gracefully shutdown {len(running_selected)} VMs? (yes/N): ").strip().lower()
        if confirm == 'yes':
            self.bulk_shutdown_vms(running_selected)
            input("\nPress Enter to continue...")
    
    def handle_bulk_stop(self):
        """Handle bulk stop VM operation."""
        all_vms = self.get_all_vms_info()
        if not all_vms:
            print("❌ No VMs found")
            input("Press Enter to continue...")
            return
        
        # Show running VMs count
        running_vms = [vm for vm in all_vms if vm['running']]
        print(f"\nFound {len(running_vms)} running VMs out of {len(all_vms)} total VMs")
        
        if len(running_vms) == 0:
            print("✅ All VMs are already stopped!")
            input("Press Enter to continue...")
            return
        
        print("\nSelect VMs to stop:")
        self.vm_selector.display_selection_help()
        
        selection = input("Enter VM selection: ").strip()
        if not selection:
            return
        
        selected_vm_ids = self.vm_selector.parse_selection(selection, all_vms)
        if not selected_vm_ids:
            print("❌ No valid VMs selected")
            input("Press Enter to continue...")
            return
        
        # Filter to only running VMs
        running_selected = [vmid for vmid in selected_vm_ids if any(vm['vmid'] == vmid and vm['running'] for vm in all_vms)]
        already_stopped = [vmid for vmid in selected_vm_ids if not any(vm['vmid'] == vmid and vm['running'] for vm in all_vms)]
        
        if already_stopped:
            print(f"\n⚠️  Skipping {len(already_stopped)} already stopped VMs: {', '.join(already_stopped)}")
        
        if not running_selected:
            print("❌ No running VMs selected")
            input("Press Enter to continue...")
            return
        
        print(f"\n📋 Selected {len(running_selected)} running VMs to stop:")
        for vmid in running_selected:
            vm_info = next((vm for vm in all_vms if vm['vmid'] == vmid), None)
            if vm_info:
                print(f"  - VM {vmid}: {vm_info['name']}")
        
        print(f"\n⚠️  WARNING: This will stop {len(running_selected)} running VMs!")
        print("This will terminate all processes in these VMs.")
        confirm = input(f"\nAre you sure you want to stop {len(running_selected)} VMs? (yes/N): ").strip().lower()
        if confirm == 'yes':
            self.bulk_stop_vms(running_selected)
            input("\nPress Enter to continue...")
    
    def handle_bulk_backup(self):
        """Handle bulk backup creation."""
        all_vms = self.get_all_vms_info()
        if not all_vms:
            print("❌ No VMs found")
            input("Press Enter to continue...")
            return
        
        print(f"\nFound {len(all_vms)} VMs available for backup")
        
        print("\nSelect VMs to backup:")
        self.vm_selector.display_selection_help()
        
        selection = input("Enter VM selection: ").strip()
        if not selection:
            return
        
        selected_vm_ids = self.vm_selector.parse_selection(selection, all_vms)
        if not selected_vm_ids:
            print("❌ No valid VMs selected")
            input("Press Enter to continue...")
            return
        
        print(f"\n📋 Selected {len(selected_vm_ids)} VMs for backup:")
        for vmid in selected_vm_ids:
            vm_info = next((vm for vm in all_vms if vm['vmid'] == vmid), None)
            if vm_info:
                status = "🟢 running" if vm_info['running'] else "🔴 stopped"
                print(f"  - VM {vmid}: {vm_info['name']} ({status})")
        
        # Storage selection
        storages = self.display_storage_list()
        if not storages:
            input("\nPress Enter to continue...")
            return
        
        print()
        storage_choice = input("Select storage number (or 'q' to cancel): ").strip()
        
        if storage_choice.lower() in ['q', 'quit']:
            return
        
        try:
            storage_index = int(storage_choice) - 1
            if 0 <= storage_index < len(storages):
                selected_storage = storages[storage_index]['storage']
            else:
                print("Invalid storage selection")
                input("Press Enter to continue...")
                return
        except ValueError:
            print("Invalid input")
            input("Press Enter to continue...")
            return
        
        # Backup mode selection
        print("\nBackup Mode:")
        print("1. snapshot - Fastest, VM stays running (requires qemu-guest-agent)")
        print("2. suspend - VM is suspended during backup")
        print("3. stop - Safest, VM is stopped during backup")
        print()
        
        mode_choice = input("Select backup mode (1-3, default: 1): ").strip()
        mode_map = {'1': 'snapshot', '2': 'suspend', '3': 'stop', '': 'snapshot'}
        
        if mode_choice in mode_map:
            backup_mode = mode_map[mode_choice]
        else:
            print("Invalid mode selection")
            input("Press Enter to continue...")
            return
        
        # Final confirmation
        print(f"\n📋 Bulk Backup Configuration:")
        print(f"  VMs: {len(selected_vm_ids)} selected")
        print(f"  Storage: {selected_storage}")
        print(f"  Mode: {backup_mode}")
        print(f"  Compression: zstd")
        
        confirm = input(f"\nProceed to create backups for {len(selected_vm_ids)} VMs? (y/N): ").strip().lower()
        if confirm in ['y', 'yes']:
            self.bulk_create_backups(selected_vm_ids, selected_storage, backup_mode)
            input("\nPress Enter to continue...")
    
    def quick_start_all(self):
        """Quick action to start all stopped VMs."""
        all_vms = self.get_all_vms_info()
        if not all_vms:
            print("❌ No VMs found")
            input("Press Enter to continue...")
            return
        
        stopped_vms = [vm for vm in all_vms if not vm['running']]
        
        if not stopped_vms:
            print("✅ All VMs are already running!")
            input("Press Enter to continue...")
            return
        
        print(f"\n🚀 Quick Start All Stopped VMs")
        print("=" * 50)
        print(f"Found {len(stopped_vms)} stopped VMs:")
        
        for vm in stopped_vms:
            print(f"  - VM {vm['vmid']}: {vm['name']}")
        
        confirm = input(f"\nStart all {len(stopped_vms)} stopped VMs? (y/N): ").strip().lower()
        if confirm in ['y', 'yes']:
            stopped_vm_ids = [vm['vmid'] for vm in stopped_vms]
            self.bulk_start_vms(stopped_vm_ids)
            input("\nPress Enter to continue...")
    
    def quick_stop_all(self):
        """Quick action to stop all running VMs."""
        all_vms = self.get_all_vms_info()
        if not all_vms:
            print("❌ No VMs found")
            input("Press Enter to continue...")
            return
        
        running_vms = [vm for vm in all_vms if vm['running']]
        
        if not running_vms:
            print("✅ All VMs are already stopped!")
            input("Press Enter to continue...")
            return
        
        print(f"\n🛑 Quick Stop All Running VMs")
        print("=" * 50)
        print(f"Found {len(running_vms)} running VMs:")
        
        for vm in running_vms:
            print(f"  - VM {vm['vmid']}: {vm['name']}")
        
        print(f"\n⚠️  WARNING: This will stop {len(running_vms)} running VMs!")
        print("This will terminate all processes in these VMs.")
        confirm = input(f"\nAre you sure you want to stop all {len(running_vms)} running VMs? (yes/N): ").strip().lower()
        if confirm == 'yes':
            running_vm_ids = [vm['vmid'] for vm in running_vms]
            self.bulk_stop_vms(running_vm_ids)
            input("\nPress Enter to continue...")
    
    def quick_backup_all(self):
        """Quick action to backup all VMs."""
        all_vms = self.get_all_vms_info()
        if not all_vms:
            print("❌ No VMs found")
            input("Press Enter to continue...")
            return
        
        print(f"\n💾 Quick Backup All VMs")
        print("=" * 50)
        print(f"Found {len(all_vms)} VMs:")
        
        for vm in all_vms:
            status = "🟢 running" if vm['running'] else "🔴 stopped"
            print(f"  - VM {vm['vmid']}: {vm['name']} ({status})")
        
        # Storage selection
        storages = self.display_storage_list()
        if not storages:
            input("\nPress Enter to continue...")
            return
        
        print()
        storage_choice = input("Select storage number (or 'q' to cancel): ").strip()
        
        if storage_choice.lower() in ['q', 'quit']:
            return
        
        try:
            storage_index = int(storage_choice) - 1
            if 0 <= storage_index < len(storages):
                selected_storage = storages[storage_index]['storage']
            else:
                print("Invalid storage selection")
                input("Press Enter to continue...")
                return
        except ValueError:
            print("Invalid input")
            input("Press Enter to continue...")
            return
        
        # Backup mode selection
        print("\nBackup Mode:")
        print("1. snapshot - Fastest, VM stays running (requires qemu-guest-agent)")
        print("2. suspend - VM is suspended during backup")
        print("3. stop - Safest, VM is stopped during backup")
        print()
        
        mode_choice = input("Select backup mode (1-3, default: 1): ").strip()
        mode_map = {'1': 'snapshot', '2': 'suspend', '3': 'stop', '': 'snapshot'}
        
        if mode_choice in mode_map:
            backup_mode = mode_map[mode_choice]
        else:
            print("Invalid mode selection")
            input("Press Enter to continue...")
            return
        
        # Final confirmation
        print(f"\n📋 Quick Backup All VMs Configuration:")
        print(f"  VMs: {len(all_vms)} VMs")
        print(f"  Storage: {selected_storage}")
        print(f"  Mode: {backup_mode}")
        print(f"  Compression: zstd")
        
        confirm = input(f"\nProceed to create backups for all {len(all_vms)} VMs? (y/N): ").strip().lower()
        if confirm in ['y', 'yes']:
            all_vm_ids = [vm['vmid'] for vm in all_vms]
            self.bulk_create_backups(all_vm_ids, selected_storage, backup_mode)
            input("\nPress Enter to continue...")
    
    def handle_bulk_create_snapshots(self):
        """Handle bulk snapshot creation."""
        all_vms = self.get_all_vms_info()
        if not all_vms:
            print("❌ No VMs found")
            input("Press Enter to continue...")
            return
        
        print(f"\n📸 Bulk Create Snapshots")
        print("=" * 50)
        print(f"Found {len(all_vms)} VMs available for snapshots")
        
        print("\nSelect VMs for snapshot creation:")
        self.vm_selector.display_selection_help()
        
        selection = input("Enter VM selection: ").strip()
        if not selection:
            return
        
        selected_vm_ids = self.vm_selector.parse_selection(selection, all_vms)
        if not selected_vm_ids:
            print("❌ No valid VMs selected")
            input("Press Enter to continue...")
            return
        
        print(f"\n📋 Selected {len(selected_vm_ids)} VMs for snapshots:")
        for vmid in selected_vm_ids:
            vm_info = next((vm for vm in all_vms if vm['vmid'] == vmid), None)
            if vm_info:
                status = "🟢 running" if vm_info['running'] else "🔴 stopped"
                print(f"  - VM {vmid}: {vm_info['name']} ({status})")
        
        # Get snapshot prefix
        print("\nEnter snapshot prefix (will be combined with VM name and timestamp):")
        print("Examples: 'pre-update', 'backup', 'test', 'stable'")
        
        prefix = input("Snapshot prefix: ").strip()
        if not prefix:
            print("❌ Snapshot prefix is required")
            input("Press Enter to continue...")
            return
        
        # Validate prefix
        if len(prefix) > 20:
            print("❌ Prefix too long (max 20 characters)")
            input("Press Enter to continue...")
            return
        
        # Ask about vmstate (RAM)
        print(f"\nSnapshot options:")
        print(f"1. Include RAM state (vmstate) - Slower but complete state")
        print(f"2. Disk only - Faster but no RAM state")
        print(f"Note: RAM state is only saved if VM is currently running")
        
        vmstate_choice = input("Select option (1-2, default: 1): ").strip()
        save_vmstate = vmstate_choice != '2'
        
        # Final confirmation
        print(f"\n📋 Bulk Snapshot Configuration:")
        print(f"  VMs: {len(selected_vm_ids)} selected")
        print(f"  Prefix: {prefix}")
        print(f"  Include RAM: {'Yes (for running VMs)' if save_vmstate else 'No'}")
        
        confirm = input(f"\nProceed to create snapshots for {len(selected_vm_ids)} VMs? (y/N): ").strip().lower()
        if confirm in ['y', 'yes']:
            # Set vmstate option temporarily
            original_vmstate = getattr(self, 'save_vmstate', True)
            self.save_vmstate = save_vmstate
            
            try:
                self.bulk_create_snapshots(selected_vm_ids, prefix)
            finally:
                # Restore original vmstate setting
                self.save_vmstate = original_vmstate
            
            input("\nPress Enter to continue...")
    
    def handle_bulk_delete_snapshots(self):
        """Handle bulk snapshot deletion."""
        all_vms = self.get_all_vms_info()
        if not all_vms:
            print("❌ No VMs found")
            input("Press Enter to continue...")
            return
        
        print(f"\n🗑️  Bulk Delete Snapshots")
        print("=" * 50)
        print(f"Found {len(all_vms)} VMs")
        
        print("\nSelect VMs for snapshot deletion:")
        self.vm_selector.display_selection_help()
        
        selection = input("Enter VM selection: ").strip()
        if not selection:
            return
        
        selected_vm_ids = self.vm_selector.parse_selection(selection, all_vms)
        if not selected_vm_ids:
            print("❌ No valid VMs selected")
            input("Press Enter to continue...")
            return
        
        print(f"\n📋 Selected {len(selected_vm_ids)} VMs for snapshot analysis:")
        for vmid in selected_vm_ids:
            vm_info = next((vm for vm in all_vms if vm['vmid'] == vmid), None)
            if vm_info:
                status = "🟢 running" if vm_info['running'] else "🔴 stopped"
                print(f"  - VM {vmid}: {vm_info['name']} ({status})")
        
        # Collect all snapshots from selected VMs
        all_snapshots = []
        vms_with_snapshots = []
        
        print(f"\n🔍 Scanning for snapshots...")
        for vmid in selected_vm_ids:
            snapshots = self.get_snapshots(vmid)
            if snapshots:
                # Filter out 'current' snapshot
                available_snapshots = [s for s in snapshots if s.get('name') != 'current']
                if available_snapshots:
                    vms_with_snapshots.append(vmid)
                    for snapshot in available_snapshots:
                        snapshot['vmid'] = vmid  # Add vmid to snapshot info
                        all_snapshots.append(snapshot)
        
        if not all_snapshots:
            print("❌ No deletable snapshots found in selected VMs")
            input("Press Enter to continue...")
            return
        
        print(f"\nFound {len(all_snapshots)} snapshots across {len(vms_with_snapshots)} VMs")
        
        # Option to delete by pattern or select specific snapshots
        print("\nDeletion options:")
        print("1. Delete by name pattern (e.g., all snapshots containing 'test')")
        print("2. Select specific snapshots to delete")
        print("3. Delete ALL snapshots from selected VMs (DANGEROUS)")
        
        delete_choice = input("Select deletion method (1-3): ").strip()
        
        snapshots_to_delete = []
        
        if delete_choice == '1':  # Pattern deletion
            pattern = input("Enter pattern to match snapshot names: ").strip().lower()
            if not pattern:
                print("❌ Pattern cannot be empty")
                input("Press Enter to continue...")
                return
            
            for snapshot in all_snapshots:
                snapshot_name = snapshot.get('name', '').lower()
                if pattern in snapshot_name:
                    snapshots_to_delete.append(snapshot)
            
            if not snapshots_to_delete:
                print(f"❌ No snapshots found matching pattern '{pattern}'")
                input("Press Enter to continue...")
                return
            
            print(f"\nFound {len(snapshots_to_delete)} snapshots matching pattern '{pattern}':")
            for snapshot in snapshots_to_delete:
                vmid = snapshot['vmid']
                name = snapshot.get('name', 'Unknown')
                print(f"  - VM {vmid}: {name}")
        
        elif delete_choice == '2':  # Specific selection
            print("\n📋 Available Snapshots:")
            print("-" * 100)
            print(f"{'#':<3} {'VM':<8} {'Name':<50} {'Description':<35} {'Created'}")
            print("-" * 100)
            
            for i, snapshot in enumerate(all_snapshots, 1):
                vmid = snapshot['vmid']
                name = snapshot.get('name', 'Unknown')
                desc = snapshot.get('description', 'No description')
                
                # Format creation time
                snaptime = snapshot.get('snaptime', 0)
                if snaptime:
                    created = datetime.fromtimestamp(snaptime).strftime('%Y-%m-%d %H:%M')
                else:
                    created = 'Unknown'
                
                # Truncate long fields
                if len(name) > 29:
                    name = name[:26] + "..."
                if len(desc) > 34:
                    desc = desc[:31] + "..."
                
                print(f"{i:<3} {vmid:<8} {name:<30} {desc:<35} {created}")
            
            print("-" * 100)
            
            selection_input = input("Enter snapshot numbers (comma-separated, e.g., 1,3,5): ").strip()
            if not selection_input:
                return
            
            try:
                indices = [int(x.strip()) - 1 for x in selection_input.split(',')]
                for idx in indices:
                    if 0 <= idx < len(all_snapshots):
                        snapshots_to_delete.append(all_snapshots[idx])
            except ValueError:
                print("❌ Invalid selection format")
                input("Press Enter to continue...")
                return
            
            if not snapshots_to_delete:
                print("❌ No valid snapshots selected")
                input("Press Enter to continue...")
                return
        
        elif delete_choice == '3':  # Delete all
            snapshots_to_delete = all_snapshots.copy()
        
        else:
            print("❌ Invalid selection")
            input("Press Enter to continue...")
            return
        
        # Final warning and confirmation
        print(f"\n⚠️  BULK SNAPSHOT DELETION WARNING")
        print("=" * 60)
        print("This operation will:")
        print(f"  • Permanently delete {len(snapshots_to_delete)} snapshots")
        print("  • Free up disk space used by these snapshots")
        print("  • This action cannot be undone!")
        print("=" * 60)
        
        print(f"\nSnapshots to be deleted:")
        for snapshot in snapshots_to_delete:
            vmid = snapshot['vmid']
            name = snapshot.get('name', 'Unknown')
            print(f"  - VM {vmid}: {name}")
        
        confirm = input(f"\nType 'DELETE' to confirm deletion of {len(snapshots_to_delete)} snapshots: ").strip()
        if confirm == 'DELETE':
            # Group snapshots by VM for efficient deletion
            snapshots_by_vm = {}
            for snapshot in snapshots_to_delete:
                vmid = snapshot['vmid']
                if vmid not in snapshots_by_vm:
                    snapshots_by_vm[vmid] = []
                snapshots_by_vm[vmid].append(snapshot['name'])
            
            self.bulk_delete_snapshots(snapshots_by_vm)
            input("\nPress Enter to continue...")
        else:
            print("Deletion cancelled")
            input("Press Enter to continue...")
    
    def bulk_create_snapshots(self, vm_ids: List[str], prefix: str, max_workers: int = 2) -> BulkOperationManager:
        """Create snapshots for multiple VMs concurrently."""
        operation_manager = BulkOperationManager(max_workers)
        
        print(f"\n📸 Creating snapshots for {len(vm_ids)} VMs")
        print(f"Prefix: {prefix}")
        print(f"Max concurrent operations: {max_workers}")
        print("=" * 60)
        
        def snapshot_single_vm(vmid: str) -> BulkOperationResult:
            start_time = time.time()
            try:
                # Check if VM exists
                vm_info = self.get_vm_info(vmid)
                if not vm_info:
                    return BulkOperationResult(vmid, "snapshot", False, "VM not found", time.time() - start_time)
                
                # Create snapshot (silent version for bulk operations)
                success = self._create_snapshot_silent(vmid, prefix)
                message = "Snapshot created successfully" if success else "Failed to create snapshot"
                return BulkOperationResult(vmid, "snapshot", success, message, time.time() - start_time)
                
            except Exception as e:
                return BulkOperationResult(vmid, "snapshot", False, str(e), time.time() - start_time)
        
        # Execute operations concurrently
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_vmid = {executor.submit(snapshot_single_vm, vmid): vmid for vmid in vm_ids}
            
            for future in as_completed(future_to_vmid):
                if operation_manager.cancelled:
                    break
                    
                result = future.result()
                operation_manager.add_result(result)
                
                # Print progress
                operation_manager.print_progress(len(vm_ids), "Create Snapshots")
        
        operation_manager.print_summary("Bulk Create Snapshots")
        return operation_manager
    
    def bulk_delete_snapshots(self, snapshots_by_vm: Dict[str, List[str]], max_workers: int = 2) -> BulkOperationManager:
        """Delete multiple snapshots concurrently."""
        total_snapshots = sum(len(snapshots) for snapshots in snapshots_by_vm.values())
        operation_manager = BulkOperationManager(max_workers)
        
        print(f"\n🗑️  Deleting {total_snapshots} snapshots across {len(snapshots_by_vm)} VMs")
        print(f"Max concurrent operations: {max_workers}")
        print("=" * 60)
        
        def delete_vm_snapshots(vmid_and_snapshots) -> List[BulkOperationResult]:
            vmid, snapshot_names = vmid_and_snapshots
            results = []
            
            for snapshot_name in snapshot_names:
                start_time = time.time()
                try:
                    # Delete snapshot (silent version for bulk operations)
                    success = self._delete_snapshot_silent(vmid, snapshot_name)
                    message = f"Deleted {snapshot_name}" if success else f"Failed to delete {snapshot_name}"
                    result = BulkOperationResult(f"{vmid}:{snapshot_name}", "delete_snapshot", success, message, time.time() - start_time)
                    results.append(result)
                    
                except Exception as e:
                    result = BulkOperationResult(f"{vmid}:{snapshot_name}", "delete_snapshot", False, str(e), time.time() - start_time)
                    results.append(result)
            
            return results
        
        # Execute operations concurrently
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_vm = {executor.submit(delete_vm_snapshots, item): item for item in snapshots_by_vm.items()}
            
            for future in as_completed(future_to_vm):
                if operation_manager.cancelled:
                    break
                    
                vm_results = future.result()
                for result in vm_results:
                    operation_manager.add_result(result)
                
                # Print progress
                operation_manager.print_progress(total_snapshots, "Delete Snapshots")
        
        operation_manager.print_summary("Bulk Delete Snapshots")
        return operation_manager
    
    def _create_snapshot_silent(self, vmid: str, prefix: str) -> bool:
        """Create a snapshot without output (for bulk operations)."""
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        vm_name = self.get_vm_name(vmid) or f"VM-{vmid}"
        snapshot_name = f"{prefix}-{vm_name}-{timestamp}"
        
        node = self.find_vm_node(vmid)
        if not node:
            return False
        
        try:
            # Prepare snapshot data
            snapshot_data = {
                'snapname': snapshot_name,
                'description': f'Bulk snapshot created {"with" if getattr(self, "save_vmstate", True) else "without"} vmstate - {timestamp}'
            }
            
            # Check if VM is running and vmstate is enabled
            vm_info = self.get_vm_info(vmid)
            if vm_info and vm_info.get('running') and getattr(self, 'save_vmstate', True):
                snapshot_data['vmstate'] = '1'
            
            # Create snapshot
            task_id = self.api._request('POST', f'/nodes/{node}/qemu/{vmid}/snapshot', data=snapshot_data)
            
            # Monitor task without output
            return self._monitor_task_silent(node, task_id)
        except ProxmoxAPIError:
            return False
    
    def _delete_snapshot_silent(self, vmid: str, snapshot_name: str) -> bool:
        """Delete a snapshot without output (for bulk operations)."""
        node = self.find_vm_node(vmid)
        if not node:
            return False
        
        try:
            # Execute deletion via API
            task_id = self.api._request('DELETE', f'/nodes/{node}/qemu/{vmid}/snapshot/{snapshot_name}')
            
            # Monitor task without output
            return self._monitor_task_silent(node, task_id)
        except ProxmoxAPIError:
            return False
    
    # ============================================================================
    # SNAPSHOT MANAGEMENT
    # ============================================================================
    
    def handle_create_snapshot(self, vmid: str):
        """Handle creating a snapshot for a VM."""
        print(f"\n📸 Create Snapshot for VM {vmid}")
        print("=" * 50)
        
        # Show VM details
        vm_info = self.get_vm_info(vmid)
        if not vm_info:
            print("❌ Could not get VM information")
            input("Press Enter to continue...")
            return
        
        # Show current VM status
        is_running, status_display, status_details = self.get_vm_status_detailed(vmid)
        print(f"VM Status: {status_display}")
        if status_details:
            print(f"Details: {status_details}")
        
        # Show current snapshots
        print("\n📋 Current Snapshots:")
        snapshots = self.get_snapshots(vmid)
        if snapshots:
            non_current_snapshots = [s for s in snapshots if s.get('name') != 'current']
            if non_current_snapshots:
                # Sort by snaptime (newest first) - handle missing snaptime
                non_current_snapshots.sort(key=lambda x: x.get('snaptime', 0), reverse=True)
                print(f"Found {len(non_current_snapshots)} existing snapshots:")
                for i, snapshot in enumerate(non_current_snapshots, 1):
                    name = snapshot.get('name', 'Unknown')
                    desc = snapshot.get('description', 'No description')
                    # Truncate long descriptions
                    if len(desc) > 50:
                        desc = desc[:47] + "..."
                    print(f"  {i}. {name} - {desc}")
            else:
                print("  No snapshots found")
        else:
            print("  No snapshots found")
        
        print("\n" + "=" * 50)
        
        # Get snapshot name prefix
        print("Enter snapshot prefix (will be combined with VM name and timestamp):")
        print("Examples: 'pre-update', 'backup', 'test', 'stable'")
        
        prefix = input("Snapshot prefix: ").strip()
        if not prefix:
            print("❌ Snapshot prefix is required")
            input("Press Enter to continue...")
            return
        
        # Validate prefix
        if len(prefix) > 20:
            print("❌ Prefix too long (max 20 characters)")
            input("Press Enter to continue...")
            return
        
        # Ask about vmstate (RAM)
        print(f"\nSnapshot options:")
        print(f"1. Include RAM state (vmstate) - Slower but complete state")
        print(f"2. Disk only - Faster but no RAM state")
        print(f"Note: RAM state is only saved if VM is currently running")
        
        vmstate_choice = input("Select option (1-2, default: 1): ").strip()
        save_vmstate = vmstate_choice != '2'
        
        # Show preview
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        vm_name = self.get_vm_name(vmid) or f"VM-{vmid}"
        preview_name = f"{prefix}-{vm_name}-{timestamp}"
        
        print(f"\n📋 Snapshot Preview:")
        print(f"  VM: {vmid} ({vm_info.get('name', 'Unknown')})")
        print(f"  Snapshot name: {preview_name}")
        print(f"  Include RAM: {'Yes' if save_vmstate and is_running else 'No' if not save_vmstate else 'N/A (VM stopped)'}")
        print(f"  VM Status: {status_display}")
        
        # Final confirmation
        confirm = input(f"\nCreate snapshot '{preview_name}'? (y/N): ").strip().lower()
        if confirm in ['y', 'yes']:
            # Set vmstate option temporarily
            original_vmstate = getattr(self, 'save_vmstate', True)
            self.save_vmstate = save_vmstate
            
            try:
                success = self.create_snapshot(vmid, prefix)
                if success:
                    print("\n✅ Snapshot created successfully!")
                    
                    # Show updated snapshot list
                    print("\n📋 Updated Snapshot List:")
                    updated_snapshots = self.get_snapshots(vmid)
                    if updated_snapshots:
                        non_current = [s for s in updated_snapshots if s.get('name') != 'current']
                        # Sort by snaptime (newest first) - handle missing snaptime
                        non_current.sort(key=lambda x: x.get('snaptime', 0), reverse=True)
                        for i, snapshot in enumerate(non_current, 1):
                            name = snapshot.get('name', 'Unknown')
                            desc = snapshot.get('description', 'No description')
                            if len(desc) > 50:
                                desc = desc[:47] + "..."
                            print(f"  {i}. {name} - {desc}")
                else:
                    print("\n❌ Failed to create snapshot!")
            finally:
                # Restore original vmstate setting
                self.save_vmstate = original_vmstate
            
            input("\nPress Enter to continue...")
        else:
            print("Snapshot creation cancelled")
            input("Press Enter to continue...")
    
    def handle_rollback_snapshot(self, vmid: str):
        """Handle rolling back to a snapshot."""
        print(f"\n⏪ Rollback Snapshot for VM {vmid}")
        print("=" * 50)
        
        # Show VM details
        vm_info = self.get_vm_info(vmid)
        if not vm_info:
            print("❌ Could not get VM information")
            input("Press Enter to continue...")
            return
        
        # Show current VM status
        is_running, status_display, status_details = self.get_vm_status_detailed(vmid)
        print(f"Current VM Status: {status_display}")
        if status_details:
            print(f"Details: {status_details}")
        
        # Get snapshots
        snapshots = self.get_snapshots(vmid)
        if not snapshots:
            print("\n❌ No snapshots found for this VM")
            input("Press Enter to continue...")
            return
        
        # Filter out 'current' snapshot
        available_snapshots = [s for s in snapshots if s.get('name') != 'current']
        if not available_snapshots:
            print("\n❌ No rollback snapshots available")
            input("Press Enter to continue...")
            return
        
        # Sort by snaptime (newest first) - handle missing snaptime
        available_snapshots.sort(key=lambda x: x.get('snaptime', 0), reverse=True)
        
        # Display available snapshots
        print(f"\n📋 Available Snapshots ({len(available_snapshots)}):")
        print("-" * 80)
        print(f"{'#':<3} {'Name':<50} {'Description':<35} {'Created'}")
        print("-" * 80)
        
        for i, snapshot in enumerate(available_snapshots, 1):
            name = snapshot.get('name', 'Unknown')
            desc = snapshot.get('description', 'No description')
            
            # Format creation time
            snaptime = snapshot.get('snaptime', 0)
            if snaptime:
                created = datetime.fromtimestamp(snaptime).strftime('%Y-%m-%d %H:%M')
            else:
                created = 'Unknown'
            
            # Truncate long fields
            if len(desc) > 34:
                desc = desc[:31] + "..."
            
            print(f"{i:<3} {name:<30} {desc:<35} {created}")
        
        print("-" * 80)
        
        # Get user selection
        print()
        choice = input("Select snapshot number to rollback to (or 'q' to cancel): ").strip()
        
        if choice.lower() in ['q', 'quit']:
            return
        
        try:
            snapshot_index = int(choice) - 1
            if 0 <= snapshot_index < len(available_snapshots):
                selected_snapshot = available_snapshots[snapshot_index]
                snapshot_name = selected_snapshot.get('name')
                
                # Show rollback warning
                print(f"\n⚠️  SNAPSHOT ROLLBACK WARNING")
                print("=" * 60)
                print("This operation will:")
                print(f"  • Revert VM {vmid} to snapshot: {snapshot_name}")
                print("  • ALL changes made after this snapshot will be LOST")
                print("  • This action cannot be undone!")
                print("=" * 60)
                
                # Get snapshot details
                desc = selected_snapshot.get('description', 'No description')
                snaptime = selected_snapshot.get('snaptime', 0)
                if snaptime:
                    created = datetime.fromtimestamp(snaptime).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    created = 'Unknown'
                
                print(f"\nSnapshot Details:")
                print(f"  Name: {snapshot_name}")
                print(f"  Description: {desc}")
                print(f"  Created: {created}")
                
                # Check if VM needs to be stopped
                if is_running:
                    print(f"\n⚠️  VM is currently running and will be stopped for rollback")
                
                # Final confirmation
                confirm = input(f"\nType 'ROLLBACK' to confirm this dangerous operation: ").strip()
                if confirm == 'ROLLBACK':
                    # Stop VM if running
                    if is_running:
                        print(f"\n🛑 Stopping VM before rollback...")
                        stop_success = self.stop_vm(vmid)
                        if not stop_success:
                            print("❌ Failed to stop VM. Rollback cancelled.")
                            input("Press Enter to continue...")
                            return
                        time.sleep(3)  # Wait for VM to stop
                    
                    # Perform rollback
                    print(f"\n⏪ Rolling back to snapshot '{snapshot_name}'...")
                    success = self.rollback_snapshot(vmid, snapshot_name)
                    
                    if success:
                        print("\n✅ Rollback completed successfully!")
                        
                        # Show new VM status
                        print("\n📊 VM Status After Rollback:")
                        new_is_running, new_status_display, new_status_details = self.get_vm_status_detailed(vmid)
                        print(f"  Status: {new_status_display}")
                        if new_status_details:
                            print(f"  Details: {new_status_details}")
                        
                        # Ask if user wants to start VM
                        if not new_is_running:
                            start_vm = input("\nStart VM after rollback? (y/N): ").strip().lower()
                            if start_vm in ['y', 'yes']:
                                self.start_vm(vmid)
                    else:
                        print("\n❌ Rollback failed!")
                    
                    input("\nPress Enter to continue...")
                else:
                    print("Rollback cancelled")
                    input("Press Enter to continue...")
            else:
                print("Invalid snapshot selection")
                input("Press Enter to continue...")
        except ValueError:
            print("Invalid input")
            input("Press Enter to continue...")
    
    def handle_delete_snapshot(self, vmid: str):
        """Handle deleting a snapshot."""
        print(f"\n🗑️  Delete Snapshot for VM {vmid}")
        print("=" * 50)
        
        # Show VM details
        vm_info = self.get_vm_info(vmid)
        if not vm_info:
            print("❌ Could not get VM information")
            input("Press Enter to continue...")
            return
        
        # Show current VM status
        is_running, status_display, status_details = self.get_vm_status_detailed(vmid)
        print(f"Current VM Status: {status_display}")
        if status_details:
            print(f"Details: {status_details}")
        
        # Get snapshots
        snapshots = self.get_snapshots(vmid)
        if not snapshots:
            print("\n❌ No snapshots found for this VM")
            input("Press Enter to continue...")
            return
        
        # Filter out 'current' snapshot
        available_snapshots = [s for s in snapshots if s.get('name') != 'current']
        if not available_snapshots:
            print("\n❌ No deletable snapshots available")
            input("Press Enter to continue...")
            return
        
        # Sort by snaptime (newest first) - handle missing snaptime
        available_snapshots.sort(key=lambda x: x.get('snaptime', 0), reverse=True)
        
        # Display available snapshots
        print(f"\n📋 Available Snapshots ({len(available_snapshots)}):")
        print("-" * 90)
        print(f"{'#':<3} {'Name':<50} {'Description':<35} {'Created':<15} {'Size'}")
        print("-" * 90)
        
        for i, snapshot in enumerate(available_snapshots, 1):
            name = snapshot.get('name', 'Unknown')
            desc = snapshot.get('description', 'No description')
            
            # Format creation time
            snaptime = snapshot.get('snaptime', 0)
            if snaptime:
                created = datetime.fromtimestamp(snaptime).strftime('%Y-%m-%d %H:%M')
            else:
                created = 'Unknown'
            
            # Get size info
            size_info = 'Unknown'
            if 'size' in snapshot:
                size_bytes = snapshot.get('size', 0)
                if size_bytes > 0:
                    size_gb = size_bytes / (1024**3)
                    size_info = f"{size_gb:.2f} GB"
            
            # Truncate long fields
            if len(desc) > 34:
                desc = desc[:31] + "..."
            
            print(f"{i:<3} {name:<30} {desc:<35} {created:<15} {size_info}")
        
        print("-" * 90)
        
        # Get user selection
        print()
        print("Options:")
        print("  - Enter snapshot number (1-{}) to delete specific snapshot".format(len(available_snapshots)))
        print("  - Enter 'all' to delete ALL snapshots")
        print("  - Enter 'q' to cancel")
        print()
        choice = input("Your choice: ").strip()
        
        if choice.lower() in ['q', 'quit']:
            return
        elif choice.lower() == 'all':
            self.delete_all_snapshots(vmid, available_snapshots)
            return
        
        try:
            snapshot_index = int(choice) - 1
            if 0 <= snapshot_index < len(available_snapshots):
                selected_snapshot = available_snapshots[snapshot_index]
                snapshot_name = selected_snapshot.get('name')
                
                # Show deletion warning
                print(f"\n⚠️  SNAPSHOT DELETION WARNING")
                print("=" * 60)
                print("This operation will:")
                print(f"  • Permanently delete snapshot: {snapshot_name}")
                print("  • Free up disk space used by this snapshot")
                print("  • This action cannot be undone!")
                print("=" * 60)
                
                # Get snapshot details
                desc = selected_snapshot.get('description', 'No description')
                snaptime = selected_snapshot.get('snaptime', 0)
                if snaptime:
                    created = datetime.fromtimestamp(snaptime).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    created = 'Unknown'
                
                print(f"\nSnapshot Details:")
                print(f"  Name: {snapshot_name}")
                print(f"  Description: {desc}")
                print(f"  Created: {created}")
                
                # Final confirmation
                confirm = input(f"\nDelete snapshot '{snapshot_name}'? (yes/N): ").strip().lower()
                if confirm == 'yes':
                    # Perform deletion
                    print(f"\n🗑️  Deleting snapshot '{snapshot_name}'...")
                    success = self.delete_snapshot(vmid, snapshot_name)
                    
                    if success:
                        print("\n✅ Snapshot deleted successfully!")
                        
                        # Show updated snapshot list
                        print("\n📋 Remaining Snapshots:")
                        updated_snapshots = self.get_snapshots(vmid)
                        if updated_snapshots:
                            remaining = [s for s in updated_snapshots if s.get('name') != 'current']
                            if remaining:
                                for i, snapshot in enumerate(remaining, 1):
                                    name = snapshot.get('name', 'Unknown')
                                    desc = snapshot.get('description', 'No description')
                                    if len(desc) > 50:
                                        desc = desc[:47] + "..."
                                    print(f"  {i}. {name} - {desc}")
                            else:
                                print("  No snapshots remaining")
                        else:
                            print("  No snapshots remaining")
                    else:
                        print("\n❌ Failed to delete snapshot!")
                    
                    input("\nPress Enter to continue...")
                else:
                    print("Deletion cancelled")
                    input("Press Enter to continue...")
            else:
                print("Invalid snapshot selection")
                input("Press Enter to continue...")
        except ValueError:
            print("Invalid input")
            input("Press Enter to continue...")
    
    def rollback_snapshot(self, vmid: str, snapshot_name: str) -> bool:
        """Rollback VM to a specific snapshot."""
        node = self.find_vm_node(vmid)
        if not node:
            print("❌ Could not find node for VM")
            return False
        
        try:
            print(f"⏪ Executing rollback to snapshot '{snapshot_name}'...")
            
            # Execute rollback via API
            task_id = self.api._request('POST', f'/nodes/{node}/qemu/{vmid}/snapshot/{snapshot_name}/rollback')
            
            # Monitor task progress
            success = self.monitor_task(node, task_id, f"Rollback for VM {vmid}")
            
            return success
            
        except ProxmoxAPIError as e:
            print(f"❌ Rollback failed: {e.message}")
            return False
    
    def delete_snapshot(self, vmid: str, snapshot_name: str) -> bool:
        """Delete a specific snapshot."""
        node = self.find_vm_node(vmid)
        if not node:
            print("❌ Could not find node for VM")
            return False
        
        try:
            print(f"🗑️  Executing snapshot deletion...")
            
            # Execute deletion via API
            task_id = self.api._request('DELETE', f'/nodes/{node}/qemu/{vmid}/snapshot/{snapshot_name}')
            
            # Monitor task progress
            success = self.monitor_task(node, task_id, f"Snapshot deletion for VM {vmid}")
            
            return success
            
        except ProxmoxAPIError as e:
            print(f"❌ Snapshot deletion failed: {e.message}")
            return False
    
    def delete_all_snapshots(self, vmid: str, snapshots: List[Dict]):
        """Delete all snapshots for a VM."""
        print(f"\n🗑️  DELETE ALL SNAPSHOTS WARNING")
        print("=" * 60)
        print("This operation will:")
        print(f"  • Permanently delete ALL {len(snapshots)} snapshots")
        print("  • Free up significant disk space")
        print("  • This action cannot be undone!")
        print("=" * 60)
        
        print(f"\nSnapshots to be deleted:")
        for i, snapshot in enumerate(snapshots, 1):
            name = snapshot.get('name', 'Unknown')
            desc = snapshot.get('description', 'No description')
            snaptime = snapshot.get('snaptime', 0)
            if snaptime:
                created = datetime.fromtimestamp(snaptime).strftime('%Y-%m-%d %H:%M')
            else:
                created = 'Unknown'
            print(f"  {i}. {name} (Created: {created})")
        
        print("=" * 60)
        
        # Double confirmation for safety
        print("\n⚠️  FINAL WARNING: This will delete ALL snapshots!")
        confirm1 = input("Type 'DELETE ALL' to confirm this dangerous operation: ").strip()
        
        if confirm1 != 'DELETE ALL':
            print("Operation cancelled - confirmation text did not match")
            input("Press Enter to continue...")
            return
        
        confirm2 = input("Are you absolutely sure? Type 'YES' to proceed: ").strip().upper()
        
        if confirm2 != 'YES':
            print("Operation cancelled")
            input("Press Enter to continue...")
            return
        
        # Proceed with bulk deletion
        print(f"\n🗑️  Deleting {len(snapshots)} snapshots...")
        print("This may take several minutes depending on snapshot sizes...\n")
        
        success_count = 0
        failed_count = 0
        
        for i, snapshot in enumerate(snapshots, 1):
            snapshot_name = snapshot.get('name', 'Unknown')
            print(f"[{i}/{len(snapshots)}] Deleting '{snapshot_name}'...")
            
            success = self.delete_snapshot(vmid, snapshot_name)
            if success:
                success_count += 1
                print(f"  ✅ Deleted successfully")
            else:
                failed_count += 1
                print(f"  ❌ Failed to delete")
            
            # Small delay between deletions to avoid overwhelming the system
            if i < len(snapshots):
                time.sleep(1)
        
        print(f"\n{'='*60}")
        print("BULK DELETION COMPLETED")
        print(f"{'='*60}")
        print(f"✅ Successfully deleted: {success_count}")
        print(f"❌ Failed to delete: {failed_count}")
        print(f"📊 Total processed: {len(snapshots)}")
        
        if failed_count > 0:
            print(f"\n⚠️  Some snapshots could not be deleted. Check VM status and try again.")
        else:
            print(f"\n🎉 All snapshots deleted successfully!")
        
        print(f"{'='*60}")
        input("\nPress Enter to continue...")
    
    def handle_vm_restore_backup(self, vmid: str):
        """Handle restoring a backup for a VM."""
        print("\n" + "=" * 60)
        print("⚠️  BACKUP RESTORE WARNING")
        print("=" * 60)
        print("This operation will:")
        print("  • OVERWRITE the current VM configuration and disks")
        print("  • Replace ALL VM data with the backup contents")
        print("  • This action cannot be undone!")
        print("=" * 60)
        
        confirm = input("Do you understand and want to proceed? (yes/N): ").strip().lower()
        if confirm != 'yes':
            print("Restore cancelled")
            input("Press Enter to continue...")
            return
        
        # Show storage selection
        storages = self.display_storage_list()
        if not storages:
            input("\nPress Enter to continue...")
            return
        
        print()
        storage_choice = input("Select storage number to browse backups (or 'q' to cancel): ").strip()
        
        if storage_choice.lower() in ['q', 'quit']:
            return
        
        try:
            storage_index = int(storage_choice) - 1
            if 0 <= storage_index < len(storages):
                selected_storage = storages[storage_index]['storage']
                
                # List backups for this VM in selected storage
                print(f"\n🔍 Searching for backups of VM {vmid} in storage '{selected_storage}'...")
                backups = self.list_backups_for_vm(vmid, selected_storage)
                
                if not backups:
                    print(f"\n❌ No backups found for VM {vmid} in storage '{selected_storage}'")
                    input("\nPress Enter to continue...")
                    return
                
                # Display backups and handle selection
                self.display_backup_list(backups)
                
                print()
                backup_choice = input("Select backup number to restore (or 'q' to cancel): ").strip()
                
                if backup_choice.lower() in ['q', 'quit']:
                    return
                
                backup_index = int(backup_choice) - 1
                if 0 <= backup_index < len(backups):
                    selected_backup = backups[backup_index]
                    
                    # Final confirmation
                    print(f"\n⚠️  Final Confirmation:")
                    print(f"Restore backup: {selected_backup['volid']}")
                    
                    final_confirm = input("\nRestore this backup? This will OVERWRITE the current VM! (yes/N): ").strip().lower()
                    if final_confirm == 'yes':
                        # Check and handle VM protection before proceeding
                        if not self.check_and_handle_protection(vmid):
                            input("\nPress Enter to continue...")
                            return
                        
                        # Stop VM if running
                        vm_info = self.get_vm_info(vmid)
                        is_running = vm_info.get('running', False) if vm_info else False
                        if is_running:
                            print("\n🛑 Stopping VM before restore...")
                            self.stop_vm(vmid)
                            time.sleep(3)  # Wait for VM to stop
                        
                        # Perform restore (simplified - assumes local storage)
                        success = self.restore_backup(
                            vmid, 
                            selected_backup['volid'],
                            selected_backup['node'],
                            'local'  # Default storage
                        )
                        
                        if success:
                            print("✅ Backup restore completed successfully!")
                        else:
                            print("❌ Backup restore failed!")
                        
                        input("\nPress Enter to continue...")
                    else:
                        print("Restore cancelled")
                        input("Press Enter to continue...")
                else:
                    print("Invalid backup selection")
                    input("Press Enter to continue...")
            else:
                print("Invalid storage selection")
                input("Press Enter to continue...")
        except ValueError:
            print("Invalid input")
            input("Press Enter to continue...")

    def handle_delete_backup(self, vmid: str):
        """Handle deleting backups for a VM."""
        print(f"\n🗑️  Delete Backup for VM {vmid}")
        print("=" * 50)
        
        # Show VM details
        vm_info = self.get_vm_info(vmid)
        if not vm_info:
            print("❌ Could not get VM information")
            input("Press Enter to continue...")
            return
        
        # Show current VM status
        is_running, status_display, status_details = self.get_vm_status_detailed(vmid)
        print(f"Current VM Status: {status_display}")
        if status_details:
            print(f"Details: {status_details}")
        
        # Show storage selection
        storages = self.display_storage_list()
        if not storages:
            input("\nPress Enter to continue...")
            return
        
        print()
        storage_choice = input("Select storage number to browse backups (or 'q' to cancel): ").strip()
        
        if storage_choice.lower() in ['q', 'quit']:
            return
        
        try:
            storage_index = int(storage_choice) - 1
            if 0 <= storage_index < len(storages):
                selected_storage = storages[storage_index]['storage']
                
                # Get backups for this VM in selected storage
                print(f"\n🔍 Searching for backups of VM {vmid} in storage '{selected_storage}'...")
                backups = self.list_backups_for_vm(vmid, selected_storage)
                
                if not backups:
                    print(f"\n❌ No backups found for VM {vmid} in storage '{selected_storage}'")
                    input("Press Enter to continue...")
                    return
                
                # Sort backups by creation time (newest first)
                backups.sort(key=lambda x: x.get('ctime', 0), reverse=True)
                
                # Display available backups
                print(f"\n📋 Available Backups ({len(backups)}):")
                print("-" * 110)
                print(f"{'#':<3} {'Backup File':<50} {'Size (GB)':<10} {'Created':<20} {'Storage':<15}")
                print("-" * 110)
                
                for i, backup in enumerate(backups, 1):
                    volid = backup.get('volid', 'unknown')
                    filename = volid.split('/')[-1] if '/' in volid else volid
                    size_gb = backup.get('size', 0) / (1024**3) if backup.get('size') else 0
                    ctime = backup.get('ctime', 0)
                    created = datetime.fromtimestamp(ctime).strftime('%Y-%m-%d %H:%M') if ctime else 'Unknown'
                    storage = backup.get('storage', 'unknown')
                    
                    # Truncate long filenames
                    if len(filename) > 49:
                        filename = filename[:46] + "..."
                    
                    print(f"{i:<3} {filename:<50} {size_gb:<10.2f} {created:<20} {storage:<15}")
                
                print("-" * 110)
                
                # Get user selection
                print()
                print("Options:")
                print(f"  - Enter backup number (1-{len(backups)}) to delete specific backup")
                print("  - Enter 'all' to delete ALL backups")
                print("  - Enter 'q' to cancel")
                print()
                choice = input("Your choice: ").strip()
                
                if choice.lower() in ['q', 'quit']:
                    return
                elif choice.lower() == 'all':
                    self.delete_all_backups(vmid, backups, selected_storage)
                    return
                
                try:
                    backup_index = int(choice) - 1
                    if 0 <= backup_index < len(backups):
                        selected_backup = backups[backup_index]
                        self.delete_single_backup(vmid, selected_backup)
                    else:
                        print("Invalid backup selection")
                        input("Press Enter to continue...")
                except ValueError:
                    print("Invalid input")
                    input("Press Enter to continue...")
            else:
                print("Invalid storage selection")
                input("Press Enter to continue...")
        except ValueError:
            print("Invalid input")
            input("Press Enter to continue...")
    
    def delete_single_backup(self, vmid: str, backup: Dict):
        """Delete a single backup."""
        volid = backup.get('volid', 'unknown')
        filename = volid.split('/')[-1] if '/' in volid else volid
        size_gb = backup.get('size', 0) / (1024**3) if backup.get('size') else 0
        ctime = backup.get('ctime', 0)
        created = datetime.fromtimestamp(ctime).strftime('%Y-%m-%d %H:%M:%S') if ctime else 'Unknown'
        
        # Show deletion warning
        print(f"\n⚠️  BACKUP DELETION WARNING")
        print("=" * 60)
        print("This operation will:")
        print(f"  • Permanently delete backup: {filename}")
        print(f"  • Free up disk space: {size_gb:.2f} GB")
        print("  • This action cannot be undone!")
        print("=" * 60)
        
        print(f"\nBackup Details:")
        print(f"  File: {filename}")
        print(f"  Size: {size_gb:.2f} GB")
        print(f"  Created: {created}")
        print(f"  Storage: {backup.get('storage', 'unknown')}")
        print(f"  Node: {backup.get('node', 'unknown')}")
        
        # Final confirmation
        confirm = input(f"\nDelete backup '{filename}'? (yes/N): ").strip().lower()
        if confirm == 'yes':
            # Perform deletion
            print(f"\n🗑️  Deleting backup '{filename}'...")
            success = self.delete_backup_file(backup)
            
            if success:
                print("\n✅ Backup deleted successfully!")
            else:
                print("\n❌ Failed to delete backup!")
            
            input("\nPress Enter to continue...")
        else:
            print("Deletion cancelled")
            input("Press Enter to continue...")
    
    def delete_all_backups(self, vmid: str, backups: List[Dict], storage: str):
        """Delete all backups for a VM in the specified storage."""
        total_size = sum(backup.get('size', 0) for backup in backups) / (1024**3)
        
        print(f"\n🗑️  DELETE ALL BACKUPS WARNING")
        print("=" * 60)
        print("This operation will:")
        print(f"  • Permanently delete ALL {len(backups)} backups")
        print(f"  • Free up disk space: {total_size:.2f} GB")
        print(f"  • Storage: {storage}")
        print("  • This action cannot be undone!")
        print("=" * 60)
        
        print(f"\nBackups to be deleted:")
        for i, backup in enumerate(backups, 1):
            volid = backup.get('volid', 'unknown')
            filename = volid.split('/')[-1] if '/' in volid else volid
            size_gb = backup.get('size', 0) / (1024**3) if backup.get('size') else 0
            ctime = backup.get('ctime', 0)
            created = datetime.fromtimestamp(ctime).strftime('%Y-%m-%d %H:%M') if ctime else 'Unknown'
            print(f"  {i}. {filename} ({size_gb:.2f} GB, Created: {created})")
        
        print("=" * 60)
        
        # Double confirmation for safety
        print("\n⚠️  FINAL WARNING: This will delete ALL backups!")
        confirm1 = input("Type 'DELETE ALL' to confirm this dangerous operation: ").strip()
        
        if confirm1 != 'DELETE ALL':
            print("Operation cancelled - confirmation text did not match")
            input("Press Enter to continue...")
            return
        
        confirm2 = input("Are you absolutely sure? Type 'YES' to proceed: ").strip().upper()
        
        if confirm2 != 'YES':
            print("Operation cancelled")
            input("Press Enter to continue...")
            return
        
        # Proceed with bulk deletion
        print(f"\n🗑️  Deleting {len(backups)} backups...")
        print("This may take several minutes depending on backup sizes...\n")
        
        success_count = 0
        failed_count = 0
        
        for i, backup in enumerate(backups, 1):
            volid = backup.get('volid', 'unknown')
            filename = volid.split('/')[-1] if '/' in volid else volid
            print(f"[{i}/{len(backups)}] Deleting '{filename}'...")
            
            success = self.delete_backup_file(backup)
            if success:
                success_count += 1
                print(f"  ✅ Deleted successfully")
            else:
                failed_count += 1
                print(f"  ❌ Failed to delete")
            
            # Small delay between deletions
            if i < len(backups):
                time.sleep(1)
        
        print(f"\n{'='*60}")
        print("BULK DELETION COMPLETED")
        print(f"{'='*60}")
        print(f"✅ Successfully deleted: {success_count}")
        print(f"❌ Failed to delete: {failed_count}")
        print(f"📊 Total processed: {len(backups)}")
        print(f"💾 Space freed: ~{total_size:.2f} GB")
        
        if failed_count > 0:
            print(f"\n⚠️  Some backups could not be deleted. Check storage permissions.")
        else:
            print(f"\n🎉 All backups deleted successfully!")
        
        print(f"{'='*60}")
        input("\nPress Enter to continue...")
    
    def delete_backup_file(self, backup: Dict) -> bool:
        """Delete a backup file via Proxmox API."""
        volid = backup.get('volid')
        node = backup.get('node')
        
        if not volid or not node:
            print("❌ Missing backup information (volid or node)")
            return False
        
        try:
            print(f"🗑️  Executing backup deletion...")
            
            # Delete backup via API
            task_id = self.api._request('DELETE', f'/nodes/{node}/storage/{backup.get("storage")}/content/{volid}')
            
            # Monitor task progress
            success = self.monitor_task(node, task_id, f"Backup deletion")
            
            return success
            
        except ProxmoxAPIError as e:
            print(f"❌ Backup deletion failed: {e.message}")
            return False
    
    def show_vm_details(self, vmid: str):
        """Show comprehensive VM details (reused from parent with enhancements)."""
        print(f"\n{'='*60}")
        print(f"VM {vmid} - Detailed Information")
        print(f"{'='*60}")
        
        vm_info = self.get_vm_info(vmid)
        if not vm_info:
            print("❌ VM not found or inaccessible")
            return
        
        # Basic info
        print(f"Name: {vm_info['name']}")
        print(f"Node: {vm_info['node']}")
        
        # Status
        is_running, status_display, status_details = self.get_vm_status_detailed(vmid)
        print(f"Status: {status_display}")
        if status_details:
            print(f"Details: {status_details}")
        
        # Protection status
        config = vm_info.get('config', {})
        protection = config.get('protection', '0')
        if protection == '1' or protection == 1:
            print(f"Protection: 🔒 ENABLED (prevents deletion/changes)")
        else:
            print(f"Protection: 🔓 disabled")
        
        # Resource usage
        if is_running:
            cpu_usage = vm_info.get('cpu_usage', 0)
            memory_usage = vm_info.get('memory_usage', 0) // (1024**2)  # MB
            memory_max = vm_info.get('memory_max', 0) // (1024**2)  # MB
            uptime_seconds = vm_info.get('uptime', 0)
            
            # Format uptime
            days = uptime_seconds // 86400
            hours = (uptime_seconds % 86400) // 3600
            minutes = (uptime_seconds % 3600) // 60
            
            if days > 0:
                uptime_str = f"{days}d {hours}h {minutes}m"
            elif hours > 0:
                uptime_str = f"{hours}h {minutes}m"
            else:
                uptime_str = f"{minutes}m"
            
            print(f"CPU Usage: {cpu_usage:.1f}%")
            print(f"Memory: {memory_usage} MB / {memory_max} MB ({(memory_usage/memory_max*100) if memory_max > 0 else 0:.1f}%)")
            print(f"Uptime: {uptime_str}")
        
        # Configuration
        if vm_info.get('config'):
            self.display_vm_config_summary(vm_info['config'], "Configuration")
        
        # Snapshot count
        snapshots = self.get_snapshots(vmid)
        snapshot_count = len([s for s in snapshots if s.get('name') != 'current'])
        print(f"\nSnapshots: {snapshot_count}")
        
        print(f"{'='*60}\n")
    
    def manage_vm_operations(self, vmid: str):
        """Sub-menu for VM management operations."""
        while True:
            try:
                # Show current VM status
                self.show_vm_details(vmid)
                
                # Get current status
                vm_info = self.get_vm_info(vmid)
                if not vm_info:
                    print("❌ VM not found or inaccessible")
                    return
                
                is_running = vm_info['running']
                
                # Show operation menu
                print("VM Management Operations:")
                print("=" * 30)
                print("1. Start VM" + (" ⚠️  (VM is already running)" if is_running else ""))
                print("2. Stop VM (Forceful)" + (" ⚠️  (VM is already stopped)" if not is_running else ""))
                print("3. Shutdown VM (Graceful)" + (" ⚠️  (VM is already stopped)" if not is_running else ""))
                print("4. Create Backup")
                print("5. Restore Backup")
                print("6. Create Snapshot")
                print("7. Rollback Snapshot")
                print("8. Delete Snapshot")
                print("9. Delete Backup")
                print("10. Back to main menu")
                print()
                
                choice = input("Select operation (1-10): ").strip()
                
                if choice == '1':  # Start VM
                    if is_running:
                        print("\n⚠️  WARNING: VM is already running!")
                        input("Press Enter to continue...")
                        continue
                    else:
                        confirm = input("\nStart VM? (y/N): ").strip().lower()
                        if confirm in ['y', 'yes']:
                            self.start_vm(vmid)
                            input("\nPress Enter to continue...")
                
                elif choice == '2':  # Stop VM (Forceful)
                    if not is_running:
                        print("\n⚠️  WARNING: VM is already stopped!")
                        input("Press Enter to continue...")
                        continue
                    else:
                        print("\n⚠️  WARNING: You are about to forcefully stop a running VM!")
                        print("This will immediately terminate all processes in the VM.")
                        confirm = input("Are you sure you want to forcefully stop this VM? (yes/N): ").strip().lower()
                        if confirm == 'yes':  # Require full "yes" for stopping
                            self.stop_vm(vmid)
                            input("\nPress Enter to continue...")
                        else:
                            print("Operation cancelled")
                            input("Press Enter to continue...")
                
                elif choice == '3':  # Shutdown VM (Graceful)
                    if not is_running:
                        print("\n⚠️  WARNING: VM is already stopped!")
                        input("Press Enter to continue...")
                        continue
                    else:
                        print("\n🔄 You are about to gracefully shutdown the VM.")
                        print("This will send an ACPI shutdown signal to the VM OS.")
                        confirm = input("Proceed with graceful shutdown? (y/N): ").strip().lower()
                        if confirm in ['y', 'yes']:
                            self.shutdown_vm(vmid)
                            input("\nPress Enter to continue...")
                        else:
                            print("Operation cancelled")
                            input("Press Enter to continue...")
                
                elif choice == '4':  # Create Backup
                    # Show storage selection
                    storages = self.display_storage_list()
                    if not storages:
                        input("\nPress Enter to continue...")
                        continue
                    
                    print()
                    storage_choice = input("Select storage number (or 'q' to cancel): ").strip()
                    
                    if storage_choice.lower() in ['q', 'quit']:
                        continue
                    
                    try:
                        storage_index = int(storage_choice) - 1
                        if 0 <= storage_index < len(storages):
                            selected_storage = storages[storage_index]['storage']
                            
                            # Select backup mode
                            print("\nBackup Mode:")
                            print("1. snapshot - Fastest, VM stays running (requires qemu-guest-agent)")
                            print("2. suspend - VM is suspended during backup")
                            print("3. stop - Safest, VM is stopped during backup")
                            print()
                            
                            mode_choice = input("Select backup mode (1-3, default: 1): ").strip()
                            
                            mode_map = {'1': 'snapshot', '2': 'suspend', '3': 'stop', '': 'snapshot'}
                            if mode_choice in mode_map:
                                backup_mode = mode_map[mode_choice]
                                
                                # Confirm backup
                                print(f"\nBackup Configuration:")
                                print(f"  VM: {vmid} ({vm_info['name']})")
                                print(f"  Storage: {selected_storage}")
                                print(f"  Mode: {backup_mode}")
                                
                                confirm = input("\nProceed with backup? (y/N): ").strip().lower()
                                if confirm in ['y', 'yes']:
                                    self.create_backup(vmid, selected_storage, backup_mode)
                                    input("\nPress Enter to continue...")
                                else:
                                    print("Backup cancelled")
                                    input("Press Enter to continue...")
                            else:
                                print("Invalid mode selection")
                                input("Press Enter to continue...")
                        else:
                            print("Invalid storage selection")
                            input("Press Enter to continue...")
                    except ValueError:
                        print("Invalid input")
                        input("Press Enter to continue...")
                
                elif choice == '4':  # Create Backup
                    # Show storage selection
                    storages = self.display_storage_list()
                    if not storages:
                        input("\nPress Enter to continue...")
                        continue
                    
                    print()
                    storage_choice = input("Select storage number (or 'q' to cancel): ").strip()
                    
                    if storage_choice.lower() in ['q', 'quit']:
                        continue
                    
                    try:
                        storage_index = int(storage_choice) - 1
                        if 0 <= storage_index < len(storages):
                            selected_storage = storages[storage_index]['storage']
                            
                            # Show backup mode selection
                            print(f"\n💾 Create Backup for VM {vmid}")
                            print("=" * 40)
                            print("Backup Modes:")
                            print("1. snapshot - VM keeps running (fastest)")
                            print("2. suspend - VM is suspended during backup")
                            print("3. stop - Safest, VM is stopped during backup")
                            print()
                            
                            mode_choice = input("Select backup mode (1-3): ").strip()
                            mode_map = {'1': 'snapshot', '2': 'suspend', '3': 'stop'}
                            
                            if mode_choice in mode_map:
                                selected_mode = mode_map[mode_choice]
                                
                                print(f"\n📦 Creating backup in '{selected_storage}' using '{selected_mode}' mode...")
                                success = self.create_backup(vmid, selected_storage, selected_mode)
                                
                                if success:
                                    print("✅ Backup created successfully!")
                                else:
                                    print("❌ Backup creation failed!")
                            else:
                                print("Invalid mode selection")
                            
                            input("\nPress Enter to continue...")
                        else:
                            print("Invalid storage selection")
                            input("Press Enter to continue...")
                    except ValueError:
                        print("Invalid input")
                        input("Press Enter to continue...")
                
                elif choice == '5':  # Restore Backup
                    self.handle_vm_restore_backup(vmid)
                
                elif choice == '6':  # Create Snapshot
                    self.handle_create_snapshot(vmid)
                
                elif choice == '7':  # Rollback Snapshot
                    self.handle_rollback_snapshot(vmid)
                
                elif choice == '8':  # Delete Snapshot
                    self.handle_delete_snapshot(vmid)
                
                elif choice == '9':  # Delete Backup
                    self.handle_delete_backup(vmid)
                
                elif choice == '10':  # Back to main menu
                    break
                
                else:
                    print("Invalid choice. Please select 1-10.")
                    input("Press Enter to continue...")
                
            except KeyboardInterrupt:
                print("\nReturning to main menu...")
                break
    
    def main_menu(self):
        """Main menu for VM management."""
        print("Proxmox VM Management Tool")
        print("=" * 30)
        
        while True:
            try:
                print()
                print("Options:")
                print("  1. View Available VMs")
                print("  2. Manage Single VM (enter VM ID)")
                print("  3. Bulk Operations")
                print("  4. Quick Start All Stopped VMs")
                print("  5. Quick Stop All Running VMs")
                print("  6. Quick Backup All VMs")
                print("  q. Quit")
                print()
                
                choice = input("Select option (1-6, VM ID, or 'q'): ").strip()
                
                if choice.lower() in ['q', 'quit']:
                    print("Goodbye!")
                    break
                elif choice == '1':
                    # View Available VMs
                    self.display_vm_list_interactive()
                    input("\nPress Enter to continue...")
                elif choice == '2':
                    # Manage Single VM
                    vm_id = input("Enter VM ID to manage: ").strip()
                    if vm_id:
                        vm_info = self.get_vm_info(vm_id)
                        if vm_info:
                            self.manage_vm_operations(vm_id)
                        else:
                            print(f"❌ VM {vm_id} not found or inaccessible")
                            input("Press Enter to continue...")
                elif choice == '3':
                    self.bulk_operations_menu()
                elif choice == '4':
                    self.quick_start_all()
                elif choice == '5':
                    self.quick_stop_all()
                elif choice == '6':
                    self.quick_backup_all()
                else:
                    # Try to interpret as VM ID
                    vm_info = self.get_vm_info(choice)
                    if vm_info:
                        self.manage_vm_operations(choice)
                    else:
                        print(f"❌ Invalid option or VM {choice} not found")
                        input("Press Enter to continue...")
                
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break


def main():
    """Main function to initialize and run the VM manager."""
    manager = ProxmoxVMManager()
    
    # Check for help
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        manager.display_usage()
        sys.exit(0)
    
    # Connect to Proxmox API (reused from parent)
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
        print()
        
    except Exception as e:
        print(f"❌ Error verifying connection: {e}")
        sys.exit(1)
    
    # Run main menu
    manager.main_menu()


if __name__ == "__main__":
    main()
