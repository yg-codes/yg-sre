#!/usr/bin/env python3

"""
Proxmox VM Snapshot Management Script (API Version)
Usage: ./pve_snapshot_manager_api.py

Provides comprehensive VM snapshot management capabilities:
- Create snapshots with intelligent naming
- Rollback to previous snapshots
- List and manage existing snapshots
- Delete snapshots with safety checks
- Bulk snapshot operations
- Real-time task monitoring
"""

import sys
import time
import re
import threading
import json
import getpass
import argparse
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
    
    def find_vm_by_name_or_id(self, identifier: str, all_vms: List[Dict]) -> Optional[str]:
        """Find VM ID by either VM ID or VM name from the provided VM list."""
        # First, try direct VM ID match
        if any(vm['vmid'] == identifier for vm in all_vms):
            return identifier
        
        # Try exact name match (case-insensitive)
        for vm in all_vms:
            vm_name = vm.get('name', '')
            if vm_name.lower() == identifier.lower():
                return vm['vmid']
        
        # Try partial name matching (case-insensitive)
        matches = []
        for vm in all_vms:
            vm_name = vm.get('name', '')
            if identifier.lower() in vm_name.lower():
                matches.append(vm)
        
        # If exactly one partial match, return it
        if len(matches) == 1:
            return matches[0]['vmid']
        elif len(matches) > 1:
            # Multiple matches - show them and return None
            print(f"⚠️  Multiple VMs match '{identifier}':")
            for vm in matches:
                status = "🟢 running" if vm.get('running', False) else "🔴 stopped"
                print(f"  - VM {vm['vmid']}: {vm['name']} ({status})")
            print("Please be more specific.")
            return None
        
        return None
    
    def resolve_vm_identifiers(self, identifiers: List[str], all_vms: List[Dict]) -> List[str]:
        """Resolve a list of VM identifiers (IDs or names) to VM IDs."""
        resolved_ids = []
        failed_lookups = []
        
        for identifier in identifiers:
            vm_id = self.find_vm_by_name_or_id(identifier, all_vms)
            if vm_id:
                if vm_id not in resolved_ids:  # Avoid duplicates
                    resolved_ids.append(vm_id)
            else:
                failed_lookups.append(identifier)
        
        if failed_lookups:
            print(f"⚠️  Could not find VMs: {', '.join(failed_lookups)}")
        
        return resolved_ids
    
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
        
        # Handle comma-separated list (e.g., "7201,7203,smtp01,workstation03")
        if ',' in selection:
            identifiers = [item.strip() for item in selection.split(',') if item.strip()]
            return self.resolve_vm_identifiers(identifiers, all_vms)
        
        # Handle pattern matching (e.g., "72*", "smtp*", "*workstation*")
        if '*' in selection:
            pattern = selection.replace('*', '.*')
            vm_ids = []
            for vm in all_vms:
                # Check against VM ID
                if re.match(pattern, vm['vmid']):
                    vm_ids.append(vm['vmid'])
                # Also check against VM name
                elif re.match(pattern, vm.get('name', ''), re.IGNORECASE):
                    vm_ids.append(vm['vmid'])
            return vm_ids
        
        # Handle single VM ID or name
        vm_id = self.find_vm_by_name_or_id(selection, all_vms)
        if vm_id:
            return [vm_id]
        
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
        print("  *                    - All VMs")
        print("  running              - All running VMs")
        print("  stopped              - All stopped VMs")
        print("  7201-7205            - Range of VM IDs")
        print("  7201,7203            - VM IDs (comma-separated)")
        print("  smtp01,workstation03 - VM names (comma-separated)")
        print("  7201,smtp01          - Mixed IDs and names")
        print("  72*                  - Pattern matching VM IDs")
        print("  smtp*                - Pattern matching VM names")
        print("  *workstation*        - Pattern matching (contains)")
        print("  i                    - Interactive selection")
        print("  7201                 - Single VM ID")
        print("  xsf-dev-smtp01       - Single VM name")
        print("  smtp01               - Partial VM name")
        print()
        print("Examples with your VMs:")
        print("  centos*              - All CentOS VMs (751,752,753)")
        print("  *smtp*               - All SMTP VMs (7204,7206)")
        print("  workstation*         - All workstation VMs")
        print("  7201,smtp01,tacacs01 - Mixed selection")
        print()

class ProxmoxSnapshotManager:
    """Manages Proxmox VM snapshots using API with intelligent naming and validation."""
    
    def __init__(self):
        self.max_snapshot_name_length = 40
        self.max_prefix_length = 25
        self.save_vmstate = False
        self.api = None
        self.nodes_cache = {}
        self.vm_selector = VMSelector(self)
        self.vmstate_keywords = ['vmstate', 'RAM', 'with vmstate', 'RAM included', 'with VM state', 'VM state included']
        
    def display_usage(self):
        """Display usage information."""
        usage_text = """
Proxmox VM Snapshot Management Tool (API Version)
================================================

This tool provides comprehensive VM snapshot management capabilities:
- Create snapshots with intelligent naming
- Rollback to previous snapshots
- List and manage existing snapshots
- Delete snapshots with safety checks
- Bulk snapshot operations
- Real-time task monitoring

API Authentication Options:
  1. Username/Password (prompted)
  2. API Token (set environment variables):
     export PVE_HOST=your-proxmox-host
     export PVE_USER=username@realm
     export PVE_TOKEN_NAME=token-name
     export PVE_TOKEN_VALUE=token-value

Usage: python3 pve_snapshot_manager_api.py
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
                
                time.sleep(2)
                
            except ProxmoxAPIError:
                return False

    def create_snapshot(self, vmid: str, name_or_prefix: str, use_exact_name: bool = False) -> bool:
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
        
        # Create snapshot name based on mode
        if use_exact_name:
            full_snapshot_name = name_or_prefix
            print(f"Creating snapshot for VM {vmid} with exact name...")
        else:
            # Original behavior: prefix + vm_name + timestamp
            full_snapshot_name = f"{name_or_prefix}-{vm_name}-{timestamp}"
            print(f"Creating snapshot for VM {vmid} with generated name...")
            
            # Handle name length limits for generated names
            if len(full_snapshot_name) > self.max_snapshot_name_length:
                print(f"  ⚠ Snapshot name too long ({len(full_snapshot_name)} chars), truncating VM name...")
                
                prefix_suffix_length = len(name_or_prefix) + 1 + 1 + 13
                max_vm_name_length = self.max_snapshot_name_length - prefix_suffix_length
                
                if max_vm_name_length <= 0:
                    print(f"  ✗ Prefix '{name_or_prefix}' is too long. Maximum prefix length is {self.max_snapshot_name_length - 14} characters")
                    return False
                
                truncated_vm_name = self.truncate_vm_name_intelligently(vm_name, max_vm_name_length)
                full_snapshot_name = f"{name_or_prefix}-{truncated_vm_name}-{timestamp}"
                print(f"  📝 Truncated VM name: '{vm_name}' -> '{truncated_vm_name}'")
        
        # Validate final snapshot name length
        if len(full_snapshot_name) > self.max_snapshot_name_length:
            print(f"  ✗ Final snapshot name '{full_snapshot_name}' is too long ({len(full_snapshot_name)} chars, max {self.max_snapshot_name_length})")
            return False
        
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
    
    def list_snapshots(self, vmid: str):
        """List all snapshots for a VM in a formatted table."""
        print(f"\n📸 Snapshots for VM {vmid}")
        print("=" * 120)
        
        # Show VM details
        vm_info = self.get_vm_info(vmid)
        if not vm_info:
            print("❌ Could not get VM information")
            return
        
        # Show current VM status
        is_running, status_display, status_details = self.get_vm_status_detailed(vmid)
        print(f"VM: {vm_info['name']} ({status_display})")
        print(f"Node: {vm_info['node']}")
        print()
        
        # Get snapshots
        snapshots = self.get_snapshots(vmid)
        if not snapshots:
            print("❌ No snapshots found for this VM")
            return
        
        # Filter out 'current' snapshot
        available_snapshots = [s for s in snapshots if s.get('name') != 'current']
        if not available_snapshots:
            print("❌ No snapshots available (only current state found)")
            return
        
        # Sort by snaptime (newest first) - handle missing snaptime
        available_snapshots.sort(key=lambda x: x.get('snaptime', 0), reverse=True)
        
        # Display snapshots table with full names
        print(f"Found {len(available_snapshots)} snapshot(s):")
        print("-" * 160)
        print(f"{'#':<3} {'Snapshot Name':<50} {'Description':<40} {'Created':<20} {'Parent':<20} {'VMState':<8}")
        print("-" * 160)
        
        for i, snapshot in enumerate(available_snapshots, 1):
            name = snapshot.get('name', 'Unknown')
            desc = snapshot.get('description', 'No description')
            parent = snapshot.get('parent', 'N/A')
            
            # Format creation time
            snaptime = snapshot.get('snaptime', 0)
            if snaptime:
                created = datetime.fromtimestamp(snaptime).strftime('%Y-%m-%d %H:%M:%S')
            else:
                created = 'Unknown'
            
            # Check if snapshot has vmstate
            has_vmstate = '❌'
            if 'vmstate' in snapshot:
                has_vmstate = '✅' if snapshot.get('vmstate') else '❌'
            elif any(keyword in desc.lower() for keyword in self.vmstate_keywords):
                has_vmstate = '✅'
            
            # Truncate only description if too long, keep names full
            if len(desc) > 39:
                desc = desc[:36] + "..."
            if len(parent) > 19:
                parent = parent[:16] + "..."
            
            print(f"{i:<3} {name:<50} {desc:<40} {created:<20} {parent:<20} {has_vmstate:<8}")
        
        print("-" * 160)
        print(f"Total: {len(available_snapshots)} snapshots")
        print("Legend: ✅ = Has VM state (RAM), ❌ = Disk only")
        print()
        print("💡 To use these snapshots:")
        print(f"   Rollback: python3 pve_snapshot_manager_api.py rollback {vmid} <snapshot_name>")
        print(f"   Delete:   python3 pve_snapshot_manager_api.py delete {vmid} <snapshot_name>")
        print("   Copy the exact snapshot name from the 'Snapshot Name' column above")
    
    def show_vm_details(self, vmid: str):
        """Show comprehensive VM details."""
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
        
        # Snapshot count
        snapshots = self.get_snapshots(vmid)
        snapshot_count = len([s for s in snapshots if s.get('name') != 'current'])
        print(f"\nSnapshots: {snapshot_count}")
        
        print(f"{'='*60}\n")
    
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
                    # Stop VM if running (rollback will handle this automatically)
                    if is_running:
                        print(f"\n🛑 VM will be stopped automatically during rollback...")
                    
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
                                print("🚀 Starting VM...")
                                # Note: start_vm function is hidden but still available
                                # You could implement a simple start function here if needed
                                print("VM start functionality is available but hidden in this snapshot manager")
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
        print("  - Hint: Press Ctrl+C to return to upper menu")
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
    
    # ============================================================================
    # BULK OPERATIONS
    # ============================================================================
    
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
        print("Hint: Press Ctrl+C to return to upper menu")
        print()
        
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
    
    def bulk_operations_menu(self):
        """Interactive menu for bulk snapshot operations."""
        while True:
            try:
                print("\n🔧 Bulk Snapshot Operations Menu")
                print("=" * 40)
                print("1. Bulk Create Snapshots")
                print("2. Bulk Delete Snapshots")
                print("3. VM Selection Help")
                print("4. Back to Main Menu")
                print()
                
                choice = input("Select operation (1-4): ").strip()
                
                if choice == '1':  # Bulk Create
                    self.handle_bulk_create_snapshots()
                elif choice == '2':  # Bulk Delete
                    self.handle_bulk_delete_snapshots()
                elif choice == '3':  # Help
                    self.vm_selector.display_selection_help()
                    input("Press Enter to continue...")
                elif choice == '4':  # Back
                    break
                else:
                    print("Invalid choice. Please select 1-4.")
                    input("Press Enter to continue...")
                    
            except KeyboardInterrupt:
                print("\nReturning to main menu...")
                break
    
    # ============================================================================
    # MENU SYSTEM
    # ============================================================================
    
    def manage_vm_snapshots(self, vmid: str):
        """Sub-menu for VM snapshot management operations."""
        while True:
            try:
                # Show current VM status
                self.show_vm_details(vmid)
                
                # Get current status
                vm_info = self.get_vm_info(vmid)
                if not vm_info:
                    print("❌ VM not found or inaccessible")
                    return
                
                # Show operation menu
                print("Snapshot Management Operations:")
                print("=" * 30)
                print("1. Create Snapshot")
                print("2. Rollback Snapshot")
                print("3. List Snapshots")
                print("4. Delete Snapshot")
                print("5. Back to main menu")
                print("q. Quit")
                print()
                
                choice = input("Select operation (1-5, q): ").strip()
                
                if choice == '1':  # Create Snapshot
                    self.handle_create_snapshot(vmid)
                
                elif choice == '2':  # Rollback Snapshot
                    self.handle_rollback_snapshot(vmid)
                
                elif choice == '3':  # List Snapshots
                    self.list_snapshots(vmid)
                    input("\nPress Enter to continue...")
                
                elif choice == '4':  # Delete Snapshot
                    self.handle_delete_snapshot(vmid)
                
                elif choice == '5':  # Back to main menu
                    break
                
                elif choice.lower() in ['q', 'quit']:
                    print("Goodbye!")
                    sys.exit(0)
                
                else:
                    print("Invalid choice. Please select 1-5 or 'q'.")
                    input("Press Enter to continue...")
                
            except KeyboardInterrupt:
                print("\nReturning to main menu...")
                break
    
    def find_vm_by_name_or_id(self, identifier: str) -> Optional[str]:
        """Find VM ID by either VM ID or VM name."""
        # First, try to get VM info directly (assuming it's a VM ID)
        vm_info = self.get_vm_info(identifier)
        if vm_info:
            return identifier
        
        # If that fails, search by name
        all_vms = self.get_all_vms()
        for vm in all_vms:
            vm_name = vm.get('name', '')
            if vm_name.lower() == identifier.lower():
                return str(vm['vmid'])
        
        # Also try partial name matching (case-insensitive)
        for vm in all_vms:
            vm_name = vm.get('name', '')
            if identifier.lower() in vm_name.lower():
                return str(vm['vmid'])
        
        return None
    
    def main_menu(self):
        """Main menu for snapshot management."""
        print("Proxmox Snapshot Management Tool")
        print("=" * 30)
        
        while True:
            try:
                print()
                print("Options:")
                print("  1. View Available VMs")
                print("  2. Manage Single VM (enter VM ID or Name)")
                print("  3. Bulk Operations")
                print("  q. Quit")
                print()
                
                choice = input("Select option (1-3, VM ID/Name, or 'q'): ").strip()
                
                if choice.lower() in ['q', 'quit']:
                    print("Goodbye!")
                    break
                elif choice == '1':
                    # View Available VMs
                    self.display_vm_list_interactive()
                    input("\nPress Enter to continue...")
                elif choice == '2':
                    # Manage Single VM
                    vm_identifier = input("Enter VM ID or VM Name: ").strip()
                    if vm_identifier:
                        vm_id = self.find_vm_by_name_or_id(vm_identifier)
                        if vm_id:
                            vm_info = self.get_vm_info(vm_id)
                            print(f"✅ Found VM {vm_id}: {vm_info['name']}")
                            self.manage_vm_snapshots(vm_id)
                        else:
                            print(f"❌ VM '{vm_identifier}' not found")
                            print("You can enter:")
                            print("  - VM ID (e.g., 7303)")
                            print("  - Full VM name (e.g., xsf-dev-workstation03)")
                            print("  - Partial VM name (e.g., workstation03)")
                            input("Press Enter to continue...")
                elif choice == '3':
                    self.bulk_operations_menu()
                else:
                    # Try to interpret as VM ID or Name
                    vm_id = self.find_vm_by_name_or_id(choice)
                    if vm_id:
                        vm_info = self.get_vm_info(vm_id)
                        print(f"✅ Found VM {vm_id}: {vm_info['name']}")
                        self.manage_vm_snapshots(vm_id)
                    else:
                        print(f"❌ Invalid option or VM '{choice}' not found")
                        print("You can enter:")
                        print("  - Menu option (1-3)")
                        print("  - VM ID (e.g., 7303)")
                        print("  - Full VM name (e.g., xsf-dev-workstation03)")
                        print("  - Partial VM name (e.g., workstation03)")
                        input("Press Enter to continue...")
                
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break


    def display_usage(self):
        """Display usage information."""
        usage_text = """
Proxmox VM Snapshot Management Tool (API Version)
================================================

INTERACTIVE MODE:
  python3 pve_snapshot_manager_api.py
  
  Provides comprehensive VM snapshot management with interactive menus:
  - Create snapshots with intelligent naming
  - Rollback to previous snapshots
  - List and manage existing snapshots
  - Delete snapshots with safety checks
  - Bulk snapshot operations

COMMAND LINE MODE:
  
  CREATE SNAPSHOTS:
    python3 pve_snapshot_manager_api.py create --vmid [vmid1] [vmid2] --prefix [prefix]
    python3 pve_snapshot_manager_api.py create --vmname [vmname1] [vmname2] --prefix [prefix]
    python3 pve_snapshot_manager_api.py create --vmid [vmid] --snapshot_name [exact_name]
    
    Creates snapshots with format: <PREFIX>-<3RD_SECTION>-YYYYMMDD-HHMMSS
    The 3RD_SECTION is extracted from VM name using '-' as separator (3rd part onwards)
    
    Options:
      --vmstate 1       Include VM state (RAM) in snapshot (slower but complete state)
      --vmstate 0       Disk only snapshot (faster, default)
      --yes             Skip confirmation prompt
    
    Examples:
      python3 pve_snapshot_manager_api.py create --vmid 7201 7203 --prefix pre-update
      python3 pve_snapshot_manager_api.py create --vmname smtp01 workstation03 --prefix backup --vmstate 1
      python3 pve_snapshot_manager_api.py create --vmid 7201 --snapshot_name backup-20250101-1200
      
  DELETE SNAPSHOTS:
    python3 pve_snapshot_manager_api.py delete --vmid [vmid] --snapshot_name [snapshot_name]
    python3 pve_snapshot_manager_api.py delete --vmname [vmname] --snapshot_name [snapshot_name1] [snapshot_name2]
    python3 pve_snapshot_manager_api.py delete --vmid [vmid] --all
    
    Delete VM snapshots with comprehensive safety checks and status monitoring.
    Supports deleting multiple snapshots or all snapshots for a VM.
    
    Examples:
      python3 pve_snapshot_manager_api.py delete --vmid 7201 --snapshot_name pre-update-smtp01-20250609-1430
      python3 pve_snapshot_manager_api.py delete --vmname smtp01 --snapshot_name backup-smtp01-20250608-0900 backup-smtp01-20250607-0900
      python3 pve_snapshot_manager_api.py delete --vmid 7201 --all
      
  ROLLBACK SNAPSHOTS:
    python3 pve_snapshot_manager_api.py rollback --vmid [vmid] --snapshot_name [snapshot_name]
    python3 pve_snapshot_manager_api.py rollback --vmname [vmname] --snapshot_name [snapshot_name]
    python3 pve_snapshot_manager_api.py rollback --vmid [vmid1] [vmid2] --snapshot_name [snapshot_name]
    python3 pve_snapshot_manager_api.py rollback --vmname [vmname1] [vmname2] --snapshot_name [snapshot_name]
    
    Rollback VM(s) to a specific snapshot with comprehensive safety checks and status monitoring.
    Supports rolling back multiple VMs to the same snapshot.
    
    Examples:
      python3 pve_snapshot_manager_api.py rollback --vmid 7201 --snapshot_name pre-update-smtp01-20250609-1430
      python3 pve_snapshot_manager_api.py rollback --vmname smtp01 --snapshot_name backup-smtp01-20250608-0900
      python3 pve_snapshot_manager_api.py rollback --vmid 7201 7202 --snapshot_name pre-update-batch-20250609-1430
      python3 pve_snapshot_manager_api.py rollback --vmname smtp01 smtp02 --snapshot_name backup-batch-20250608-0900
      
  LIST SNAPSHOTS:
    python3 pve_snapshot_manager_api.py list --vmid [vmid1] [vmid2]
    python3 pve_snapshot_manager_api.py list --vmname [vmname1] [vmname2]
    
    List all snapshots for specific VM(s).
    
    Examples:
      python3 pve_snapshot_manager_api.py list --vmid 7201
      python3 pve_snapshot_manager_api.py list --vmname smtp01
      python3 pve_snapshot_manager_api.py list --vmid 7201 7202 7203
      python3 pve_snapshot_manager_api.py list --vmname smtp01 smtp02

API Authentication Options:
  1. Username/Password (prompted in interactive mode)
  2. API Token (set environment variables):
     export PVE_HOST=your-proxmox-host
     export PVE_USER=username@realm
     export PVE_TOKEN_NAME=token-name
     export PVE_TOKEN_VALUE=token-value

Command Line Notes:
  - VM identifiers can be VM IDs (7201) or VM names (smtp01, xsf-dev-smtp01)
  - For create command, you can specify multiple VMs separated by spaces or commas
  - Snapshot names must be exact (use 'list' command to see available snapshots)
  - All operations include comprehensive safety checks and status monitoring
"""
        print(usage_text)
    
    def parse_vm_list(self, vm_args: List[str]) -> List[str]:
        """Parse command line VM arguments, supporting both individual and comma-separated lists."""
        all_vms = self.get_all_vms_info()
        vm_identifiers = []
        
        # Join all args and split by comma to handle both formats:
        # ["7201", "7202,7203", "smtp01"] -> ["7201", "7202", "7203", "smtp01"]
        for arg in vm_args:
            vm_identifiers.extend([vm.strip() for vm in arg.split(',') if vm.strip()])
        
        # Resolve all identifiers to VM IDs
        resolved_ids = []
        for identifier in vm_identifiers:
            vm_id = self.find_vm_by_name_or_id(identifier)
            if vm_id:
                resolved_ids.append(vm_id)
            else:
                print(f"❌ VM '{identifier}' not found")
                return []
        
        return resolved_ids
    
    def cmd_create_snapshots(self, args: List[str], skip_confirmation: bool = False, use_exact_name: bool = False) -> bool:
        """Handle command line snapshot creation."""
        if len(args) < 2:
            print("❌ Usage: python3 pve_snapshot_manager_api.py create [options] [prefix] [vmid1/vmname1] [vmid2/vmname2] ...")
            print("Options:")
            print("  --with-vmstate    Include VM state (RAM) in snapshot")
            print("  --no-vmstate      Disk only snapshot (default)")
            print("Example: python3 pve_snapshot_manager_api.py create --with-vmstate pre-update 7201 smtp01")
            return False
        
        # Parse options
        include_vmstate = False  # Default to disk-only
        arg_index = 0
        
        # Check for vmstate options
        if args[0] == '--with-vmstate':
            include_vmstate = True
            arg_index = 1
        elif args[0] == '--no-vmstate':
            include_vmstate = False
            arg_index = 1
        
        # Ensure we have enough arguments after parsing options
        if len(args) < arg_index + 2:
            print("❌ Usage: python3 pve_snapshot_manager_api.py create [options] [prefix] [vmid1/vmname1] [vmid2/vmname2] ...")
            print("Options:")
            print("  --with-vmstate    Include VM state (RAM) in snapshot")
            print("  --no-vmstate      Disk only snapshot (default)")
            print("Example: python3 pve_snapshot_manager_api.py create --with-vmstate pre-update 7201 smtp01")
            return False
        
        snapshot_name_or_prefix = args[arg_index]
        vm_args = args[arg_index + 1:]
        
        # Validate snapshot name/prefix
        max_length = 40 if use_exact_name else 20
        name_type = "snapshot name" if use_exact_name else "prefix"
        
        if len(snapshot_name_or_prefix) > max_length:
            print(f"❌ {name_type.capitalize()} '{snapshot_name_or_prefix}' too long (max {max_length} characters)")
            return False
        
        # Parse VM list
        vm_ids = self.parse_vm_list(vm_args)
        if not vm_ids:
            return False
        
        action_desc = f"Creating snapshots for {len(vm_ids)} VMs with {name_type} '{snapshot_name_or_prefix}'"
        print(f"📸 {action_desc}")
        print(f"VM State: {'WITH vmstate (RAM)' if include_vmstate else 'WITHOUT vmstate (disk only)'}")
        print("VMs to snapshot:")
        
        running_count = 0
        for vm_id in vm_ids:
            vm_info = self.get_vm_info(vm_id)
            if vm_info:
                status = "🟢 running" if vm_info['running'] else "🔴 stopped"
                if vm_info['running']:
                    running_count += 1
                print(f"  - VM {vm_id}: {vm_info['name']} ({status})")
        
        # Show vmstate behavior for running VMs
        if include_vmstate and running_count > 0:
            print(f"\n💡 VM State Info:")
            print(f"  - {running_count} running VM(s) will include RAM state")
            print(f"  - {len(vm_ids) - running_count} stopped VM(s) will be disk-only (RAM state not applicable)")
        elif include_vmstate and running_count == 0:
            print(f"\n⚠️  Note: --with-vmstate specified but all VMs are stopped")
            print(f"  All snapshots will be disk-only (RAM state only applies to running VMs)")
        
        # Confirm operation
        if skip_confirmation:
            print("\n✅ Proceeding with snapshot creation (--yes flag provided)")
        else:
            confirm = input(f"\nProceed to create snapshots? (y/N): ").strip().lower()
            if confirm not in ['y', 'yes']:
                print("Operation cancelled")
                return False
        
        # Set vmstate option temporarily
        original_vmstate = getattr(self, 'save_vmstate', False)
        self.save_vmstate = include_vmstate
        
        try:
            # Create snapshots
            success_count = 0
            for vm_id in vm_ids:
                print(f"\n{'='*60}")
                success = self.create_snapshot(vm_id, snapshot_name_or_prefix, use_exact_name=use_exact_name)
                if success:
                    success_count += 1
        finally:
            # Restore original vmstate setting
            self.save_vmstate = original_vmstate
        
        print(f"\n{'='*60}")
        print(f"SNAPSHOT CREATION SUMMARY")
        print(f"{'='*60}")
        print(f"Total VMs: {len(vm_ids)}")
        print(f"Successful: {success_count}")
        print(f"Failed: {len(vm_ids) - success_count}")
        print(f"Success Rate: {(success_count/len(vm_ids)*100):.1f}%")
        print(f"VM State: {'WITH vmstate (RAM)' if include_vmstate else 'WITHOUT vmstate (disk only)'}")
        
        return success_count == len(vm_ids)
    def cmd_delete_snapshot(self, args: List[str], skip_confirmation: bool = False) -> bool:
        """Handle command line snapshot deletion."""
        if len(args) != 2:
            print("❌ Usage: python3 pve_snapshot_manager_api.py delete [vmid/vmname] [snapshot_name]")
            print("Example: python3 pve_snapshot_manager_api.py delete 7201 pre-update-smtp01-20250609-1430")
            return False
        
        vm_identifier, snapshot_name = args
        
        # Resolve VM ID
        vm_id = self.find_vm_by_name_or_id(vm_identifier)
        if not vm_id:
            print(f"❌ VM '{vm_identifier}' not found")
            return False
        
        vm_info = self.get_vm_info(vm_id)
        if not vm_info:
            print(f"❌ Could not get VM information for {vm_id}")
            return False
        
        print(f"🗑️  Deleting snapshot '{snapshot_name}' from VM {vm_id}")
        print(f"VM: {vm_info['name']}")
        
        # Check if snapshot exists
        snapshots = self.get_snapshots(vm_id)
        available_snapshots = [s for s in snapshots if s.get('name') != 'current']
        snapshot_exists = any(s.get('name') == snapshot_name for s in available_snapshots)
        
        if not snapshot_exists:
            print(f"❌ Snapshot '{snapshot_name}' not found")
            if available_snapshots:
                print("Available snapshots:")
                for snapshot in available_snapshots:
                    name = snapshot.get('name', 'Unknown')
                    desc = snapshot.get('description', 'No description')
                    print(f"  - {name}: {desc}")
            else:
                print("No snapshots available for this VM")
            return False
        
        # Show deletion warning
        print(f"\n⚠️  SNAPSHOT DELETION WARNING")
        print("=" * 60)
        print("This operation will:")
        print(f"  • Permanently delete snapshot: {snapshot_name}")
        print("  • Free up disk space used by this snapshot")
        print("  • This action cannot be undone!")
        print("=" * 60)
        
        # Confirm operation
        if skip_confirmation:
            print(f"\n✅ Proceeding with snapshot deletion (--yes flag provided)")
        else:
            confirm = input(f"\nDelete snapshot '{snapshot_name}'? (yes/N): ").strip().lower()
            if confirm != 'yes':
                print("Operation cancelled")
                return False
        
        # Delete snapshot
        success = self.delete_snapshot(vm_id, snapshot_name)
        if success:
            print(f"\n✅ Snapshot '{snapshot_name}' deleted successfully!")
        else:
            print(f"\n❌ Failed to delete snapshot '{snapshot_name}'")
        
        return success
    
    def cmd_rollback_snapshot(self, args: List[str], skip_confirmation: bool = False) -> bool:
        """Handle command line snapshot rollback."""
        if len(args) != 2:
            print("❌ Usage: python3 pve_snapshot_manager_api.py rollback [vmid/vmname] [snapshot_name]")
            print("Example: python3 pve_snapshot_manager_api.py rollback 7201 pre-update-smtp01-20250609-1430")
            return False
        
        vm_identifier, snapshot_name = args
        
        # Resolve VM ID
        vm_id = self.find_vm_by_name_or_id(vm_identifier)
        if not vm_id:
            print(f"❌ VM '{vm_identifier}' not found")
            return False
        
        vm_info = self.get_vm_info(vm_id)
        if not vm_info:
            print(f"❌ Could not get VM information for {vm_id}")
            return False
        
        print(f"⏪ Rolling back VM {vm_id} to snapshot '{snapshot_name}'")
        print(f"VM: {vm_info['name']}")
        
        # Check if snapshot exists
        snapshots = self.get_snapshots(vm_id)
        available_snapshots = [s for s in snapshots if s.get('name') != 'current']
        target_snapshot = None
        
        for snapshot in available_snapshots:
            if snapshot.get('name') == snapshot_name:
                target_snapshot = snapshot
                break
        
        if not target_snapshot:
            print(f"❌ Snapshot '{snapshot_name}' not found")
            if available_snapshots:
                print("Available snapshots:")
                for snapshot in available_snapshots:
                    name = snapshot.get('name', 'Unknown')
                    desc = snapshot.get('description', 'No description')
                    snaptime = snapshot.get('snaptime', 0)
                    if snaptime:
                        created = datetime.fromtimestamp(snaptime).strftime('%Y-%m-%d %H:%M')
                    else:
                        created = 'Unknown'
                    print(f"  - {name}: {desc} (Created: {created})")
            else:
                print("No snapshots available for this VM")
            return False
        
        # Show current VM status
        is_running, status_display, _ = self.get_vm_status_detailed(vm_id)
        print(f"Current VM Status: {status_display}")
        
        # Show rollback warning
        print(f"\n⚠️  SNAPSHOT ROLLBACK WARNING")
        print("=" * 60)
        print("This operation will:")
        print(f"  • Revert VM {vm_id} to snapshot: {snapshot_name}")
        print("  • ALL changes made after this snapshot will be LOST")
        print("  • This action cannot be undone!")
        if is_running:
            print("  • VM is currently running and will be stopped during rollback")
        print("=" * 60)
        
        # Show snapshot details
        desc = target_snapshot.get('description', 'No description')
        snaptime = target_snapshot.get('snaptime', 0)
        if snaptime:
            created = datetime.fromtimestamp(snaptime).strftime('%Y-%m-%d %H:%M:%S')
        else:
            created = 'Unknown'
        
        print(f"\nSnapshot Details:")
        print(f"  Name: {snapshot_name}")
        print(f"  Description: {desc}")
        print(f"  Created: {created}")
        
        # Confirm operation
        if skip_confirmation:
            print("\n✅ Proceeding with rollback (--yes flag provided)")
        else:
            confirm = input(f"\nType 'ROLLBACK' to confirm this dangerous operation: ").strip()
            if confirm != 'ROLLBACK':
                print("Operation cancelled")
                return False
        
        # Perform rollback
        success = self.rollback_snapshot(vm_id, snapshot_name)
        if success:
            print(f"\n✅ Rollback to '{snapshot_name}' completed successfully!")
            
            # Show new VM status
            print("\n📊 VM Status After Rollback:")
            new_is_running, new_status_display, _ = self.get_vm_status_detailed(vm_id)
            print(f"  Status: {new_status_display}")
        else:
            print(f"\n❌ Rollback to '{snapshot_name}' failed!")
        
        return success
    
    def cmd_list_snapshots(self, args: List[str]) -> bool:
        """Handle command line snapshot listing."""
        if len(args) != 1:
            print("❌ Usage: python3 pve_snapshot_manager_api.py list [vmid/vmname]")
            print("Example: python3 pve_snapshot_manager_api.py list 7201")
            return False
        
        vm_identifier = args[0]
        
        # Resolve VM ID
        vm_id = self.find_vm_by_name_or_id(vm_identifier)
        if not vm_id:
            print(f"❌ VM '{vm_identifier}' not found")
            return False
        
        # List snapshots
        self.list_snapshots(vm_id)
        return True
    
    def handle_command_line(self, args: List[str]) -> bool:
        """Handle command line arguments using argparse."""
        parser = argparse.ArgumentParser(
            prog='pve_snapshot_manager.py',
            description='Proxmox VM Snapshot Management Tool',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  %(prog)s create --vmid 100 --prefix backup
  %(prog)s create --vmname web-server --snapshot_name backup-20250101 --vmstate 1
  %(prog)s list --vmid 100
  %(prog)s list --vmname web-server database-server
  %(prog)s rollback --vmid 100 --snapshot_name backup-20250101-1200
  %(prog)s rollback --vmname web-server database-server --snapshot_name backup-20250101-1200
  %(prog)s delete --vmname web-server --snapshot_name backup-20250101-1200
            '''
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Create subcommand
        create_parser = subparsers.add_parser('create', help='Create VM snapshots')
        create_group = create_parser.add_mutually_exclusive_group(required=True)
        create_group.add_argument('--vmid', nargs='+', type=int, help='VM ID(s)')
        create_group.add_argument('--vmname', nargs='+', help='VM name(s)')
        create_parser.add_argument('--prefix', default='snapshot', help='Snapshot prefix (default: snapshot)')
        create_parser.add_argument('--snapshot_name', help='Full snapshot name (max 40 chars)')
        create_parser.add_argument('--vmstate', type=int, choices=[0, 1], default=0, 
                                 help='Include VM state: 0=no vmstate (default), 1=with vmstate')
        create_parser.add_argument('--yes', action='store_true', 
                                 help='Skip confirmation prompt')
        
        # List subcommand
        list_parser = subparsers.add_parser('list', help='List VM snapshots')
        list_group = list_parser.add_mutually_exclusive_group(required=True)
        list_group.add_argument('--vmid', nargs='+', type=int, help='VM ID(s)')
        list_group.add_argument('--vmname', nargs='+', help='VM name(s)')
        
        # Rollback subcommand
        rollback_parser = subparsers.add_parser('rollback', help='Rollback VM(s) to snapshot')
        rollback_group = rollback_parser.add_mutually_exclusive_group(required=True)
        rollback_group.add_argument('--vmid', nargs='+', type=int, help='VM ID(s)')
        rollback_group.add_argument('--vmname', nargs='+', help='VM name(s)')
        rollback_parser.add_argument('--snapshot_name', required=True, help='Snapshot name to rollback to')
        rollback_parser.add_argument('--yes', action='store_true', 
                                   help='Skip confirmation prompt')
        
        # Delete subcommand
        delete_parser = subparsers.add_parser('delete', help='Delete VM snapshot(s)')
        delete_group = delete_parser.add_mutually_exclusive_group(required=True)
        delete_group.add_argument('--vmid', nargs='+', type=int, help='VM ID(s)')
        delete_group.add_argument('--vmname', nargs='+', help='VM name(s)')
        
        # Create mutually exclusive group for snapshot selection
        snapshot_group = delete_parser.add_mutually_exclusive_group(required=True)
        snapshot_group.add_argument('--snapshot_name', nargs='+', help='Snapshot name(s) to delete (space-separated)')
        snapshot_group.add_argument('--all', action='store_true', help='Delete all snapshots for the VM(s)')
        
        delete_parser.add_argument('--yes', action='store_true', 
                                 help='Skip confirmation prompt')
        
        try:
            parsed_args = parser.parse_args(args)
        except SystemExit:
            return False
        
        if not parsed_args.command:
            parser.print_help()
            return False
        
        # Execute the appropriate command based on parsed arguments
        if parsed_args.command == 'create':
            return self.cmd_create_snapshots_new(parsed_args)
        elif parsed_args.command == 'list':
            return self.cmd_list_snapshots_new(parsed_args)
        elif parsed_args.command == 'rollback':
            return self.cmd_rollback_snapshot_new(parsed_args)
        elif parsed_args.command == 'delete':
            return self.cmd_delete_snapshot_new(parsed_args)
        else:
            parser.print_help()
            return False

    def cmd_create_snapshots_new(self, args) -> bool:
        """Create snapshots using new argument structure."""
        try:
            # Determine VM target(s)
            vm_targets = []
            if args.vmid:
                vm_targets = [str(vmid) for vmid in args.vmid]
            elif args.vmname:
                vm_targets = args.vmname
            
            # Validate snapshot name length if provided
            if args.snapshot_name and len(args.snapshot_name) > 40:
                print("❌ Error: Snapshot name cannot exceed 40 characters")
                return False
            
            # Prepare options for legacy method
            legacy_args = []
            
            # Add vmstate option
            if args.vmstate == 1:
                legacy_args.append('--with-vmstate')
            else:
                legacy_args.append('--no-vmstate')
            
            # Add prefix or snapshot name
            if args.snapshot_name:
                legacy_args.append(args.snapshot_name)
            else:
                legacy_args.append(args.prefix)
            
            # Add VM targets
            legacy_args.extend(vm_targets)
            
            # Call the existing create method with yes flag and exact name flag
            return self.cmd_create_snapshots(legacy_args, skip_confirmation=args.yes, use_exact_name=bool(args.snapshot_name))
            
        except Exception as e:
            print(f"❌ Error creating snapshots: {e}")
            return False
    
    def cmd_list_snapshots_new(self, args) -> bool:
        """List snapshots using new argument structure."""
        try:
            # Determine VM target(s)
            vm_targets = []
            if args.vmid:
                vm_targets = [str(vmid) for vmid in args.vmid]
            elif args.vmname:
                vm_targets = args.vmname
            
            # Process each VM target
            success = True
            for vm_target in vm_targets:
                if not self.cmd_list_snapshots([vm_target]):
                    success = False
            
            return success
            
        except Exception as e:
            print(f"❌ Error listing snapshots: {e}")
            return False
    
    def cmd_rollback_multiple_vms(self, vm_targets: List[str], snapshot_name: str, skip_confirmation: bool = False) -> bool:
        """Handle rollback for multiple VMs to the same snapshot."""
        print(f"⏪ Rolling back {len(vm_targets)} VM(s) to snapshot '{snapshot_name}'")
        print("=" * 60)
        
        # Resolve all VM IDs and validate
        vm_info_list = []
        for vm_target in vm_targets:
            vm_id = self.find_vm_by_name_or_id(vm_target)
            if not vm_id:
                print(f"❌ VM '{vm_target}' not found")
                return False
            
            vm_info = self.get_vm_info(vm_id)
            if not vm_info:
                print(f"❌ Could not get VM information for {vm_id}")
                return False
            
            # Check if snapshot exists
            snapshots = self.get_snapshots(vm_id)
            available_snapshots = [s for s in snapshots if s.get('name') != 'current']
            target_snapshot = None
            
            for snapshot in available_snapshots:
                if snapshot.get('name') == snapshot_name:
                    target_snapshot = snapshot
                    break
            
            if not target_snapshot:
                print(f"❌ Snapshot '{snapshot_name}' not found for VM {vm_id} ({vm_info['name']})")
                if available_snapshots:
                    print(f"Available snapshots for VM {vm_id}:")
                    for snapshot in available_snapshots:
                        name = snapshot.get('name', 'Unknown')
                        desc = snapshot.get('description', 'No description')
                        print(f"  - {name}: {desc}")
                return False
            
            vm_info_list.append({
                'vm_id': vm_id,
                'vm_info': vm_info,
                'target_snapshot': target_snapshot
            })
        
        # Display VMs to be rolled back
        print(f"VMs to rollback:")
        for vm_data in vm_info_list:
            vm_id = vm_data['vm_id']
            vm_info = vm_data['vm_info']
            is_running, status_display, _ = self.get_vm_status_detailed(vm_id)
            print(f"  • VM {vm_id}: {vm_info['name']} (Status: {status_display})")
        
        # Show rollback warning
        print(f"\n⚠️  BULK SNAPSHOT ROLLBACK WARNING")
        print("=" * 60)
        print("This operation will:")
        print(f"  • Revert {len(vm_info_list)} VM(s) to snapshot: {snapshot_name}")
        print("  • ALL changes made after this snapshot will be LOST")
        print("  • This action cannot be undone!")
        print("  • Running VMs will be stopped during rollback")
        print("=" * 60)
        
        # Show snapshot details (from first VM)
        target_snapshot = vm_info_list[0]['target_snapshot']
        desc = target_snapshot.get('description', 'No description')
        snaptime = target_snapshot.get('snaptime', 0)
        if snaptime:
            created = datetime.fromtimestamp(snaptime).strftime('%Y-%m-%d %H:%M:%S')
        else:
            created = 'Unknown'
        
        print(f"\nSnapshot Details:")
        print(f"  Name: {snapshot_name}")
        print(f"  Description: {desc}")
        print(f"  Created: {created}")
        
        # Confirm operation
        if skip_confirmation:
            print("\n✅ Proceeding with bulk rollback (--yes flag provided)")
        else:
            confirm = input(f"\nType 'ROLLBACK' to confirm this dangerous operation for {len(vm_info_list)} VM(s): ").strip()
            if confirm != 'ROLLBACK':
                print("Operation cancelled")
                return False
        
        # Perform rollbacks
        success_count = 0
        failed_vms = []
        
        for vm_data in vm_info_list:
            vm_id = vm_data['vm_id']
            vm_info = vm_data['vm_info']
            
            print(f"\n⏪ Rolling back VM {vm_id} ({vm_info['name']}) to '{snapshot_name}'...")
            success = self.rollback_snapshot(vm_id, snapshot_name)
            
            if success:
                print(f"✅ VM {vm_id} rollback completed successfully!")
                success_count += 1
            else:
                print(f"❌ VM {vm_id} rollback failed!")
                failed_vms.append(f"{vm_id} ({vm_info['name']})")
        
        # Summary
        print(f"\n📊 Rollback Summary:")
        print(f"  ✅ Successfully rolled back: {success_count}/{len(vm_info_list)} VMs")
        if failed_vms:
            print(f"  ❌ Failed to rollback: {', '.join(failed_vms)}")
        
        return len(failed_vms) == 0

    def cmd_rollback_snapshot_new(self, args) -> bool:
        """Rollback snapshot using new argument structure."""
        try:
            # Determine VM target(s)
            vm_targets = []
            if args.vmid:
                vm_targets = [str(vmid) for vmid in args.vmid]
            elif args.vmname:
                vm_targets = args.vmname
            
            # Handle multiple VMs
            if len(vm_targets) == 1:
                # Single VM - use existing method
                return self.cmd_rollback_snapshot([vm_targets[0], args.snapshot_name], skip_confirmation=args.yes)
            else:
                # Multiple VMs - use bulk rollback logic
                return self.cmd_rollback_multiple_vms(vm_targets, args.snapshot_name, skip_confirmation=args.yes)
            
        except Exception as e:
            print(f"❌ Error rolling back snapshot: {e}")
            return False
    
    def cmd_delete_multiple_snapshots(self, vm_identifier: str, snapshot_names: List[str], skip_confirmation: bool = False) -> bool:
        """Handle deletion of multiple snapshots for a single VM."""
        # Resolve VM ID
        vm_id = self.find_vm_by_name_or_id(vm_identifier)
        if not vm_id:
            print(f"❌ VM '{vm_identifier}' not found")
            return False

        vm_info = self.get_vm_info(vm_id)
        if not vm_info:
            print(f"❌ Could not get VM information for {vm_id}")
            return False

        print(f"🗑️  Deleting {len(snapshot_names)} snapshots from VM {vm_id}")
        print(f"VM: {vm_info['name']}")
        print(f"Snapshots: {', '.join(snapshot_names)}")

        # Check if all snapshots exist
        snapshots = self.get_snapshots(vm_id)
        available_snapshots = [s for s in snapshots if s.get('name') != 'current']
        available_names = [s.get('name') for s in available_snapshots]
        
        missing_snapshots = [name for name in snapshot_names if name not in available_names]
        if missing_snapshots:
            print(f"❌ The following snapshots were not found: {', '.join(missing_snapshots)}")
            if available_snapshots:
                print("Available snapshots:")
                for snapshot in available_snapshots:
                    name = snapshot.get('name', 'Unknown')
                    desc = snapshot.get('description', 'No description')
                    print(f"  - {name}: {desc}")
            return False

        # Show deletion warning
        print(f"\n⚠️  MULTIPLE SNAPSHOT DELETION WARNING")
        print("=" * 60)
        print("This operation will:")
        for snapshot_name in snapshot_names:
            print(f"  • Permanently delete snapshot: {snapshot_name}")
        print("  • Free up disk space used by these snapshots")
        print("  • This action cannot be undone!")
        print("=" * 60)

        # Confirm operation
        if skip_confirmation:
            print(f"\n✅ Proceeding with snapshot deletion (--yes flag provided)")
        else:
            confirm = input(f"\nDelete {len(snapshot_names)} snapshots? (yes/N): ").strip().lower()
            if confirm != 'yes':
                print("Operation cancelled")
                return False

        # Delete snapshots one by one
        success_count = 0
        failed_snapshots = []
        
        for snapshot_name in snapshot_names:
            print(f"\n🗑️  Deleting snapshot '{snapshot_name}'...")
            success = self.delete_snapshot(vm_id, snapshot_name)
            if success:
                print(f"✅ Snapshot '{snapshot_name}' deleted successfully!")
                success_count += 1
            else:
                print(f"❌ Failed to delete snapshot '{snapshot_name}'")
                failed_snapshots.append(snapshot_name)

        # Summary
        print(f"\n📊 Deletion Summary:")
        print(f"  ✅ Successfully deleted: {success_count}/{len(snapshot_names)} snapshots")
        if failed_snapshots:
            print(f"  ❌ Failed to delete: {', '.join(failed_snapshots)}")

        return len(failed_snapshots) == 0
    
    def cmd_delete_all_snapshots(self, vm_identifier: str, skip_confirmation: bool = False) -> bool:
        """Handle deletion of all snapshots for a single VM."""
        # Resolve VM ID
        vm_id = self.find_vm_by_name_or_id(vm_identifier)
        if not vm_id:
            print(f"❌ VM '{vm_identifier}' not found")
            return False

        vm_info = self.get_vm_info(vm_id)
        if not vm_info:
            print(f"❌ Could not get VM information for {vm_id}")
            return False

        # Get all snapshots (excluding 'current')
        snapshots = self.get_snapshots(vm_id)
        available_snapshots = [s for s in snapshots if s.get('name') != 'current']
        
        if not available_snapshots:
            print(f"ℹ️  No snapshots found for VM {vm_id} ({vm_info['name']})")
            return True

        snapshot_names = [s.get('name') for s in available_snapshots]
        
        print(f"🗑️  Deleting ALL {len(snapshot_names)} snapshots from VM {vm_id}")
        print(f"VM: {vm_info['name']}")
        print(f"Snapshots: {', '.join(snapshot_names)}")

        # Show deletion warning
        print(f"\n⚠️  DELETE ALL SNAPSHOTS WARNING")
        print("=" * 60)
        print("This operation will:")
        print(f"  • Permanently delete ALL {len(snapshot_names)} snapshots")
        print("  • Free up significant disk space")
        print("  • This action cannot be undone!")
        print("=" * 60)

        # Confirm operation
        if skip_confirmation:
            print(f"\n✅ Proceeding with all snapshots deletion (--yes flag provided)")
        else:
            confirm = input(f"\nDelete ALL {len(snapshot_names)} snapshots? (yes/N): ").strip().lower()
            if confirm != 'yes':
                print("Operation cancelled")
                return False

        # Delete snapshots one by one
        success_count = 0
        failed_snapshots = []
        
        for snapshot_name in snapshot_names:
            print(f"\n🗑️  Deleting snapshot '{snapshot_name}'...")
            success = self.delete_snapshot(vm_id, snapshot_name)
            if success:
                print(f"✅ Snapshot '{snapshot_name}' deleted successfully!")
                success_count += 1
            else:
                print(f"❌ Failed to delete snapshot '{snapshot_name}'")
                failed_snapshots.append(snapshot_name)

        # Summary
        print(f"\n📊 Deletion Summary:")
        print(f"  ✅ Successfully deleted: {success_count}/{len(snapshot_names)} snapshots")
        if failed_snapshots:
            print(f"  ❌ Failed to delete: {', '.join(failed_snapshots)}")

        return len(failed_snapshots) == 0

    def cmd_delete_multiple_vms(self, vm_targets: List[str], snapshot_names: List[str], skip_confirmation: bool = False) -> bool:
        """Handle deletion of specific snapshots for multiple VMs."""
        print(f"🗑️  Deleting snapshot(s) '{', '.join(snapshot_names)}' from {len(vm_targets)} VM(s)")
        print("=" * 60)
        
        # Resolve all VM IDs and validate snapshots exist
        vm_info_list = []
        for vm_target in vm_targets:
            vm_id = self.find_vm_by_name_or_id(vm_target)
            if not vm_id:
                print(f"❌ VM '{vm_target}' not found")
                return False
            
            vm_info = self.get_vm_info(vm_id)
            if not vm_info:
                print(f"❌ Could not get VM information for {vm_id}")
                return False
            
            # Check if all snapshots exist for this VM
            snapshots = self.get_snapshots(vm_id)
            available_snapshots = [s for s in snapshots if s.get('name') != 'current']
            available_snapshot_names = [s.get('name') for s in available_snapshots]
            
            missing_snapshots = []
            for snapshot_name in snapshot_names:
                if snapshot_name not in available_snapshot_names:
                    missing_snapshots.append(snapshot_name)
            
            if missing_snapshots:
                print(f"❌ The following snapshots were not found for VM {vm_id} ({vm_info['name']}): {', '.join(missing_snapshots)}")
                if available_snapshots:
                    print(f"Available snapshots for VM {vm_id}:")
                    for snapshot in available_snapshots:
                        name = snapshot.get('name', 'Unknown')
                        desc = snapshot.get('description', 'No description')
                        print(f"  - {name}: {desc}")
                return False
            
            vm_info_list.append({
                'vm_id': vm_id,
                'vm_info': vm_info,
                'snapshots_to_delete': snapshot_names
            })
        
        # Display VMs and snapshots to be deleted
        print(f"VMs and snapshots to delete:")
        for vm_data in vm_info_list:
            vm_id = vm_data['vm_id']
            vm_info = vm_data['vm_info']
            print(f"  • VM {vm_id}: {vm_info['name']} → {', '.join(snapshot_names)}")
        
        # Show deletion warning
        total_deletions = len(vm_info_list) * len(snapshot_names)
        print(f"\n⚠️  BULK SNAPSHOT DELETION WARNING")
        print("=" * 60)
        print("This operation will:")
        print(f"  • Permanently delete {len(snapshot_names)} snapshot(s) from {len(vm_info_list)} VM(s)")
        print(f"  • Total deletions: {total_deletions} snapshots")
        print("  • Free up disk space used by these snapshots")
        print("  • This action cannot be undone!")
        print("=" * 60)
        
        # Confirm operation
        if skip_confirmation:
            print(f"\n✅ Proceeding with bulk snapshot deletion (--yes flag provided)")
        else:
            confirm = input(f"\nDelete {total_deletions} snapshots from {len(vm_info_list)} VM(s)? (yes/N): ").strip().lower()
            if confirm != 'yes':
                print("Operation cancelled")
                return False
        
        # Perform deletions
        total_success = 0
        total_failed = 0
        failed_deletions = []
        
        for vm_data in vm_info_list:
            vm_id = vm_data['vm_id']
            vm_info = vm_data['vm_info']
            
            print(f"\n🗑️  Processing VM {vm_id} ({vm_info['name']})...")
            
            for snapshot_name in snapshot_names:
                print(f"  Deleting snapshot '{snapshot_name}'...")
                success = self.delete_snapshot(vm_id, snapshot_name)
                
                if success:
                    print(f"  ✅ Snapshot '{snapshot_name}' deleted successfully!")
                    total_success += 1
                else:
                    print(f"  ❌ Failed to delete snapshot '{snapshot_name}'")
                    total_failed += 1
                    failed_deletions.append(f"VM {vm_id}: {snapshot_name}")
        
        # Summary
        print(f"\n📊 Bulk Deletion Summary:")
        print(f"  ✅ Successfully deleted: {total_success}/{total_deletions} snapshots")
        if failed_deletions:
            print(f"  ❌ Failed deletions:")
            for failure in failed_deletions:
                print(f"    - {failure}")
        
        return total_failed == 0
    
    def cmd_delete_all_snapshots_multiple_vms(self, vm_targets: List[str], skip_confirmation: bool = False) -> bool:
        """Handle deletion of all snapshots for multiple VMs."""
        print(f"🗑️  Deleting ALL snapshots from {len(vm_targets)} VM(s)")
        print("=" * 60)
        
        # Resolve all VM IDs and get snapshot counts
        vm_info_list = []
        total_snapshots = 0
        
        for vm_target in vm_targets:
            vm_id = self.find_vm_by_name_or_id(vm_target)
            if not vm_id:
                print(f"❌ VM '{vm_target}' not found")
                return False
            
            vm_info = self.get_vm_info(vm_id)
            if not vm_info:
                print(f"❌ Could not get VM information for {vm_id}")
                return False
            
            # Get all snapshots (excluding 'current')
            snapshots = self.get_snapshots(vm_id)
            available_snapshots = [s for s in snapshots if s.get('name') != 'current']
            snapshot_names = [s.get('name') for s in available_snapshots]
            
            vm_info_list.append({
                'vm_id': vm_id,
                'vm_info': vm_info,
                'snapshot_names': snapshot_names,
                'snapshot_count': len(snapshot_names)
            })
            
            total_snapshots += len(snapshot_names)
        
        if total_snapshots == 0:
            print(f"ℹ️  No snapshots found across all specified VMs")
            return True
        
        # Display VMs and snapshot counts
        print(f"VMs and snapshot counts:")
        for vm_data in vm_info_list:
            vm_id = vm_data['vm_id']
            vm_info = vm_data['vm_info']
            count = vm_data['snapshot_count']
            if count > 0:
                print(f"  • VM {vm_id}: {vm_info['name']} → {count} snapshots")
            else:
                print(f"  • VM {vm_id}: {vm_info['name']} → No snapshots")
        
        # Show deletion warning
        print(f"\n⚠️  DELETE ALL SNAPSHOTS WARNING")
        print("=" * 60)
        print("This operation will:")
        print(f"  • Permanently delete ALL {total_snapshots} snapshots from {len(vm_info_list)} VM(s)")
        print("  • Free up significant disk space")
        print("  • This action cannot be undone!")
        print("=" * 60)
        
        # Confirm operation
        if skip_confirmation:
            print(f"\n✅ Proceeding with bulk deletion of all snapshots (--yes flag provided)")
        else:
            confirm = input(f"\nDelete ALL {total_snapshots} snapshots from {len(vm_info_list)} VM(s)? (yes/N): ").strip().lower()
            if confirm != 'yes':
                print("Operation cancelled")
                return False
        
        # Perform deletions
        total_success = 0
        total_failed = 0
        failed_deletions = []
        
        for vm_data in vm_info_list:
            vm_id = vm_data['vm_id']
            vm_info = vm_data['vm_info']
            snapshot_names = vm_data['snapshot_names']
            
            if not snapshot_names:
                print(f"\n⏭️  Skipping VM {vm_id} ({vm_info['name']}) - no snapshots")
                continue
            
            print(f"\n🗑️  Processing VM {vm_id} ({vm_info['name']}) - {len(snapshot_names)} snapshots...")
            
            for snapshot_name in snapshot_names:
                print(f"  Deleting snapshot '{snapshot_name}'...")
                success = self.delete_snapshot(vm_id, snapshot_name)
                
                if success:
                    print(f"  ✅ Snapshot '{snapshot_name}' deleted successfully!")
                    total_success += 1
                else:
                    print(f"  ❌ Failed to delete snapshot '{snapshot_name}'")
                    total_failed += 1
                    failed_deletions.append(f"VM {vm_id}: {snapshot_name}")
        
        # Summary
        print(f"\n📊 Bulk Deletion Summary:")
        print(f"  ✅ Successfully deleted: {total_success}/{total_snapshots} snapshots")
        if failed_deletions:
            print(f"  ❌ Failed deletions:")
            for failure in failed_deletions:
                print(f"    - {failure}")
        
        return total_failed == 0
    
    def cmd_delete_snapshot_new(self, args) -> bool:
        """Delete snapshot(s) using new argument structure."""
        try:
            # Determine VM target(s)
            vm_targets = []
            if args.vmid:
                vm_targets = [str(vmid) for vmid in args.vmid]
            elif args.vmname:
                vm_targets = args.vmname
            
            # Handle --all flag
            if args.all:
                if len(vm_targets) == 1:
                    return self.cmd_delete_all_snapshots(vm_targets[0], skip_confirmation=args.yes)
                else:
                    return self.cmd_delete_all_snapshots_multiple_vms(vm_targets, skip_confirmation=args.yes)
            
            # Handle multiple snapshot names
            if len(vm_targets) == 1:
                # Single VM
                if len(args.snapshot_name) == 1:
                    # Single snapshot - use existing method
                    return self.cmd_delete_snapshot([vm_targets[0], args.snapshot_name[0]], skip_confirmation=args.yes)
                else:
                    # Multiple snapshots - use bulk delete logic
                    return self.cmd_delete_multiple_snapshots(vm_targets[0], args.snapshot_name, skip_confirmation=args.yes)
            else:
                # Multiple VMs
                return self.cmd_delete_multiple_vms(vm_targets, args.snapshot_name, skip_confirmation=args.yes)
            
        except Exception as e:
            print(f"❌ Error deleting snapshot(s): {e}")
            return False


def main():
    """Main function to initialize and run the snapshot manager."""
    manager = ProxmoxSnapshotManager()
    
    # Check for help - handled by argparse in handle_command_line method
    
    # Check for command line mode
    if len(sys.argv) > 1:
        # Command line mode
        command_args = sys.argv[1:]
        
        # Connect to Proxmox API (silent mode for CLI)
        if not manager.connect_to_proxmox():
            print("❌ Failed to connect to Proxmox API")
            sys.exit(1)
        
        # Verify connection silently
        try:
            nodes = manager.get_nodes()
            if not nodes:
                print("❌ No nodes found or insufficient permissions")
                sys.exit(1)
        except Exception as e:
            print(f"❌ Error verifying connection: {e}")
            sys.exit(1)
        
        # Execute command
        success = manager.handle_command_line(command_args)
        sys.exit(0 if success else 1)
    
    # Interactive mode
    # Connect to Proxmox API (verbose mode for interactive)
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
