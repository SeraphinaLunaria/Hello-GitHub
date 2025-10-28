#!/usr/bin/env python3
"""
IP Blocklist Manager
A tool to manage blocked IP addresses for security purposes
"""

import ipaddress
import json
import os
from datetime import datetime
from typing import Set, List, Dict


class IPBlocklistManager:
    """Manage a blocklist of IP addresses"""

    def __init__(self, filename: str = "blocklist.json"):
        self.filename = filename
        self.blocked_ips: Set[str] = set()
        self.blocked_networks: List[ipaddress.IPv4Network] = []
        self.metadata: Dict[str, Dict] = {}
        self.load()

    def add_ip(self, ip: str, reason: str = "Unknown") -> bool:
        """
        Add an IP address to the blocklist

        Args:
            ip: IP address to block
            reason: Reason for blocking

        Returns:
            bool: True if added successfully
        """
        try:
            # Validate IP address
            ip_obj = ipaddress.ip_address(ip)

            if ip in self.blocked_ips:
                print(f"IP {ip} is already blocked")
                return False

            self.blocked_ips.add(ip)
            self.metadata[ip] = {
                'reason': reason,
                'added': datetime.now().isoformat(),
                'type': 'ip'
            }

            print(f"✓ Added {ip} to blocklist")
            return True

        except ValueError as e:
            print(f"✗ Invalid IP address: {e}")
            return False

    def add_network(self, network: str, reason: str = "Unknown") -> bool:
        """
        Add a network range to the blocklist

        Args:
            network: Network in CIDR notation (e.g., 192.168.1.0/24)
            reason: Reason for blocking

        Returns:
            bool: True if added successfully
        """
        try:
            # Validate network
            net_obj = ipaddress.IPv4Network(network, strict=False)

            # Check if already exists
            for existing in self.blocked_networks:
                if existing == net_obj:
                    print(f"Network {network} is already blocked")
                    return False

            self.blocked_networks.append(net_obj)
            self.metadata[str(net_obj)] = {
                'reason': reason,
                'added': datetime.now().isoformat(),
                'type': 'network'
            }

            print(f"✓ Added network {net_obj} to blocklist")
            return True

        except ValueError as e:
            print(f"✗ Invalid network: {e}")
            return False

    def remove_ip(self, ip: str) -> bool:
        """Remove an IP from the blocklist"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            if ip in self.metadata:
                del self.metadata[ip]
            print(f"✓ Removed {ip} from blocklist")
            return True
        else:
            print(f"✗ IP {ip} not found in blocklist")
            return False

    def remove_network(self, network: str) -> bool:
        """Remove a network from the blocklist"""
        try:
            net_obj = ipaddress.IPv4Network(network, strict=False)

            for existing in self.blocked_networks:
                if existing == net_obj:
                    self.blocked_networks.remove(existing)
                    if str(net_obj) in self.metadata:
                        del self.metadata[str(net_obj)]
                    print(f"✓ Removed network {net_obj} from blocklist")
                    return True

            print(f"✗ Network {network} not found in blocklist")
            return False

        except ValueError as e:
            print(f"✗ Invalid network: {e}")
            return False

    def is_blocked(self, ip: str) -> bool:
        """
        Check if an IP is blocked

        Args:
            ip: IP address to check

        Returns:
            bool: True if blocked
        """
        try:
            ip_obj = ipaddress.ip_address(ip)

            # Check exact match
            if ip in self.blocked_ips:
                return True

            # Check if in blocked network
            for network in self.blocked_networks:
                if ip_obj in network:
                    return True

            return False

        except ValueError:
            return False

    def list_blocked(self):
        """Display all blocked IPs and networks"""
        print("\n" + "="*60)
        print("BLOCKLIST")
        print("="*60)

        if not self.blocked_ips and not self.blocked_networks:
            print("\nNo blocked IPs or networks")
            return

        print(f"\n--- Blocked IPs ({len(self.blocked_ips)}) ---")
        for ip in sorted(self.blocked_ips):
            info = self.metadata.get(ip, {})
            reason = info.get('reason', 'Unknown')
            added = info.get('added', 'Unknown')
            print(f"  {ip:15s} - {reason} (Added: {added[:10]})")

        print(f"\n--- Blocked Networks ({len(self.blocked_networks)}) ---")
        for network in sorted(self.blocked_networks):
            info = self.metadata.get(str(network), {})
            reason = info.get('reason', 'Unknown')
            added = info.get('added', 'Unknown')
            print(f"  {str(network):18s} - {reason} (Added: {added[:10]})")

        print("\n" + "="*60)

    def save(self):
        """Save blocklist to file"""
        data = {
            'ips': list(self.blocked_ips),
            'networks': [str(net) for net in self.blocked_networks],
            'metadata': self.metadata,
            'last_updated': datetime.now().isoformat()
        }

        try:
            with open(self.filename, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"✓ Blocklist saved to {self.filename}")
        except Exception as e:
            print(f"✗ Error saving blocklist: {e}")

    def load(self):
        """Load blocklist from file"""
        if not os.path.exists(self.filename):
            print(f"No existing blocklist found. Starting fresh.")
            return

        try:
            with open(self.filename, 'r') as f:
                data = json.load(f)

            self.blocked_ips = set(data.get('ips', []))
            self.blocked_networks = [
                ipaddress.IPv4Network(net)
                for net in data.get('networks', [])
            ]
            self.metadata = data.get('metadata', {})

            print(f"✓ Loaded blocklist from {self.filename}")
            print(f"  IPs: {len(self.blocked_ips)}, Networks: {len(self.blocked_networks)}")

        except Exception as e:
            print(f"✗ Error loading blocklist: {e}")

    def stats(self):
        """Display statistics"""
        print("\n" + "="*60)
        print("BLOCKLIST STATISTICS")
        print("="*60)

        total_ips = len(self.blocked_ips)
        total_networks = len(self.blocked_networks)

        # Calculate total blocked IPs (including networks)
        blocked_from_networks = sum(net.num_addresses for net in self.blocked_networks)

        print(f"\nIndividual IPs: {total_ips}")
        print(f"Network Ranges: {total_networks}")
        print(f"Total Blocked IPs: {total_ips + blocked_from_networks}")

        # Reasons breakdown
        reasons = {}
        for info in self.metadata.values():
            reason = info.get('reason', 'Unknown')
            reasons[reason] = reasons.get(reason, 0) + 1

        print("\n--- Block Reasons ---")
        for reason, count in sorted(reasons.items(), key=lambda x: x[1], reverse=True):
            print(f"  {reason:20s}: {count}")

        print("\n" + "="*60)


def main():
    """Main function"""
    manager = IPBlocklistManager()

    print("\n" + "="*60)
    print("IP BLOCKLIST MANAGER")
    print("="*60)

    while True:
        print("\nOptions:")
        print("  1. Add IP")
        print("  2. Add Network")
        print("  3. Remove IP")
        print("  4. Remove Network")
        print("  5. Check IP")
        print("  6. List All")
        print("  7. Statistics")
        print("  8. Save")
        print("  9. Quit")

        choice = input("\nSelect option: ").strip()

        if choice == '1':
            ip = input("Enter IP address: ").strip()
            reason = input("Reason for blocking: ").strip()
            manager.add_ip(ip, reason or "Manual block")

        elif choice == '2':
            network = input("Enter network (CIDR notation, e.g., 192.168.1.0/24): ").strip()
            reason = input("Reason for blocking: ").strip()
            manager.add_network(network, reason or "Manual block")

        elif choice == '3':
            ip = input("Enter IP address to remove: ").strip()
            manager.remove_ip(ip)

        elif choice == '4':
            network = input("Enter network to remove: ").strip()
            manager.remove_network(network)

        elif choice == '5':
            ip = input("Enter IP address to check: ").strip()
            if manager.is_blocked(ip):
                print(f"✗ IP {ip} is BLOCKED")
            else:
                print(f"✓ IP {ip} is NOT blocked")

        elif choice == '6':
            manager.list_blocked()

        elif choice == '7':
            manager.stats()

        elif choice == '8':
            manager.save()

        elif choice == '9':
            print("Save before quitting? (y/n): ", end='')
            if input().strip().lower() == 'y':
                manager.save()
            print("\nGoodbye!")
            break

        else:
            print("Invalid option")


if __name__ == "__main__":
    main()
