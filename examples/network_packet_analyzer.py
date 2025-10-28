#!/usr/bin/env python3
"""
Network Packet Analyzer
Analyze network packets for security monitoring (requires root/admin privileges)
Educational tool for understanding network traffic
"""

import socket
import struct
import textwrap
from datetime import datetime


class PacketAnalyzer:
    """Analyze network packets for security purposes"""

    def __init__(self):
        self.packet_count = 0
        self.protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        self.suspicious_ports = {21, 23, 3389, 445}  # FTP, Telnet, RDP, SMB
        self.alerts = []

    def create_socket(self):
        """
        Create raw socket for packet capture
        Note: Requires root/admin privileges
        """
        try:
            # Create raw socket
            # For Linux
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            return sock
        except PermissionError:
            print("Error: Root/admin privileges required for packet capture")
            return None
        except AttributeError:
            # For Windows
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostname(), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                return sock
            except Exception as e:
                print(f"Error creating socket: {e}")
                return None

    def parse_ethernet_frame(self, data):
        """Parse Ethernet frame"""
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.format_mac(dest_mac), self.format_mac(src_mac), socket.htons(proto), data[14:]

    def format_mac(self, mac_bytes):
        """Format MAC address"""
        return ':'.join(map('{:02x}'.format, mac_bytes))

    def parse_ipv4_header(self, data):
        """Parse IPv4 header"""
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, self.format_ipv4(src), self.format_ipv4(target), data[header_length:]

    def format_ipv4(self, addr):
        """Format IPv4 address"""
        return '.'.join(map(str, addr))

    def parse_tcp_segment(self, data):
        """Parse TCP segment"""
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1

        return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

    def parse_udp_segment(self, data):
        """Parse UDP segment"""
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[8:]

    def check_suspicious_activity(self, protocol, src_ip, dest_ip, src_port=None, dest_port=None, flags=None):
        """Check for suspicious network activity"""
        alerts = []

        # Check for suspicious ports
        if dest_port and dest_port in self.suspicious_ports:
            alerts.append(f"⚠️ Connection to suspicious port {dest_port}")

        # Check for SYN flood (SYN without ACK)
        if flags and flags['syn'] and not flags['ack']:
            alerts.append(f"⚠️ Potential SYN scan detected")

        # Check for NULL scan
        if flags and not any(flags.values()):
            alerts.append(f"⚠️ Potential NULL scan detected")

        # Check for XMAS scan
        if flags and flags['fin'] and flags['psh'] and flags['urg']:
            alerts.append(f"⚠️ Potential XMAS scan detected")

        return alerts

    def analyze_packet(self, data):
        """Analyze a single packet"""
        self.packet_count += 1

        try:
            # Parse Ethernet frame
            dest_mac, src_mac, eth_proto, eth_data = self.parse_ethernet_frame(data)

            # Check if it's an IP packet (0x0800)
            if eth_proto == 8:
                # Parse IPv4
                version, header_length, ttl, proto, src_ip, dest_ip, ip_data = self.parse_ipv4_header(eth_data)

                protocol_name = self.protocols.get(proto, f'Other ({proto})')

                packet_info = {
                    'number': self.packet_count,
                    'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                    'src_mac': src_mac,
                    'dest_mac': dest_mac,
                    'src_ip': src_ip,
                    'dest_ip': dest_ip,
                    'protocol': protocol_name,
                    'ttl': ttl
                }

                # TCP
                if proto == 6:
                    src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, tcp_data = self.parse_tcp_segment(ip_data)

                    packet_info['src_port'] = src_port
                    packet_info['dest_port'] = dest_port
                    packet_info['flags'] = {
                        'syn': flag_syn,
                        'ack': flag_ack,
                        'fin': flag_fin,
                        'rst': flag_rst,
                        'psh': flag_psh,
                        'urg': flag_urg
                    }

                    # Check for suspicious activity
                    alerts = self.check_suspicious_activity(
                        proto, src_ip, dest_ip, src_port, dest_port, packet_info['flags']
                    )

                    if alerts:
                        packet_info['alerts'] = alerts
                        self.alerts.extend(alerts)

                # UDP
                elif proto == 17:
                    src_port, dest_port, size, udp_data = self.parse_udp_segment(ip_data)
                    packet_info['src_port'] = src_port
                    packet_info['dest_port'] = dest_port
                    packet_info['size'] = size

                    # Check for suspicious activity
                    alerts = self.check_suspicious_activity(proto, src_ip, dest_ip, src_port, dest_port)
                    if alerts:
                        packet_info['alerts'] = alerts
                        self.alerts.extend(alerts)

                return packet_info

        except Exception as e:
            print(f"Error parsing packet: {e}")
            return None

    def display_packet(self, packet_info):
        """Display packet information"""
        if not packet_info:
            return

        print(f"\n{'='*70}")
        print(f"Packet #{packet_info['number']} - {packet_info['timestamp']}")
        print(f"{'='*70}")

        print(f"\n[Ethernet Frame]")
        print(f"  Source MAC:      {packet_info['src_mac']}")
        print(f"  Destination MAC: {packet_info['dest_mac']}")

        print(f"\n[IPv4 Packet]")
        print(f"  Source IP:       {packet_info['src_ip']}")
        print(f"  Destination IP:  {packet_info['dest_ip']}")
        print(f"  Protocol:        {packet_info['protocol']}")
        print(f"  TTL:             {packet_info['ttl']}")

        if 'src_port' in packet_info:
            print(f"\n[{packet_info['protocol']} Segment]")
            print(f"  Source Port:     {packet_info['src_port']}")
            print(f"  Destination Port: {packet_info['dest_port']}")

            if 'flags' in packet_info:
                flags = packet_info['flags']
                flag_str = ', '.join([k.upper() for k, v in flags.items() if v])
                print(f"  Flags:           {flag_str if flag_str else 'None'}")

        if 'alerts' in packet_info:
            print(f"\n[SECURITY ALERTS]")
            for alert in packet_info['alerts']:
                print(f"  {alert}")

    def capture_packets(self, count=10):
        """
        Capture and analyze network packets

        Args:
            count: Number of packets to capture (0 for continuous)
        """
        sock = self.create_socket()
        if not sock:
            return

        print(f"\n{'='*70}")
        print("NETWORK PACKET ANALYZER")
        print(f"{'='*70}")
        print(f"\nStarted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Capturing {count if count > 0 else 'unlimited'} packets...")
        print("\nPress Ctrl+C to stop\n")

        try:
            packet_num = 0
            while count == 0 or packet_num < count:
                raw_data, addr = sock.recvfrom(65535)
                packet_info = self.analyze_packet(raw_data)

                # Display only packets with alerts or every 10th packet
                if packet_info and ('alerts' in packet_info or packet_num % 10 == 0):
                    self.display_packet(packet_info)
                elif packet_info:
                    # Just show a summary line for other packets
                    print(f"Packet #{packet_info['number']}: {packet_info['src_ip']}:{packet_info.get('src_port', 'N/A')} → "
                          f"{packet_info['dest_ip']}:{packet_info.get('dest_port', 'N/A')} [{packet_info['protocol']}]")

                packet_num += 1

        except KeyboardInterrupt:
            print("\n\nCapture stopped by user")
        finally:
            sock.close()
            self.display_summary()

    def display_summary(self):
        """Display capture summary"""
        print(f"\n{'='*70}")
        print("CAPTURE SUMMARY")
        print(f"{'='*70}")
        print(f"Total Packets Captured: {self.packet_count}")
        print(f"Security Alerts: {len(self.alerts)}")

        if self.alerts:
            print(f"\n[Alert Summary]")
            from collections import Counter
            alert_counts = Counter(self.alerts)
            for alert, count in alert_counts.most_common():
                print(f"  {alert}: {count} times")

        print(f"\n{'='*70}")


def main():
    """Main function"""
    import sys

    analyzer = PacketAnalyzer()

    print("="*70)
    print("NETWORK PACKET ANALYZER")
    print("="*70)
    print("\n⚠️ WARNING: This tool requires root/administrator privileges")
    print("⚠️ Only use on networks you own or have permission to monitor")
    print("\nOptions:")
    print("  1. Capture 10 packets")
    print("  2. Capture 50 packets")
    print("  3. Capture 100 packets")
    print("  4. Continuous capture (Ctrl+C to stop)")
    print("  5. Exit")

    try:
        choice = input("\nSelect option: ").strip()

        if choice == '1':
            analyzer.capture_packets(10)
        elif choice == '2':
            analyzer.capture_packets(50)
        elif choice == '3':
            analyzer.capture_packets(100)
        elif choice == '4':
            analyzer.capture_packets(0)
        elif choice == '5':
            print("\nGoodbye!")
            sys.exit(0)
        else:
            print("Invalid option")

    except Exception as e:
        print(f"\nError: {e}")
        print("\nNote: This tool requires root privileges on Linux or administrator on Windows")
        print("Try running with: sudo python3 network_packet_analyzer.py")


if __name__ == "__main__":
    main()
