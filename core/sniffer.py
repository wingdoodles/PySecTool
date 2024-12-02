from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, get_if_list
from scapy.layers.http import HTTP
from datetime import datetime
import json
import logging
import netifaces


class PacketEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, '__str__'):
            return str(obj)
        return json.JSONEncoder.default(self, obj)


class PacketSniffer:
    def __init__(self):
        self.interface = "eth0"
        self.captured_packets = []
        self.filters = []
        self.is_running = False
    def get_interfaces(self):
        # Get all available network interfaces
        interfaces = netifaces.interfaces()
        # Filter out loopback and inactive interfaces
        return [iface for iface in interfaces if iface != 'lo']

    def setup_logging(self):
        logging.basicConfig(
            filename='packet_capture.log',
            level=logging.INFO,
            format='%(asctime)s - %(message)s'
        )

    def packet_callback(self, packet):
        packet_info = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': str(packet.summary()),
            'length': len(packet)
        }
    
        self.captured_packets.append(packet_info)
        logging.info(json.dumps(packet_info, cls=PacketEncoder))
        return packet_info
    
    def add_filter(self, filter_string):
        self.filters.append(filter_string)
    
    def clear_filters(self):
        self.filters = []
    
    def start_sniff(self, interface=None, count=0):
        self.interface = interface or self.interface
        self.is_running = True
        filter_exp = " and ".join(self.filters) if self.filters else None
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                filter=filter_exp,
                count=count,
                store=0
            )
        except Exception as e:
            logging.error(f"Sniffing error: {str(e)}")
            
    def stop_sniff(self):
        self.is_running = False
    
    def get_statistics(self):
        if not self.captured_packets:
            return {}
            
        stats = {
            'total_packets': len(self.captured_packets),
            'protocols': {},
            'top_ips': {},
            'top_ports': {}
        }
        
        for packet in self.captured_packets:
            # Count protocols
            proto = packet.get('protocol', 'Unknown')
            stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1
            
            # Count IPs
            if 'src_ip' in packet:
                stats['top_ips'][packet['src_ip']] = stats['top_ips'].get(packet['src_ip'], 0) + 1
            
            # Count ports
            if 'src_port' in packet:
                stats['top_ports'][packet['src_port']] = stats['top_ports'].get(packet['src_port'], 0) + 1
        
        return stats
    
    def save_capture(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.captured_packets, f, indent=2)
