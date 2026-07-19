import json
import time
import threading
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy library is not installed. Some features will be unavailable. Use 'pip install scapy' to install.")

class PacketCapture:
    """Network Packet Capture Class"""
    
    def __init__(self, interface=None, output_file="data/captured_packets.json"):
        self.interface = interface
        self.output_file = output_file
        self.is_capturing = False
        self.capture_thread = None
        self.packet_count = 0
        self.packets = [] 
    
    def get_interfaces(self):
        """Get available network interfaces"""
        if SCAPY_AVAILABLE:
            from scapy.arch import get_if_list
            try:
                return get_if_list()
            except:
                pass
        return ["eth0", "wlan0", "en0", "en1", "Wi-Fi", "Ethernet"]
    
    def start_capture(self, packet_count=1000, timeout=None):
        """Start capturing packets"""
        if not SCAPY_AVAILABLE or self.is_capturing:
            return False
        
        self.packet_count = 0
        self.packets = []
        self.is_capturing = True
        
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(packet_count, timeout)
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()
        return True
    
    def stop_capture(self):
        """Stop capturing packets"""
        if not self.is_capturing:
            return self.packet_count
        
        self.is_capturing = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(2.0)
        
        self._save_packets()
        return self.packet_count
    
    def _capture_packets(self, packet_count=1000, timeout=None):
        """Internal capture method"""
        try:
            sniff(iface=self.interface, 
                  prn=self._process_packet,
                  count=packet_count,
                  timeout=timeout,
                  store=False,
                  stop_filter=lambda p: not self.is_capturing)
        except Exception as e:
            print(f"Capture error: {str(e)}")
        finally:
            self.is_capturing = False
            self._save_packets()
    
    def _process_packet(self, packet):
        """Process a single packet and store it in memory"""
        if not self.is_capturing:
            return
        
        packet_info = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
            "size": len(packet),
            "src": None,
            "dst": None,
            "protocol": None,
            "info": {}
        }
        
        if Ether in packet:
            packet_info["src_mac"] = packet[Ether].src
            packet_info["dst_mac"] = packet[Ether].dst
            
        if IP in packet:
            packet_info["src"] = packet[IP].src
            packet_info["dst"] = packet[IP].dst
            packet_info["protocol"] = "IP"
            packet_info["info"]["ttl"] = packet[IP].ttl
            
        if TCP in packet:
            packet_info["protocol"] = "TCP"
            packet_info["info"]["sport"] = packet[TCP].sport
            packet_info["info"]["dport"] = packet[TCP].dport
            packet_info["info"]["flags"] = str(packet[TCP].flags)
        elif UDP in packet:
            packet_info["protocol"] = "UDP"
            packet_info["info"]["sport"] = packet[UDP].sport
            packet_info["info"]["dport"] = packet[UDP].dport
        elif ICMP in packet:
            packet_info["protocol"] = "ICMP"
            packet_info["info"]["type"] = packet[ICMP].type
            packet_info["info"]["code"] = packet[ICMP].code
        elif ARP in packet:
            packet_info["protocol"] = "ARP"
            packet_info["src"] = packet[ARP].psrc
            packet_info["dst"] = packet[ARP].pdst
            packet_info["info"]["op"] = "request" if packet[ARP].op == 1 else "reply"
            
        self.packets.append(packet_info)
        self.packet_count += 1
        
        if self.packet_count % 100 == 0:
            self._save_packets()
            
    def _save_packets(self):
        """Save packets to disk"""
        try:
            import os
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
            with open(self.output_file, 'w') as f:
                json.dump(self.packets, f, indent=2)
        except Exception as e:
            print(f"Error saving packets: {str(e)}")