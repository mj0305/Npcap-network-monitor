import json
import pandas as pd
from datetime import datetime

class TrafficAnalyzer:
    """Network Traffic Analyzer Class"""
    
    def __init__(self, data_file="data/captured_packets.json"):
        self.data_file = data_file
        self.packets = []
        self.df = None
    
    def load_data(self):
        """Load data and convert to DataFrame"""
        try:
            with open(self.data_file, 'r') as f:
                self.packets = json.load(f)
            
            self.df = pd.DataFrame(self.packets)
            if not self.df.empty:
                self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
                self.df['size'] = pd.to_numeric(self.df['size'])
            
            return len(self.packets) > 0
        except Exception as e:
            print(f"Error loading data: {str(e)}")
            return False
            
    def get_basic_stats(self):
        if self.df is None or self.df.empty: return {}
        return {
            "total_packets": len(self.df),
            "total_bytes": int(self.df['size'].sum()),
            "avg_packet_size": float(self.df['size'].mean()),
            "unique_src_ips": len(self.df['src'].dropna().unique()),
            "unique_dst_ips": len(self.df['dst'].dropna().unique()),
            "start_time": self.df['timestamp'].min().strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": self.df['timestamp'].max().strftime("%Y-%m-%d %H:%M:%S")
        }
        
    def get_protocol_distribution(self):
        if self.df is None or self.df.empty: return {}
        protocol_counts = self.df['protocol'].value_counts().to_dict()
        if None in protocol_counts:
            protocol_counts['Unknown'] = protocol_counts.pop(None, 0)
        return protocol_counts
        
    def get_traffic_by_time(self, interval='1S'):
        if self.df is None or self.df.empty: return pd.DataFrame()
        resampled = self.df.set_index('timestamp').resample(interval)
        return pd.DataFrame({
            'bytes': resampled['size'].sum(),
            'packets': resampled.size()
        }).reset_index()
        
    def get_top_talkers(self, n=10):
        if self.df is None or self.df.empty: return {}, {}
        
        src_traffic = self.df.groupby('src')['size'].sum().sort_values(ascending=False).head(n).to_dict()
        dst_traffic = self.df.groupby('dst')['size'].sum().sort_values(ascending=False).head(n).to_dict()
        
        if None in src_traffic: src_traffic['Unknown'] = src_traffic.pop(None, 0)
        if None in dst_traffic: dst_traffic['Unknown'] = dst_traffic.pop(None, 0)
        
        return src_traffic, dst_traffic