import pandas as pd
import numpy as np

class AnomalyDetector:
    """Network Traffic Anomaly Detector Class"""
    
    def __init__(self, analyzer):
        if not analyzer:
            raise ValueError("AnomalyDetector requires a valid TrafficAnalyzer instance.")
        self.analyzer = analyzer
        self.anomalies = []

    @property
    def df(self):
        return self.analyzer.df
        
    @property
    def packets(self):
        return self.analyzer.packets

    def detect_size_anomalies(self):
        """Detect abnormal packet sizes using Pandas vectorization"""
        if self.df is None or self.df.empty:
            return []
            
        mean_size = self.df['size'].mean()
        std_size = self.df['size'].std()
        if std_size == 0 or pd.isna(std_size): 
            std_size = 1
            
        df_copy = self.df.copy()
        df_copy['z_score'] = abs(df_copy['size'] - mean_size) / std_size
        
        anomalies_df = df_copy[df_copy['z_score'] > 3].sort_values('z_score', ascending=False)
        
        size_anomalies = []
        for _, packet in anomalies_df.iterrows():
            size_anomalies.append({
                "timestamp": packet['timestamp'].strftime("%Y-%m-%d %H:%M:%S"),
                "size": int(packet['size']),
                "z_score": packet['z_score'],
                "src": packet['src'] if pd.notna(packet['src']) else "-",
                "dst": packet['dst'] if pd.notna(packet['dst']) else "-",
                "protocol": packet['protocol'] if pd.notna(packet['protocol']) else "-",
                "type": "Abnormally Large" if packet['size'] > mean_size else "Abnormally Small"
            })
        return size_anomalies

    def detect_rate_anomalies(self):
        """Detect abnormal traffic rates"""
        if self.df is None or self.df.empty:
            return []
            
        traffic_by_time = self.df.set_index('timestamp').resample('1S')['size'].agg(['sum', 'count']).reset_index()
        traffic_by_time.columns = ['timestamp', 'bytes', 'packets']
        
        if len(traffic_by_time) <= 1:
            return []
            
        mean_bytes, std_bytes = traffic_by_time['bytes'].mean(), traffic_by_time['bytes'].std() or 1
        mean_pkts, std_pkts = traffic_by_time['packets'].mean(), traffic_by_time['packets'].std() or 1
        
        traffic_by_time['bytes_z'] = abs(traffic_by_time['bytes'] - mean_bytes) / std_bytes
        traffic_by_time['pkts_z'] = abs(traffic_by_time['packets'] - mean_pkts) / std_pkts
        
        rate_anomalies = []
        
        bytes_anomalies = traffic_by_time[traffic_by_time['bytes_z'] > 3]
        for _, row in bytes_anomalies.iterrows():
            rate_anomalies.append({
                "timestamp": row['timestamp'].strftime("%Y-%m-%d %H:%M:%S"),
                "value": int(row['bytes']),
                "z_score": row['bytes_z'],
                "metric": "Bytes/sec",
                "type": "Traffic Spike" if row['bytes'] > mean_bytes else "Traffic Drop"
            })
            
        pkts_anomalies = traffic_by_time[traffic_by_time['pkts_z'] > 3]
        for _, row in pkts_anomalies.iterrows():
            rate_anomalies.append({
                "timestamp": row['timestamp'].strftime("%Y-%m-%d %H:%M:%S"),
                "value": int(row['packets']),
                "z_score": row['pkts_z'],
                "metric": "Packets/sec",
                "type": "Packet Rate Spike" if row['packets'] > mean_pkts else "Packet Rate Drop"
            })
            
        rate_anomalies.sort(key=lambda x: x['z_score'], reverse=True)
        return rate_anomalies