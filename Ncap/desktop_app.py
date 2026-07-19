import sys
import os
import time
# --- 注意这行：新增了 QScrollArea ---
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QPushButton, QComboBox, QSpinBox, 
                             QTableWidget, QTableWidgetItem, QProgressBar, QMessageBox,
                             QGroupBox, QFormLayout, QScrollArea)
from PyQt5.QtCore import QTimer, pyqtSignal, QThread

from packet_capture import PacketCapture
from analyzer import TrafficAnalyzer
from detector import AnomalyDetector
from visualizer import TrafficVisualizer

os.makedirs('data', exist_ok=True)

class CaptureThread(QThread):
    update_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(int)
    error_signal = pyqtSignal(str)
    
    def __init__(self, capture, parent=None):
        super().__init__(parent)
        self.capture = capture
        self.running = False
        
    def run(self):
        self.running = True
        try:
            while self.running and self.capture.is_capturing:
                self.update_signal.emit(self.capture.packet_count)
                time.sleep(0.5)
            self.finished_signal.emit(self.capture.packet_count)
        except Exception as e:
            self.error_signal.emit(str(e))
            
    def stop(self):
        self.running = False
        self.wait()

class CaptureTab(QWidget):
    """Packet Capture Tab"""
    def __init__(self, app_context):
        super().__init__()
        self.app = app_context
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        control_group = QGroupBox("Capture Control")
        control_layout = QFormLayout()
        
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.app.capture.get_interfaces())
        control_layout.addRow("Network Interface:", self.interface_combo)
        
        self.packet_count_spin = QSpinBox()
        self.packet_count_spin.setRange(1, 100000)
        self.packet_count_spin.setValue(1000)
        control_layout.addRow("Packet Count Limit:", self.packet_count_spin)
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(0, 3600)
        self.timeout_spin.setValue(60)
        self.timeout_spin.setSpecialValueText("Unlimited")
        control_layout.addRow("Timeout (seconds):", self.timeout_spin)
        
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Capture")
        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.setEnabled(False)
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        layout.addLayout(button_layout)
        
        status_group = QGroupBox("Capture Status")
        status_layout = QVBoxLayout()
        self.status_label = QLabel("Ready")
        self.packet_count_label = QLabel("Captured Packets: 0")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.packet_count_label)
        status_layout.addWidget(self.progress_bar)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        table_group = QGroupBox("Recently Captured Packets")
        table_layout = QVBoxLayout()
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels(["Timestamp", "Size (Bytes)", "Source IP", "Dest IP", "Protocol", "Info"])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        table_layout.addWidget(self.packet_table)
        table_group.setLayout(table_layout)
        layout.addWidget(table_group)
        
        self.setLayout(layout)

    def start_capture(self):
        self.app.capture.interface = self.interface_combo.currentText()
        success = self.app.capture.start_capture(
            packet_count=self.packet_count_spin.value(),
            timeout=self.timeout_spin.value() if self.timeout_spin.value() > 0 else None
        )
        if success:
            self.status_label.setText("Capturing...")
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.progress_bar.setValue(0)
            
            self.app.capture_thread = CaptureThread(self.app.capture)
            self.app.capture_thread.update_signal.connect(self.update_capture_status)
            self.app.capture_thread.finished_signal.connect(self.capture_finished)
            self.app.capture_thread.error_signal.connect(self.capture_error)
            self.app.capture_thread.start()
            self.app.update_timer.start(1000)
        else:
            QMessageBox.warning(self, "Error", "Failed to start capture.")

    def stop_capture(self):
        packet_count = self.app.capture.stop_capture()
        self.status_label.setText("Stopped")
        self.packet_count_label.setText(f"Captured Packets: {packet_count}")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        if self.app.capture_thread: self.app.capture_thread.stop()
        self.app.update_timer.stop()
        self.update_packet_table()

    def update_capture_status(self, packet_count):
        self.packet_count_label.setText(f"Captured Packets: {packet_count}")
        max_packets = self.packet_count_spin.value()
        self.progress_bar.setValue(min(int(packet_count / max_packets * 100), 100))
        self.update_packet_table()

    def capture_finished(self, packet_count):
        self.status_label.setText("Completed")
        self.packet_count_label.setText(f"Captured Packets: {packet_count}")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(100)
        self.app.update_timer.stop()
        self.update_packet_table()

    def capture_error(self, error_msg):
        QMessageBox.critical(self, "Capture Error", f"Error occurred: {error_msg}")
        self.stop_capture()

    def update_packet_table(self):
        try:
            packets = self.app.capture.packets[-100:]
            self.packet_table.setRowCount(len(packets))
            
            for i, packet in enumerate(packets):
                self.packet_table.setItem(i, 0, QTableWidgetItem(packet.get('timestamp', '-')))
                self.packet_table.setItem(i, 1, QTableWidgetItem(str(packet.get('size', 0))))
                self.packet_table.setItem(i, 2, QTableWidgetItem(packet.get('src') or "-"))
                self.packet_table.setItem(i, 3, QTableWidgetItem(packet.get('dst') or "-"))
                self.packet_table.setItem(i, 4, QTableWidgetItem(packet.get('protocol') or "-"))
                
                info_str = ", ".join([f"{k}: {v}" for k, v in packet.get('info', {}).items()])
                self.packet_table.setItem(i, 5, QTableWidgetItem(info_str))
        except Exception as e:
            print(f"Failed to update table: {e}")

class AnalyzeTab(QWidget):
    """Traffic Analysis Tab"""
    def __init__(self, app_context):
        super().__init__()
        self.app = app_context
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        control_group = QGroupBox("Analysis Control")
        control_layout = QHBoxLayout()
        self.load_data_button = QPushButton("Load Latest Captured Data")
        self.load_data_button.clicked.connect(self.load_data)
        control_layout.addWidget(self.load_data_button)
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        stats_group = QGroupBox("Basic Statistics")
        stats_layout = QFormLayout()
        self.labels = {
            'total': QLabel("0"), 'bytes': QLabel("0"), 'avg': QLabel("0"),
            'src_ips': QLabel("0"), 'dst_ips': QLabel("0"),
            'start': QLabel("-"), 'end': QLabel("-")
        }
        stats_layout.addRow("Total Packets:", self.labels['total'])
        stats_layout.addRow("Total Bytes:", self.labels['bytes'])
        stats_layout.addRow("Avg Packet Size:", self.labels['avg'])
        stats_layout.addRow("Unique Source IPs:", self.labels['src_ips'])
        stats_layout.addRow("Unique Dest IPs:", self.labels['dst_ips'])
        stats_layout.addRow("Start Time:", self.labels['start'])
        stats_layout.addRow("End Time:", self.labels['end'])
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # --- 核心修改：将图表包裹进 QScrollArea 滚动区域 ---
        charts_group = QGroupBox("Traffic Analysis Charts")
        charts_layout = QVBoxLayout()
        
        self.protocol_layout = QVBoxLayout()
        self.traffic_layout = QVBoxLayout()
        self.talkers_layout = QVBoxLayout()
        
        charts_layout.addLayout(self.protocol_layout)
        charts_layout.addLayout(self.traffic_layout)
        charts_layout.addLayout(self.talkers_layout)
        
        charts_group.setLayout(charts_layout)
        
        # 创建滚动面板
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(charts_group)
        
        # 添加滚动面板到主布局
        layout.addWidget(scroll_area)
        self.setLayout(layout)

    def load_data(self):
        if self.app.analyzer.load_data():
            self.update_stats()
            self.update_charts()
        else:
            QMessageBox.warning(self, "Error", "Failed to load data. Please ensure packets have been captured.")

    def update_stats(self):
        stats = self.app.analyzer.get_basic_stats()
        if stats:
            self.labels['total'].setText(str(stats.get("total_packets", 0)))
            self.labels['bytes'].setText(str(stats.get("total_bytes", 0)))
            self.labels['avg'].setText(f"{stats.get('avg_packet_size', 0):.2f}")
            self.labels['src_ips'].setText(str(stats.get("unique_src_ips", 0)))
            self.labels['dst_ips'].setText(str(stats.get("unique_dst_ips", 0)))
            self.labels['start'].setText(str(stats.get("start_time", "-")))
            self.labels['end'].setText(str(stats.get("end_time", "-")))

    def update_charts(self):
        self._clear_layout(self.protocol_layout)
        self._clear_layout(self.traffic_layout)
        self._clear_layout(self.talkers_layout)
        
        protocol_dist = self.app.analyzer.get_protocol_distribution()
        if protocol_dist:
            canvas = self.app.visualizer.create_protocol_pie_chart(protocol_dist)
            self.protocol_layout.addWidget(canvas)
            
        traffic_data = self.app.analyzer.get_traffic_by_time()
        if not traffic_data.empty:
            canvas = self.app.visualizer.create_traffic_time_series(traffic_data)
            self.traffic_layout.addWidget(canvas)
            
        src_traffic, dst_traffic = self.app.analyzer.get_top_talkers()
        if src_traffic and dst_traffic:
            canvas = self.app.visualizer.create_top_talkers_bar_chart(src_traffic, dst_traffic)
            self.talkers_layout.addWidget(canvas)

    def _clear_layout(self, layout):
        while layout.count():
            child = layout.takeAt(0)
            if child.widget(): child.widget().deleteLater()

class DetectTab(QWidget):
    """Anomaly Detection Tab"""
    def __init__(self, app_context):
        super().__init__()
        self.app = app_context
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        control_group = QGroupBox("Detection Control")
        control_layout = QHBoxLayout()
        self.detect_button = QPushButton("Run Anomaly Detection")
        self.detect_button.clicked.connect(self.run_detection)
        control_layout.addWidget(self.detect_button)
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        size_group = QGroupBox("Abnormal Packet Sizes")
        size_layout = QVBoxLayout()
        self.size_table = QTableWidget()
        self.size_table.setColumnCount(7)
        self.size_table.setHorizontalHeaderLabels(["Timestamp", "Size (Bytes)", "Z-Score", "Src IP", "Dst IP", "Protocol", "Type"])
        self.size_table.horizontalHeader().setStretchLastSection(True)
        size_layout.addWidget(self.size_table)
        size_group.setLayout(size_layout)
        layout.addWidget(size_group)
        
        rate_group = QGroupBox("Abnormal Traffic Rates")
        rate_layout = QVBoxLayout()
        self.rate_table = QTableWidget()
        self.rate_table.setColumnCount(5)
        self.rate_table.setHorizontalHeaderLabels(["Timestamp", "Value", "Z-Score", "Metric", "Type"])
        self.rate_table.horizontalHeader().setStretchLastSection(True)
        rate_layout.addWidget(self.rate_table)
        rate_group.setLayout(rate_layout)
        layout.addWidget(rate_group)
        
        self.setLayout(layout)

    def run_detection(self):
        if not self.app.analyzer.df is not None:
            self.app.analyzer.load_data()
            
        if self.app.analyzer.df is None:
            QMessageBox.warning(self, "Error", "Please load data in 'Traffic Analysis' tab first.")
            return
            
        size_anomalies = self.app.detector.detect_size_anomalies()
        self.size_table.setRowCount(len(size_anomalies))
        for i, anomaly in enumerate(size_anomalies):
            self.size_table.setItem(i, 0, QTableWidgetItem(anomaly['timestamp']))
            self.size_table.setItem(i, 1, QTableWidgetItem(str(anomaly['size'])))
            self.size_table.setItem(i, 2, QTableWidgetItem(f"{anomaly['z_score']:.2f}"))
            self.size_table.setItem(i, 3, QTableWidgetItem(anomaly['src']))
            self.size_table.setItem(i, 4, QTableWidgetItem(anomaly['dst']))
            self.size_table.setItem(i, 5, QTableWidgetItem(anomaly['protocol']))
            self.size_table.setItem(i, 6, QTableWidgetItem(anomaly['type']))
        
        rate_anomalies = self.app.detector.detect_rate_anomalies()
        self.rate_table.setRowCount(len(rate_anomalies))
        for i, anomaly in enumerate(rate_anomalies):
            self.rate_table.setItem(i, 0, QTableWidgetItem(str(anomaly['timestamp'])))
            self.rate_table.setItem(i, 1, QTableWidgetItem(str(anomaly['value'])))
            self.rate_table.setItem(i, 2, QTableWidgetItem(f"{anomaly['z_score']:.2f}"))
            self.rate_table.setItem(i, 3, QTableWidgetItem(anomaly['metric']))
            self.rate_table.setItem(i, 4, QTableWidgetItem(anomaly['type']))
            
        if not size_anomalies and not rate_anomalies:
            QMessageBox.information(self, "Detection Result", "No abnormal traffic detected.")

class NetworkMonitorApp(QMainWindow):
    """Main App Window"""
    def __init__(self):
        super().__init__()
        
        self.capture = PacketCapture(output_file="data/captured_packets.json")
        self.analyzer = TrafficAnalyzer(data_file="data/captured_packets.json")
        self.detector = AnomalyDetector(self.analyzer)
        self.visualizer = TrafficVisualizer(self.analyzer)
        
        self.capture_thread = None
        self.update_timer = QTimer()
        
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle('Network Traffic Monitoring System')
        self.setGeometry(100, 100, 1200, 800)
        
        self.tabs = QTabWidget()
        
        self.capture_tab = CaptureTab(self)
        self.analyze_tab = AnalyzeTab(self)
        self.detect_tab = DetectTab(self)
        
        self.tabs.addTab(self.capture_tab, "Packet Capture")
        self.tabs.addTab(self.analyze_tab, "Traffic Analysis")
        self.tabs.addTab(self.detect_tab, "Anomaly Detection")
        
        self.setCentralWidget(self.tabs)
        self.show()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkMonitorApp()
    sys.exit(app.exec_())