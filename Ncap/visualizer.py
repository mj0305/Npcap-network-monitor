import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from PyQt5.QtWidgets import QSizePolicy

class TrafficVisualizer:
    """Network Traffic Visualizer Class"""
    
    def __init__(self, analyzer=None):
        plt.style.use('ggplot')
        self.colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', 
                       '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']
        self.analyzer = analyzer
    
    def _setup_auto_resize(self, fig, canvas, min_height=250):
        try:
            fig.set_layout_engine('tight') 
        except AttributeError:
            fig.set_tight_layout(True)      

        canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        canvas.setMinimumSize(300, min_height)
        canvas.updateGeometry()

    def create_protocol_pie_chart(self, protocol_data):
        fig = Figure(dpi=100)
        ax = fig.add_subplot(111)
        
        labels = list(protocol_data.keys())
        sizes = list(protocol_data.values())
        
        if not sizes:
            ax.text(0.5, 0.5, 'No protocol data available', 
                    horizontalalignment='center', verticalalignment='center')
            ax.axis('off')
        else:
            # 【优化1】：计算总数并生成带有百分比的自定义图例标签
            total = sum(sizes)
            legend_labels = [f"{label} ({size/total*100:.1f}%)" for label, size in zip(labels, sizes)]
            
            # 绘制饼图，取消 autopct 参数，不在饼图上画任何文字
            wedges, texts = ax.pie(
                sizes, 
                labels=None,
                startangle=90,
                colors=self.colors[:len(labels)]
            )
            # 将带有百分比的标签放在图例中
            ax.legend(wedges, legend_labels, loc='center left', bbox_to_anchor=(1, 0.5))
            ax.set_title('Protocol Distribution')
        
        canvas = FigureCanvas(fig)
        self._setup_auto_resize(fig, canvas, min_height=250)
        return canvas
    
    def create_traffic_time_series(self, traffic_data):
        fig = Figure(dpi=100)
        ax1 = fig.add_subplot(111)
        
        if traffic_data.empty:
            ax1.text(0.5, 0.5, 'No traffic data available', 
                     horizontalalignment='center', verticalalignment='center')
            ax1.axis('off')
        else:
            ax1.plot(traffic_data['timestamp'], traffic_data['bytes'], 'b-', label='Bytes')
            ax1.set_xlabel('Time')
            
            # 【优化2】：移除原有的竖向 ylabel，把单位写在坐标轴最顶端
            ax1.text(0, 1.02, 'Bytes', color='b', transform=ax1.transAxes, ha='left', va='bottom', fontweight='bold')
            ax1.tick_params('y', colors='b')
            
            ax2 = ax1.twinx()
            ax2.plot(traffic_data['timestamp'], traffic_data['packets'], 'r-', label='Packets')
            
            # 把右侧的单位也写在坐标轴最顶端
            ax2.text(1, 1.02, 'Packets', color='r', transform=ax2.transAxes, ha='right', va='bottom', fontweight='bold')
            ax2.tick_params('y', colors='r')
            
            # 给标题增加上边距，防止跟上面的文字重叠
            ax1.set_title('Traffic Time Series', pad=25)
            
            # 【优化3】：把 Bytes 和 Packets 的图例移动到图表最后面（正下方居中）
            lines1, labels1 = ax1.get_legend_handles_labels()
            lines2, labels2 = ax2.get_legend_handles_labels()
            ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper center', bbox_to_anchor=(0.5, -0.2), ncol=2)
            
            fig.autofmt_xdate()
        
        canvas = FigureCanvas(fig)
        self._setup_auto_resize(fig, canvas, min_height=280)  # 高度稍微增加一点给底部的图例留空间
        return canvas
    
    def create_top_talkers_bar_chart(self, src_traffic, dst_traffic):
        fig = Figure(dpi=100)
        
        if not src_traffic and not dst_traffic:
            ax = fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No traffic data available', 
                    horizontalalignment='center', verticalalignment='center')
            ax.axis('off')
        else:
            ax1 = fig.add_subplot(211)
            ax2 = fig.add_subplot(212)
            
            if src_traffic:
                ips = list(src_traffic.keys())
                values = list(src_traffic.values())
                y_pos = np.arange(len(ips))
                max_ips = min(10, len(ips))
                
                ax1.barh(y_pos[:max_ips], values[:max_ips], color=self.colors[:max_ips], height=0.5)
                ax1.set_yticks(y_pos[:max_ips])
                ax1.set_yticklabels(ips[:max_ips])
                ax1.invert_yaxis()
                ax1.set_xlabel('Bytes')
                ax1.set_title('Top Source IPs (by Bytes)')
            else:
                ax1.text(0.5, 0.5, 'No source IP data', ha='center', va='center')
                ax1.axis('off')
            
            if dst_traffic:
                ips = list(dst_traffic.keys())
                values = list(dst_traffic.values())
                y_pos = np.arange(len(ips))
                max_ips = min(10, len(ips))
                
                ax2.barh(y_pos[:max_ips], values[:max_ips], color=self.colors[:max_ips], height=0.5)
                ax2.set_yticks(y_pos[:max_ips])
                ax2.set_yticklabels(ips[:max_ips])
                ax2.invert_yaxis()
                ax2.set_xlabel('Bytes')
                ax2.set_title('Top Dest IPs (by Bytes)')
            else:
                ax2.text(0.5, 0.5, 'No destination IP data', ha='center', va='center')
                ax2.axis('off')
        
        canvas = FigureCanvas(fig)
        self._setup_auto_resize(fig, canvas, min_height=450)
        return canvas