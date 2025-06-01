# 필요한 모듈을 임포트
from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
import os
import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QPushButton, QVBoxLayout, QWidget,
    QStackedWidget, QComboBox, QHBoxLayout, QTableWidget, QTableWidgetItem, QMessageBox, QFileDialog, QLineEdit, QCheckBox
)
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import QTimer, QThread, pyqtSignal, Qt
import platform
import threading
import queue
import ctypes
from datetime import datetime
import winreg
import psutil
import re

# 모듈 경로를 부모 디렉토리로 설정하기 위한 코드 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)  # components 디렉토리의 부모 (scripts)
sys.path.append(parent_dir)

# 패킷 캡처 기능을 모듈화
class PacketCapture:
    def __init__(self, interface, count=100):
        self.interface = interface
        self.count = count

    def capture_packets(self):
        """지정된 네트워크 인터페이스에서 패킷을 캡처합니다."""
        return sniff(iface=self.interface, count=self.count)

    def preprocess_packets(self, packets):
        """캡처된 패킷을 DataFrame으로 전처리합니다."""
        data = []
        for packet in packets:
            if IP in packet:
                data.append({
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': packet[IP].proto,
                    'length': len(packet),
                    'info': self._get_packet_info(packet)
                })
        return pd.DataFrame(data)

    def _get_packet_info(self, packet):
        """패킷 정보 추출"""
        info = []
        if IP in packet:
            info.append(f"IP {packet[IP].src} → {packet[IP].dst}")
            info.append(f"TTL: {packet[IP].ttl}")
            info.append(f"ID: {packet[IP].id}")
            if TCP in packet:
                info.append(f"TCP {packet[TCP].sport} → {packet[TCP].dport}")
                info.append(f"Seq: {packet[TCP].seq}")
                info.append(f"Ack: {packet[TCP].ack}")
                info.append(f"Window: {packet[TCP].window}")
                flags = self._get_tcp_flags(packet[TCP].flags)
                if flags:
                    info.append(f"Flags: {' '.join(flags)}")
            elif UDP in packet:
                info.append(f"UDP {packet[UDP].sport} → {packet[UDP].dport}")
                info.append(f"Length: {packet[UDP].len}")
            elif ICMP in packet:
                info.append(f"ICMP Type: {packet[ICMP].type}")
                info.append(f"ICMP Code: {packet[ICMP].code}")
        return ' | '.join(info)

    def _get_tcp_flags(self, flags):
        """TCP 플래그 추출"""
        flag_list = []
        if flags & 0x02:  # SYN
            flag_list.append("SYN")
        if flags & 0x10:  # ACK
            flag_list.append("ACK")
        if flags & 0x01:  # FIN
            flag_list.append("FIN")
        if flags & 0x04:  # RST
            flag_list.append("RST")
        if flags & 0x08:  # PSH
            flag_list.append("PSH")
        if flags & 0x20:  # URG
            flag_list.append("URG")
        return flag_list

    def save_to_csv(self, dataframe, filename):
        """DataFrame을 CSV 파일로 저장합니다."""
        if not os.path.exists('data'):
            os.makedirs('data')
        filepath = os.path.join('data', filename)
        try:
            dataframe.to_csv(filepath, index=False)
            print(f"데이터가 {filepath}에 저장되었습니다.")
        except Exception as e:
            print(f"데이터 저장 중 오류 발생: {e}")

# PacketCaptureCore 클래스의 리팩터링
class PacketCaptureCore:
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=100)
        self.is_running = False
        self.packet_count = 0
        self.max_packets = 300000
        self.sniff_thread = None
        self.capture_completed = False

    def check_npcap(self):
        """Npcap/libpcap 설치 여부를 확인합니다."""
        if platform.system() == 'Windows':
            # Windows에서 Npcap 확인
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Npcap')
            winreg.CloseKey(key)
            print("Npcap detected in registry: SOFTWARE\\Npcap")
            return True
        except FileNotFoundError:
            print("Npcap not found in registry: SOFTWARE\\Npcap")
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Npcap')
            winreg.CloseKey(key)
            print("Npcap detected in registry: SOFTWARE\\WOW6432Node\\Npcap")
            return True
        except FileNotFoundError:
            print("Npcap not found in registry: SOFTWARE\\WOW6432Node\\Npcap")
            default_path = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'Npcap')
        if os.path.exists(default_path):
            print(f"Npcap detected in directory: {default_path}")
            return True
        else:
            print(f"Npcap not found in directory: {default_path}")
            return False
        else:
            # Unix/Linux에서 libpcap 확인
            try:
                # scapy가 정상적으로 임포트되면 libpcap이 설치된 것으로 간주
                from scapy.all import conf
                return True
            except ImportError:
                print("libpcap이 설치되지 않았습니다.")
        return False

    def get_network_interfaces(self):
        """네트워크 인터페이스 목록을 반환합니다."""
        interfaces = psutil.net_if_addrs()
        return list(interfaces.keys())

    def start_capture(self, interface, max_packets):
        """패킷 캡처를 시작합니다."""
        if self.is_running:
            return False
        self.is_running = True
        self.packet_count = 0
        self.max_packets = max_packets
        print(f"Starting packet capture on interface: {interface} with max_packets: {max_packets}")
        def capture():
            packets = sniff(iface=interface, count=max_packets, prn=self._process_packet, stop_filter=lambda x: not self.is_running)
            self.is_running = False
            self.capture_completed = True
        self.sniff_thread = threading.Thread(target=capture)
        self.sniff_thread.start()
        return True

    def _process_packet(self, packet):
        """캡처된 패킷을 처리합니다."""
        if self.packet_count >= self.max_packets:
            self.is_running = False
            return
        if IP in packet:
            packet_info = {
                'no': self.packet_count + 1,
                'source': packet[IP].src,
                'destination': packet[IP].dst,
                'protocol': packet[IP].proto,
                'length': len(packet),
                'info': str(packet.summary())
            }
            self.packet_queue.put(packet_info)
            self.packet_count += 1

    def get_packet_queue(self):
        """패킷 큐를 반환합니다."""
        return self.packet_queue

    def get_packet_count(self):
        """캡처된 패킷 수를 반환합니다."""
        return self.packet_count

    def stop_capture(self):
        """패킷 캡처를 중지하고 캡처된 패킷 수를 반환합니다."""
        print("Stopping packet capture...")
        self.is_running = False
        if self.sniff_thread is not None:
            self.sniff_thread.join()  # Ensure the sniffing thread has finished
        print(f"Packet capture stopped. Total packets captured: {self.packet_count}")
        return self.packet_count

    def get_packet_dataframe(self):
        """패킷 큐에 있는 데이터를 DataFrame으로 변환합니다."""
        packets = []
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            packets.append(packet)
        return pd.DataFrame(packets)

# 파일 로드 스레드 정의가 없을 수 있으므로 추가
class FileLoadThread(QThread):
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(bool)
    error = pyqtSignal(str)
    packets_loaded = pyqtSignal(list)
    
    def __init__(self, core, file_path):
        super().__init__()
        self.core = core
        self.file_path = file_path
        
    def run(self):
        try:
            print(f"파일 '{self.file_path}' 로드 중...")
            self.progress.emit(0, 100)
            
            # pcap/pcapng 파일 읽기
            from scapy.all import rdpcap
            packets = rdpcap(self.file_path)
            total_packets = len(packets)
            
            # 패킷을 처리하여 큐에 추가
            packet_list = []
            for i, packet in enumerate(packets):
                if IP in packet:
                    packet_info = {
                        'no': i + 1,
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': packet[IP].proto,
                        'length': len(packet),
                        'info': str(packet.summary())
                    }
                    packet_list.append(packet_info)
                
                # 진행률 업데이트
                if i % 100 == 0:
                    progress = int((i / total_packets) * 100)
                    self.progress.emit(progress, 100)
            
            # 패킷 리스트 전송
            self.packets_loaded.emit(packet_list)
            
            self.progress.emit(100, 100)
            self.finished.emit(True)
        except Exception as e:
            self.error.emit(str(e))
            self.finished.emit(False)

# MainApp 클래스의 리팩터링
class MainApp(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_app = parent
        self.setWindowTitle("패킷 캡처 애플리케이션")
        self.setWindowIcon(QIcon("icon.png"))
        self.core = PacketCaptureCore()
        self.check_for_updates()
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)
        self.packet_widget = QWidget()
        packet_layout = QVBoxLayout()
        control_layout = QHBoxLayout()
        
        # 뒤로가기 버튼 수정
        self.back_button = QPushButton("")
        self.back_button.setIcon(QIcon.fromTheme("go-previous"))
        self.back_button.setFixedSize(30, 30)
        self.back_button.clicked.connect(self.go_back)  # 뒤로가기 기능 연결
        control_layout.addWidget(self.back_button)
        
        interface_label = QLabel("네트워크 인터페이스:")
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.core.get_network_interfaces())
        packet_count_label = QLabel("최대 패킷 수:")
        self.packet_count_combo = QComboBox()
        self.packet_count_combo.addItems(["100", "500", "1000"])
        start_button = QPushButton("캡처 시작")
        stop_button = QPushButton("캡처 중지")
        load_button = QPushButton("파일 불러오기")
        control_layout.addWidget(interface_label)
        control_layout.addWidget(self.interface_combo)
        control_layout.addWidget(packet_count_label)
        control_layout.addWidget(self.packet_count_combo)
        control_layout.addWidget(start_button)
        control_layout.addWidget(stop_button)
        control_layout.addWidget(load_button)
        self.status_label = QLabel("상태: 대기 중")
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels(["No.", "Source", "Destination", "Protocol", "Length", "Info"])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        packet_layout.addLayout(control_layout)
        packet_layout.addWidget(self.status_label)
        packet_layout.addWidget(self.packet_table)
        self.packet_widget.setLayout(packet_layout)
        self.stacked_widget.addWidget(self.packet_widget)
        self.setup_timer()
        start_button.clicked.connect(self.start_capture)
        stop_button.clicked.connect(self.stop_capture)
        load_button.clicked.connect(self.load_pcapng_file)
        
        # 처음에는 뒤로가기 버튼 비활성화 (메인 앱이 없을 경우)
        if self.parent_app is None:
            self.back_button.setVisible(False)
    
    def go_back(self):
        """메인 화면으로 돌아가기"""
        if self.parent_app:
            try:
                # 캡처 중이라면 중지
                if self.core.is_running:
                    self.stop_capture()
                    
                # 부모 앱의 메인 화면 표시 메서드 호출
                self.parent_app.show_main_screen()
            except Exception as e:
                print(f"뒤로가기 중 오류 발생: {e}")
                QMessageBox.warning(self, "오류", "뒤로가기 실패")
    
    def setup_timer(self):
        """타이머를 설정합니다."""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_packet_table)
        self.update_timer.start(500)

    def start_capture(self):
        """패킷 캡처를 시작합니다."""
        selected_interface = self.interface_combo.currentText()
        max_packets = int(self.packet_count_combo.currentText())
        if self.core.start_capture(selected_interface, max_packets):
            self.status_label.setText(f"상태: 캡처 중 (0/{max_packets})")
            QMessageBox.information(self, "캡처 시작", "패킷 캡처가 시작되었습니다.")
        else:
            QMessageBox.warning(self, "캡처 실패", "패킷 캡처를 시작할 수 없습니다.")

    def stop_capture(self):
        """패킷 캡처를 중지합니다."""
        packet_count = self.core.stop_capture()
        self.status_label.setText("상태: 중지됨")
        QMessageBox.information(self, "캡처 완료", f"캡처된 패킷 수: {packet_count}")

    def update_packet_table(self):
        """패킷 테이블을 업데이트합니다."""
        packet_queue = self.core.get_packet_queue()
        new_packets = []
        while not packet_queue.empty():
            packet = packet_queue.get()
            new_packets.append(packet)
        if not new_packets:
            return
        current_row = self.packet_table.rowCount()
        self.packet_table.setRowCount(current_row + len(new_packets))
        for i, packet in enumerate(new_packets):
            self.packet_table.setItem(current_row + i, 0, QTableWidgetItem(str(packet.get('no', ''))))
            self.packet_table.setItem(current_row + i, 1, QTableWidgetItem(str(packet.get('source', ''))))
            self.packet_table.setItem(current_row + i, 2, QTableWidgetItem(str(packet.get('destination', ''))))
            self.packet_table.setItem(current_row + i, 3, QTableWidgetItem(str(packet.get('protocol', ''))))
            self.packet_table.setItem(current_row + i, 4, QTableWidgetItem(str(packet.get('length', ''))))
            info_item = QTableWidgetItem(str(packet.get('info', '')))
            info_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            self.packet_table.setItem(current_row + i, 5, info_item)
        self.packet_table.scrollToBottom()

    def load_pcapng_file(self):
        """PCAPNG 파일을 불러옵니다."""
        file_path, _ = QFileDialog.getOpenFileName(self, "pcapng 파일 선택", "", "PCAPNG Files (*.pcapng);;All Files (*)")
        if file_path:
            self.file_load_thread = FileLoadThread(self.core, file_path)
            self.file_load_thread.progress.connect(self.update_progress)
            self.file_load_thread.finished.connect(self.file_load_finished)
            self.file_load_thread.error.connect(self.file_load_error)
            self.file_load_thread.packets_loaded.connect(self.file_load_packets_loaded)
            self.file_load_thread.start()

    def update_progress(self, current, total):
        """진행 상황을 업데이트합니다."""
        self.status_label.setText(f"상태: 파일 로드 중... ({current}/{total})")

    def file_load_finished(self, success):
        """파일 로드가 완료되었을 때 호출됩니다."""
        if success:
            self.status_label.setText(f"상태: 파일 로드 완료 ({self.core.get_packet_count()} 패킷)")
        else:
            self.status_label.setText("상태: 파일 로드 실패")
            QMessageBox.critical(self, "오류", "파일 로드에 실패했습니다.")

    def file_load_error(self, error_message):
        """파일 로드 중 오류가 발생했을 때 호출됩니다."""
        self.status_label.setText("상태: 파일 로드 오류")
        QMessageBox.critical(self, "오류", f"파일 로드 중 오류 발생: {error_message}")

    def file_load_packets_loaded(self, packets):
        """파일에서 로드된 패킷을 처리합니다."""
        # 기존 패킷 큐 초기화
        while not self.core.packet_queue.empty():
            self.core.packet_queue.get()
        
        # 새로운 패킷 추가
        for packet in packets:
            self.core.packet_queue.put(packet)
        
        # 테이블 업데이트
        self.update_packet_table()

    def check_for_updates(self):
        """업데이트를 확인합니다."""
        pass

# 메인 함수
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainApp()
    window.show()
    sys.exit(app.exec()) 