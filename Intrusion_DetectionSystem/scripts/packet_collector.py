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

def capture_packets(interface, count=100):
    """지정된 네트워크 인터페이스에서 패킷을 캡처합니다."""
    packets = sniff(iface=interface, count=count)
    return packets

def _get_packet_info(packet):
    """패킷 정보 추출"""
    info = []
    
    # IP 정보
    if IP in packet:
        info.append(f"IP {packet[IP].src} → {packet[IP].dst}")
        info.append(f"TTL: {packet[IP].ttl}")
        info.append(f"ID: {packet[IP].id}")
        
        # TCP 정보
        if TCP in packet:
            info.append(f"TCP {packet[TCP].sport} → {packet[TCP].dport}")
            info.append(f"Seq: {packet[TCP].seq}")
            info.append(f"Ack: {packet[TCP].ack}")
            info.append(f"Window: {packet[TCP].window}")
            
            # TCP 플래그
            flags = []
            if packet[TCP].flags & 0x02:  # SYN
                flags.append("SYN")
            if packet[TCP].flags & 0x10:  # ACK
                flags.append("ACK")
            if packet[TCP].flags & 0x01:  # FIN
                flags.append("FIN")
            if packet[TCP].flags & 0x04:  # RST
                flags.append("RST")
            if packet[TCP].flags & 0x08:  # PSH
                flags.append("PSH")
            if packet[TCP].flags & 0x20:  # URG
                flags.append("URG")
            if flags:
                info.append(f"Flags: {' '.join(flags)}")
        
        # UDP 정보
        elif UDP in packet:
            info.append(f"UDP {packet[UDP].sport} → {packet[UDP].dport}")
            info.append(f"Length: {packet[UDP].len}")
        
        # ICMP 정보
        elif ICMP in packet:
            info.append(f"ICMP Type: {packet[ICMP].type}")
            info.append(f"ICMP Code: {packet[ICMP].code}")
    
    return ' | '.join(info)

def preprocess_packets(packets):
    """캡처된 패킷을 DataFrame으로 전처리합니다."""
    data = []
    for packet in packets:
        if IP in packet:
            data.append({
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'length': len(packet),
                'info': _get_packet_info(packet)
            })
    return pd.DataFrame(data)

def save_to_csv(dataframe, filename):
    """DataFrame을 CSV 파일로 저장합니다."""
    if not os.path.exists('data'):
        os.makedirs('data')
    filepath = os.path.join('data', filename)
    dataframe.to_csv(filepath, index=False)
    print(f"데이터가 {filepath}에 저장되었습니다.")

class PacketCaptureCore:
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=100)
        self.is_running = False
        self.packet_count = 0
        self.max_packets = 1000
        self.sniff_thread = None
        self.capture_completed = False

    def check_npcap(self):
        # Check registry for Npcap
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Npcap')
            winreg.CloseKey(key)
            print("Npcap detected in registry: SOFTWARE\\Npcap")
            return True
        except FileNotFoundError:
            print("Npcap not found in registry: SOFTWARE\\Npcap")

        # Check alternative registry path
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Npcap')
            winreg.CloseKey(key)
            print("Npcap detected in registry: SOFTWARE\\WOW6432Node\\Npcap")
            return True
        except FileNotFoundError:
            print("Npcap not found in registry: SOFTWARE\\WOW6432Node\\Npcap")

        # Check default installation directory
        default_path = os.path.join(os.environ.get('SystemRoot', 'C:\Windows'), 'System32', 'Npcap')
        if os.path.exists(default_path):
            print(f"Npcap detected in directory: {default_path}")
            return True
        else:
            print(f"Npcap not found in directory: {default_path}")

        return False

    def install_npcap(self):
        pass  # ... existing code from the second code snippet ...

    def check_admin_privileges(self):
        pass  # ... existing code from the second code snippet ...

    def get_network_interfaces(self):
        interfaces = psutil.net_if_addrs()
        return list(interfaces.keys())

    def start_capture(self, interface, max_packets):
        if self.is_running:
            return False

        self.is_running = True
        self.packet_count = 0
        self.max_packets = max_packets

        def capture():
            packets = sniff(iface=interface, count=max_packets, prn=self._process_packet, stop_filter=lambda x: not self.is_running)
            self.is_running = False
            self.capture_completed = True

        self.sniff_thread = threading.Thread(target=capture)
        self.sniff_thread.start()
        return True

    def _process_packet(self, packet):
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

    def stop_capture(self):
        pass  # ... existing code from the second code snippet ...

    def capture_packets(self, interface):
        pass  # ... existing code from the second code snippet ...

    def get_packet_queue(self):
        return self.packet_queue

    def get_packet_count(self):
        return self.packet_count

    def load_pcapng_file(self, file_path):
        pass  # ... existing code from the second code snippet ...

    def check_for_updates(self):
        
        pass

class FileLoadThread(QThread):
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(bool)
    error = pyqtSignal(str)

    def __init__(self, core, file_path):
        super().__init__()
        self.core = core
        self.file_path = file_path
        self.chunk_size = 100

    def run(self):
        pass

class MainApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("패킷 캡처 애플리케이션")
        self.setWindowIcon(QIcon("icon.png"))

        self.core = PacketCaptureCore()
        self.check_for_updates()

        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        self.packet_widget = QWidget()
        packet_layout = QVBoxLayout()

        control_layout = QHBoxLayout()
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

        packet_layout.addLayout(control_layout)
        packet_layout.addWidget(self.status_label)
        packet_layout.addWidget(self.packet_table)
        self.packet_widget.setLayout(packet_layout)

        self.stacked_widget.addWidget(self.packet_widget)

        self.setup_timer()

        start_button.clicked.connect(self.start_capture)
        stop_button.clicked.connect(self.stop_capture)
        load_button.clicked.connect(self.load_pcapng_file)

    def setup_timer(self):
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_packet_table)
        self.update_timer.start(200)

    def start_capture(self):
        selected_interface = self.interface_combo.currentText()
        max_packets = int(self.packet_count_combo.currentText())
        if self.core.start_capture(selected_interface, max_packets):
            self.status_label.setText(f"상태: 캡처 중 (0/{max_packets})")

    def stop_capture(self):
        packet_count = self.core.stop_capture()
        self.status_label.setText("상태: 중지됨")
        QMessageBox.information(self, "캡처 완료", f"캡처된 패킷 수: {packet_count}")

    def update_packet_table(self):
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
        file_path, _ = QFileDialog.getOpenFileName(self, "pcapng 파일 선택", "", "PCAPNG Files (*.pcapng);;All Files (*)")
        if file_path:
            self.file_load_thread = FileLoadThread(self.core, file_path)
            self.file_load_thread.progress.connect(self.update_progress)
            self.file_load_thread.finished.connect(self.file_load_finished)
            self.file_load_thread.error.connect(self.file_load_error)
            self.file_load_thread.start()

    def update_progress(self, current, total):
        self.status_label.setText(f"상태: 파일 로드 중... ({current}/{total})")

    def file_load_finished(self, success):
        if success:
            self.status_label.setText(f"상태: 파일 로드 완료 ({self.core.get_packet_count()} 패킷)")
        else:
            self.status_label.setText("상태: 파일 로드 실패")
            QMessageBox.critical(self, "오류", "파일 로드에 실패했습니다.")

    def file_load_error(self, error_message):
        self.status_label.setText("상태: 파일 로드 오류")
        QMessageBox.critical(self, "오류", f"파일 로드 중 오류 발생: {error_message}")

    def check_for_updates(self):
        # 업데이트 확인 및 설치 로직을 여기에 추가합니다.
        pass

class TrafficGeneratorApp(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("트래픽 생성기")
        layout = QVBoxLayout()

        # IP 입력
        ip_layout = QHBoxLayout()
        ip_label = QLabel("대상 IP:")
        self.ip_input = QLineEdit()
        ip_layout.addWidget(ip_label)
        ip_layout.addWidget(self.ip_input)
        layout.addLayout(ip_layout)

        # 트래픽 유형 선택
        self.syn_flood_checkbox = QCheckBox("SYN 플러드")
        self.udp_flood_checkbox = QCheckBox("UDP 플러드")
        self.http_slowloris_checkbox = QCheckBox("HTTP Slowloris")
        layout.addWidget(self.syn_flood_checkbox)
        layout.addWidget(self.udp_flood_checkbox)
        layout.addWidget(self.http_slowloris_checkbox)

        # 패킷 수 및 속도 입력
        packet_count_layout = QHBoxLayout()
        packet_count_label = QLabel("패킷 수:")
        self.packet_count_input = QLineEdit("10")
        packet_count_layout.addWidget(packet_count_label)
        packet_count_layout.addWidget(self.packet_count_input)
        layout.addLayout(packet_count_layout)

        # 패킷 생성 버튼
        generate_button = QPushButton("패킷 생성 및 전송")
        generate_button.clicked.connect(self.generate_traffic)
        layout.addWidget(generate_button)

        self.setLayout(layout)

    def generate_traffic(self):
        target_ip = self.ip_input.text()
        packet_count = int(self.packet_count_input.text())
        if self.is_valid_ip(target_ip):
            if self.syn_flood_checkbox.isChecked():
                self.send_syn_flood(target_ip, packet_count)
            if self.udp_flood_checkbox.isChecked():
                self.send_udp_flood(target_ip, packet_count)
            if self.http_slowloris_checkbox.isChecked():
                self.send_http_slowloris(target_ip, packet_count)
            print(f"패킷이 {target_ip}로 전송되었습니다.")
        else:
            QMessageBox.warning(self, "잘못된 IP", "올바른 IP 주소를 입력하세요.")
            self.ip_input.clear()

    def is_valid_ip(self, ip):
        # 간단한 IP 주소 유효성 검사
        pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        return pattern.match(ip) is not None

    def send_syn_flood(self, target_ip, count):
        packet = IP(dst=target_ip)/TCP(dport=80, flags='S')
        send(packet, count=count)

    def send_udp_flood(self, target_ip, count):
        packet = IP(dst=target_ip)/UDP(dport=80)
        send(packet, count=count)

    def send_http_slowloris(self, target_ip, count):
        for _ in range(count):
            threading.Thread(target=self.slowloris_attack, args=(target_ip,)).start()

    def slowloris_attack(self, target_ip):
        pass

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainApp()
    window.show()
    app.exec()