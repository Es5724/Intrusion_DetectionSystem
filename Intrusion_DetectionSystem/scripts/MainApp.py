import sys
import ctypes
from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QVBoxLayout, QWidget, QStackedWidget, QHBoxLayout, QComboBox, QTableWidget, QTableWidgetItem, QMessageBox
from PyQt6.QtGui import QIcon
from packet_collector import capture_packets, preprocess_packets, PacketCaptureCore
import pandas as pd
from sklearn.preprocessing import StandardScaler
from PyQt6.QtCore import Qt
from DataPreprocessingApp import DataPreprocessingApp
from AITrainingApp import AITrainingApp
from TrafficGeneratorApp import TrafficGeneratorApp

def run_as_admin():
    """관리자 권한으로 스크립트를 재실행합니다."""
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True
    else:
        # 관리자 권한으로 재실행
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

class MainApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("취약점 자동진단 시스템")
        self.setWindowIcon(QIcon("icon.png"))

        self.core = PacketCaptureCore()

        # Npcap 설치 여부 확인 (임시 비활성화)
        # if not self.core.check_npcap():
        #     QMessageBox.critical(self, "Npcap 미설치", "Npcap이 설치되어 있지 않습니다. 설치 후 다시 시도하세요.")
        #     sys.exit(1)

        self.check_for_updates()

        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        # 메인 화면 설정
        self.main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)  # 중앙 정렬

        # 버튼 스타일
        button_style = """
            QPushButton {
                background-color: #B0B0B0;
                color: black;
                font-size: 12px;  # Reduce text size by one-third
                padding: 10px;
                border-radius: 5px;
                border: 1px solid #A0A0A0;
            }
            QPushButton:hover {
                background-color: #A0A0A0;
            }
            QPushButton:pressed {
                background-color: #909090;
            }
        """

        # 버튼 생성 및 스타일 적용
        main_button_capture = QPushButton("패킷 캡처")
        main_button_capture.setStyleSheet(button_style)
        main_button_capture.clicked.connect(self.show_packet_capture)
        main_button_capture.setFixedSize(300, 30)

        main_button_traffic_gen = QPushButton("트래픽 생성")
        main_button_traffic_gen.setStyleSheet(button_style)
        main_button_traffic_gen.clicked.connect(self.show_traffic_generator)
        main_button_traffic_gen.setFixedSize(300, 30)

        main_button_ai_training = QPushButton("AI 에이전트 학습")
        main_button_ai_training.setStyleSheet(button_style)
        main_button_ai_training.clicked.connect(self.show_ai_training)
        main_button_ai_training.setFixedSize(300, 30)

        main_button_analysis = QPushButton("학습 분석 및 결과")
        main_button_analysis.setStyleSheet(button_style)
        main_button_analysis.clicked.connect(self.show_analysis_results)
        main_button_analysis.setFixedSize(300, 30)

        main_button_auto_diagnosis = QPushButton("자동 진단 시스템 활성화")
        main_button_auto_diagnosis.setStyleSheet(button_style)
        main_button_auto_diagnosis.clicked.connect(self.activate_auto_diagnosis)
        main_button_auto_diagnosis.setFixedSize(300, 30)

        # 버튼을 레이아웃에 추가
        main_layout.addWidget(main_button_capture)
        main_layout.addWidget(main_button_traffic_gen)
        main_layout.addWidget(main_button_ai_training)
        main_layout.addWidget(main_button_analysis)
        main_layout.addWidget(main_button_auto_diagnosis)

        self.main_widget.setLayout(main_layout)
        self.stacked_widget.addWidget(self.main_widget)

        # 패킷 캡처 화면 설정
        self.packet_widget = QWidget()
        packet_layout = QVBoxLayout()

        control_layout = QHBoxLayout()
        back_button = QPushButton("")
        back_button.setIcon(QIcon.fromTheme("go-previous"))  # 아이콘 설정
        back_button.clicked.connect(self.show_main_screen)
        back_button.setFixedSize(30, 30)  # 데이터 전처리 화면의 크기에 맞춤
        control_layout.addWidget(back_button)

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

    def show_packet_capture(self):
        # 패킷 캡처 화면으로 전환
        self.stacked_widget.setCurrentWidget(self.packet_widget)

    def show_data_preprocessing(self):
        # 데이터 전처리 화면으로 전환
        self.preprocess_widget = DataPreprocessingApp(self)
        self.stacked_widget.addWidget(self.preprocess_widget)
        self.stacked_widget.setCurrentWidget(self.preprocess_widget)

    def show_main_screen(self):
        # 메인 화면으로 전환
        self.stacked_widget.setCurrentWidget(self.main_widget)

    def start_capture(self):
        selected_interface = self.interface_combo.currentText()
        max_packets = int(self.packet_count_combo.currentText())
        if self.core.start_capture(selected_interface, max_packets):
            self.status_label.setText(f"상태: 캡처 중 (0/{max_packets})")
            QMessageBox.information(self, "캡처 시작", "패킷 캡처가 시작되었습니다.")
        else:
            QMessageBox.warning(self, "캡처 실패", "패킷 캡처를 시작할 수 없습니다.")

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

    def setup_timer(self):
        # 타이머 설정 및 연결
        pass

    def load_pcapng_file(self):
        # 파일 불러오기 로직 구현
        pass

    def check_for_updates(self):
        # 업데이트 확인 및 설치 로직을 여기에 추가합니다.
        print("업데이트 확인 중...")
        # 현재는 단순히 업데이트 확인 중임을 출력합니다.

    def show_ai_training(self):
        # AI 에이전트 학습 화면으로 전환
        self.ai_training_widget = AITrainingApp(self)
        self.stacked_widget.addWidget(self.ai_training_widget)
        self.stacked_widget.setCurrentWidget(self.ai_training_widget)

    def show_analysis_results(self):
        # 학습 분석 및 결과 화면으로 전환
        print("학습 분석 및 결과 화면으로 전환")

    def activate_auto_diagnosis(self):
        # 자동 진단 시스템 활성화
        print("자동 진단 시스템 활성화")

    def show_traffic_generator(self):
        # 트래픽 생성 화면으로 전환
        if not hasattr(self, 'traffic_gen_widget') or self.traffic_gen_widget is None:
            # 관리자 권한 요청
            if not run_as_admin():
                return
            self.traffic_gen_widget = TrafficGeneratorApp(self)
            self.stacked_widget.addWidget(self.traffic_gen_widget)
        self.stacked_widget.setCurrentWidget(self.traffic_gen_widget)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainApp()
    window.show()
    app.exec()