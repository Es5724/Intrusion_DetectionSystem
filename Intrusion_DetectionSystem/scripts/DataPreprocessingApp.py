from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QFileDialog, QHBoxLayout, QTableWidget, QTableWidgetItem
from PyQt6.QtGui import QIcon, QCloseEvent
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from packet_collector import preprocess_packets
from PyQt6.QtCore import Qt
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

class DataPreprocessingApp(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_app = parent
        self.setWindowTitle("데이터 전처리")
        layout = QVBoxLayout()

        # 상단 레이아웃 설정
        top_layout = QHBoxLayout()
        back_button = QPushButton("")
        back_button.setIcon(QIcon.fromTheme("go-previous"))  # 아이콘 설정
        back_button.setFixedSize(30, 30)  # 버튼 크기 조정
        back_button.clicked.connect(self.return_to_main)
        top_layout.addWidget(back_button)

        upload_button = QPushButton("데이터 파일 업로드")
        upload_button.clicked.connect(self.upload_data_file)
        top_layout.addWidget(upload_button)

        preprocess_button = QPushButton("데이터 전처리")
        preprocess_button.clicked.connect(self.preprocess_data)
        top_layout.addWidget(preprocess_button)

        layout.addLayout(top_layout)

        label = QLabel("데이터 전처리 화면입니다.")
        layout.addWidget(label)

        # 테이블 설정
        self.data_table = QTableWidget()
        self.data_table.setColumnCount(6)
        self.data_table.setHorizontalHeaderLabels(["No.", "Source", "Destination", "Protocol", "Length", "Info"])
        self.data_table.horizontalHeader().setStretchLastSection(True)  # 마지막 열 확장
        layout.addWidget(self.data_table)

        self.setLayout(layout)

    def closeEvent(self, event: QCloseEvent):
        self.parent_app.show_main_screen()
        event.accept()

    def return_to_main(self):
        self.parent_app.show_main_screen()
        self.close()

    def upload_data_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "데이터 파일 선택", "", "CSV Files (*.csv);;PCAP Files (*.pcap *.pcapng);;All Files (*)")
        if file_path:
            try:
                if file_path.endswith('.csv'):
                    data = pd.read_csv(file_path)
                else:
                    packets = rdpcap(file_path)
                    data = preprocess_packets(packets)
                print("데이터 파일이 성공적으로 로드되었습니다.")
                self.display_data_in_table(data)
            except Exception as e:
                print(f"데이터 파일 로드 중 오류 발생: {e}")

    def display_data_in_table(self, data):
        self.data_table.setRowCount(len(data))
        for i, row in data.iterrows():
            self.data_table.setItem(i, 0, QTableWidgetItem(str(i + 1)))  # No
            self.data_table.setItem(i, 1, QTableWidgetItem(str(row['src_ip'])))  # Source
            self.data_table.setItem(i, 2, QTableWidgetItem(str(row['dst_ip'])))  # Destination
            self.data_table.setItem(i, 3, QTableWidgetItem(str(row['protocol'])))  # Protocol
            self.data_table.setItem(i, 4, QTableWidgetItem(str(row['length'])))  # Length
            info_item = QTableWidgetItem(str(row.get('info', '')))
            info_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            self.data_table.setItem(i, 5, info_item)  # Info
        self.data_table.scrollToBottom()

    def preprocess_data(self):
        # 데이터 전처리 로직 구현
        print("데이터 전처리 시작")
        if self.data_table.rowCount() == 0:
            print("데이터가 없습니다.")
            return

        # 테이블 데이터를 DataFrame으로 변환
        data = []
        for row in range(self.data_table.rowCount()):
            data.append({
                'src_ip': self.data_table.item(row, 1).text(),
                'dst_ip': self.data_table.item(row, 2).text(),
                'protocol': int(self.data_table.item(row, 3).text()),
                'length': int(self.data_table.item(row, 4).text()),
                'info': self.data_table.item(row, 5).text()
            })
        df = pd.DataFrame(data)

        # 결측치 처리
        df.fillna(0, inplace=True)

        # 데이터 정규화
        scaler = StandardScaler()
        df[['length']] = scaler.fit_transform(df[['length']])

        # 범주형 데이터 인코딩
        encoder = OneHotEncoder(sparse=False)
        protocol_encoded = encoder.fit_transform(df[['protocol']])
        df = df.drop('protocol', axis=1)
        df = pd.concat([df, pd.DataFrame(protocol_encoded, columns=encoder.get_feature_names_out(['protocol']))], axis=1)

        print("전처리 완료:")
        print(df.head())

        # 파일 저장
        save_path, _ = QFileDialog.getSaveFileName(self, "파일 저장", "", "CSV Files (*.csv);;All Files (*)")
        if save_path:
            df.to_csv(save_path, index=False)
            print(f"전처리된 데이터가 {save_path}에 저장되었습니다.")

    def _get_packet_info(self, packet):
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