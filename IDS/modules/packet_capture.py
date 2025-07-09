import pandas as pd
import numpy as np
import os
import queue
import threading
import time
import winreg
import psutil
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

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

class PacketCaptureCore:
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=100)
        self.is_running = False
        self.packet_count = 0
        self.max_packets = 300000
        self.sniff_thread = None
        self.capture_completed = False
        self.defense_callback = None  # 방어 모듈 콜백 함수
        self.enable_defense = False   # 방어 기능 활성화 여부
        self.active_interface = None  # 현재 사용 중인 인터페이스

    def register_defense_module(self, callback_function):
        """방어 모듈 콜백 함수를 등록합니다."""
        self.defense_callback = callback_function
        self.enable_defense = True
        print("방어 모듈이 패킷 캡처 시스템에 등록되었습니다.")
        return True

    def check_npcap(self):
        """Npcap 설치 여부를 확인합니다."""
        import logging
        # 윈도우 환경이 아닌 경우 Npcap 확인 불필요
        if os.name != 'nt':
            logging.getLogger('PacketCapture').info("윈도우 환경이 아니므로 Npcap 확인을 건너뜁니다.")
            return True
            
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Npcap')
            winreg.CloseKey(key)
            logging.getLogger('PacketCapture').info("Npcap detected in registry: SOFTWARE\\Npcap")
            return True
        except FileNotFoundError:
            logging.getLogger('PacketCapture').debug("Npcap not found in registry: SOFTWARE\\Npcap")
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Npcap')
            winreg.CloseKey(key)
            logging.getLogger('PacketCapture').info("Npcap detected in registry: SOFTWARE\\WOW6432Node\\Npcap")
            return True
        except FileNotFoundError:
            logging.getLogger('PacketCapture').debug("Npcap not found in registry: SOFTWARE\\WOW6432Node\\Npcap")
        default_path = os.path.join(os.environ.get('SystemRoot', 'C:\Windows'), 'System32', 'Npcap')
        if os.path.exists(default_path):
            logging.getLogger('PacketCapture').info(f"Npcap detected in directory: {default_path}")
            return True
        else:
            logging.getLogger('PacketCapture').debug(f"Npcap not found in directory: {default_path}")
        return False

    def get_network_interfaces(self):
        """네트워크 인터페이스 목록을 반환합니다."""
        interfaces = psutil.net_if_addrs()
        return list(interfaces.keys())

    def get_active_interface(self):
        """현재 활성화된 인터페이스 이름을 반환합니다."""
        return self.active_interface

    def put_packet(self, packet):
        """
        큐에 패킷을 안전하게 추가합니다. 문자열이나 다른 타입의 패킷은 딕셔너리로 변환합니다.
        
        Args:
            packet: 추가할 패킷 데이터 (딕셔너리, 문자열 등)
        """
        try:
            # 패킷이 딕셔너리가 아닌 경우 변환
            if not isinstance(packet, dict):
                if isinstance(packet, str):
                    # 문자열을 간단한 딕셔너리로 변환
                    packet = {
                        'source': 'unknown',
                        'destination': 'unknown',
                        'protocol': 'unknown',
                        'length': len(packet) if packet else 0,
                        'info': packet,
                        'raw_data': packet
                    }
                else:
                    # 다른 타입의 경우, 기본 값 딕셔너리 반환
                    packet = {
                        'source': 'unknown',
                        'destination': 'unknown',
                        'protocol': 'unknown',
                        'length': 0,
                        'info': str(packet),
                        'raw_data': str(packet)
                    }
            
            # 큐에 추가
            self.packet_queue.put(packet)
            return True
        except Exception as e:
            import logging
            logging.getLogger('PacketCapture').error(f"패킷 큐 추가 중 오류: {e}")
            return False
            
    def start_capture(self, interface, max_packets):
        """패킷 캡처를 시작합니다."""
        if self.is_running:
            return False
        self.is_running = True
        self.packet_count = 0
        self.max_packets = max_packets
        self.active_interface = interface  # 활성 인터페이스 저장
        import logging
        logging.getLogger('PacketCapture').info(f"Starting packet capture on interface: {interface} with max_packets: {max_packets}")
        
        def packet_callback(packet):
            """패킷 캡처 콜백 함수"""
            if not self.is_running:
                return
            if IP in packet:
                try:
                    packet_info = {
                        'no': self.packet_count + 1,
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': packet[IP].proto,
                        'length': len(packet),
                        'info': str(packet.summary())
                    }
                    # 안전한 큐 추가 함수 사용
                    self.put_packet(packet_info)
                    self.packet_count += 1
                    import logging
                    logging.getLogger('PacketCapture').debug(f"디버그: 패킷 캡처됨 - {self.packet_count}번째 패킷")
                    
                    # 방어 모듈 콜백 함수가 등록되었고 활성화되어 있으면 실행
                    if self.enable_defense and self.defense_callback:
                        # 전처리된 패킷을 방어 모듈로 직접 전달
                        self.defense_callback(packet_info)
                        
                except Exception as e:
                    import logging
                    logging.getLogger('PacketCapture').error(f"디버그: 패킷 처리 중 오류 발생: {str(e)}")
        
        def capture():
            try:
                import logging
                logging.getLogger('PacketCapture').debug(f"디버그: 캡처 스레드 시작 - 인터페이스: {interface}")
                sniff(iface=interface, prn=packet_callback, store=0, stop_filter=lambda x: not self.is_running)
                logging.getLogger('PacketCapture').debug("디버그: 캡처 스레드 종료")
            except Exception as e:
                import logging
                logging.getLogger('PacketCapture').error(f"디버그: 캡처 중 오류 발생: {str(e)}")
            finally:
                self.is_running = False
                self.capture_completed = True
        
        self.sniff_thread = threading.Thread(target=capture)
        self.sniff_thread.daemon = True
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
            # 안전한 큐 추가 함수 사용
            self.put_packet(packet_info)
            self.packet_count += 1

    def get_packet_queue(self):
        """패킷 큐를 반환합니다."""
        return self.packet_queue

    def get_packet_count(self):
        """캡처된 패킷 수를 반환합니다."""
        return self.packet_count

    def stop_capture(self):
        """패킷 캡처를 중지하고 캡처된 패킷 수를 반환합니다."""
        import logging
        logging.getLogger('PacketCapture').info("Stopping packet capture...")
        self.is_running = False
        if self.sniff_thread is not None:
            self.sniff_thread.join()
        logging.getLogger('PacketCapture').info(f"Packet capture stopped. Total packets captured: {self.packet_count}")
        return self.packet_count

    def get_packet_dataframe(self):
        """패킷 큐에 있는 데이터를 DataFrame으로 변환합니다."""
        packets = []
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            packets.append(packet)
        return pd.DataFrame(packets)

def preprocess_packet_data(df):
    """패킷 데이터 전처리 함수"""
    import logging
    logging.getLogger('PacketCapture').debug("디버그: 전처리 시작 - 입력 데이터 크기: %s", df.shape)
    
    # 필요한 전처리 작업 수행
    if 'protocol' in df.columns:
        logging.getLogger('PacketCapture').debug("디버그: 프로토콜 매핑 시작")
        # 프로토콜 번호를 이름으로 매핑
        protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        df['protocol'] = df['protocol'].map(protocol_map).fillna('Other')
        logging.getLogger('PacketCapture').debug("디버그: 프로토콜 매핑 완료")
    
    if 'source' in df.columns and 'destination' in df.columns:
        logging.getLogger('PacketCapture').debug("디버그: IP 주소 정규화 시작")
        # IP 주소 정규화
        df['source'] = df['source'].apply(lambda x: x.split(':')[0] if ':' in x else x)
        df['destination'] = df['destination'].apply(lambda x: x.split(':')[0] if ':' in x else x)
        logging.getLogger('PacketCapture').debug("디버그: IP 주소 정규화 완료")
    
    logging.getLogger('PacketCapture').debug("디버그: 전처리 완료 - 출력 데이터 크기: %s", df.shape)
    return df 