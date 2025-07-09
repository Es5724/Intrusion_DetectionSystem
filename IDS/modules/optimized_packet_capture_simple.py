"""
간소화된 최적화 패킷 캡처 모듈
- 호환성 중심
- 안정성 우선
- 기본적인 멀티스레딩만 사용
"""

import os
import queue
import threading
import time
import psutil
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
import numpy as np
import gc

# 플랫폼별 임포트
if os.name == 'nt':
    import winreg


class OptimizedPacketCapture:
    """최적화된 패킷 캡처 시스템 - 간소화 버전"""
    
    def __init__(self, num_workers=None):
        # 기본 속성들 (PacketCaptureCore와 동일)
        self.packet_queue = queue.Queue(maxsize=10000)
        self.is_running = False
        self.packet_count = 0
        self.max_packets = 300000
        self.sniff_thread = None
        self.capture_completed = False
        self.defense_callback = None
        self.enable_defense = False
        self.active_interface = None
        
        # 최적화 관련 속성
        self.num_workers = num_workers or max(1, min(4, os.cpu_count() - 1))
        self.processing_threads = []
        self.processed_queue = queue.Queue(maxsize=50000)
        
        # 통계
        self.stats = {
            'packets_captured': 0,
            'packets_processed': 0,
            'packets_dropped': 0
        }
        
        # 적응형 샘플링
        self.sampling_rate = 1.0
        self.last_cpu_check = time.time()
        
        print(f"최적화된 패킷 캡처 초기화 (워커: {self.num_workers}개)")
    
    def check_npcap(self):
        """Npcap 설치 여부 확인"""
        if os.name != 'nt':
            return True
            
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Npcap')
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            pass
            
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Npcap')
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            pass
            
        default_path = os.path.join(os.environ.get('SystemRoot', 'C:\Windows'), 'System32', 'Npcap')
        return os.path.exists(default_path)
    
    def get_network_interfaces(self):
        """네트워크 인터페이스 목록 반환"""
        interfaces = psutil.net_if_addrs()
        return list(interfaces.keys())
    
    def get_packet_count(self):
        """캡처된 패킷 수 반환"""
        return self.stats['packets_captured']
    
    def get_active_interface(self):
        """현재 활성화된 인터페이스 반환"""
        return self.active_interface
    
    def register_defense_module(self, callback_function):
        """방어 모듈 콜백 함수 등록"""
        self.defense_callback = callback_function
        self.enable_defense = True
        print("방어 모듈이 패킷 캡처 시스템에 등록되었습니다.")
        return True
    
    def put_packet(self, packet):
        """큐에 패킷 추가"""
        try:
            if not isinstance(packet, dict):
                packet = self._convert_packet_to_dict(packet)
            
            self.packet_queue.put_nowait(packet)
            self.stats['packets_captured'] += 1
            self.packet_count += 1
            return True
        except queue.Full:
            self.stats['packets_dropped'] += 1
            return False
    
    def _convert_packet_to_dict(self, packet):
        """패킷을 딕셔너리로 변환"""
        if isinstance(packet, str):
            return {
                'source': 'unknown',
                'destination': 'unknown',
                'protocol': 'unknown',
                'length': len(packet) if packet else 0,
                'info': packet,
                'raw_data': packet
            }
        else:
            return {
                'source': 'unknown',
                'destination': 'unknown',
                'protocol': 'unknown',
                'length': 0,
                'info': str(packet),
                'raw_data': str(packet)
            }
    
    def packet_callback(self, packet):
        """패킷 캡처 콜백"""
        if not self.is_running:
            return
            
        # 최대 패킷 수 체크
        if self.max_packets > 0 and self.stats['packets_captured'] >= self.max_packets:
            self.is_running = False
            return
            
        # 적응형 샘플링
        if self.sampling_rate < 1.0 and np.random.random() > self.sampling_rate:
            return
            
        try:
            if IP in packet:
                packet_info = {
                    'no': self.stats['packets_captured'] + 1,
                    'source': packet[IP].src,
                    'destination': packet[IP].dst,
                    'protocol': packet[IP].proto,
                    'length': len(packet),
                    'info': str(packet.summary()),
                    'timestamp': time.time()
                }
                
                # 큐에 추가
                self.put_packet(packet_info)
                
                # 방어 모듈 콜백 실행
                if self.enable_defense and self.defense_callback:
                    try:
                        self.defense_callback(packet_info)
                    except Exception as e:
                        # 로그에만 기록 (화면 출력 안 함)
                        import logging
                        logging.getLogger('OptimizedCapture').error(f"방어 모듈 콜백 오류: {e}")
                        
        except Exception as e:
            # 로그에만 기록 (화면 출력 안 함)
            import logging
            logging.getLogger('OptimizedCapture').error(f"패킷 처리 중 오류: {e}")
    
    def processing_worker(self):
        """패킷 처리 워커 스레드"""
        batch = []
        batch_size = 100
        last_process_time = time.time()
        
        while self.is_running or not self.packet_queue.empty():
            try:
                # 큐에서 패킷 가져오기
                packet_info = self.packet_queue.get(timeout=0.1)
                batch.append(packet_info)
                
                # 배치가 가득 차거나 시간이 지나면 처리
                if len(batch) >= batch_size or (time.time() - last_process_time > 0.5):
                    if batch:
                        # 여기서 실제 처리 수행 (예: ML 모델 적용)
                        for item in batch:
                            self.processed_queue.put(item)
                            self.stats['packets_processed'] += 1
                            
                        batch = []
                        last_process_time = time.time()
                        
            except queue.Empty:
                continue
            except Exception as e:
                # 로그에만 기록 (화면 출력 안 함)
                import logging
                logging.getLogger('OptimizedCapture').error(f"처리 워커 오류: {e}")
    
    def adaptive_sampling(self):
        """CPU 부하에 따른 적응형 샘플링"""
        current_time = time.time()
        if current_time - self.last_cpu_check > 1.0:  # 1초마다 체크
            try:
                cpu_percent = psutil.cpu_percent(interval=0.1)
                
                if cpu_percent > 80:
                    self.sampling_rate = max(0.1, self.sampling_rate * 0.8)
                elif cpu_percent < 50:
                    self.sampling_rate = min(1.0, self.sampling_rate * 1.2)
                    
                self.last_cpu_check = current_time
            except:
                pass
    
    def monitor_performance(self):
        """성능 모니터링"""
        while self.is_running:
            time.sleep(5)  # 5초마다
            
            # 적응형 샘플링 조정
            self.adaptive_sampling()
            
            # 통계를 로그에만 기록 (화면 출력 안 함)
            import logging
            logging.getLogger('OptimizedCapture').debug(f"[성능] 캡처: {self.stats['packets_captured']}, "
                  f"처리: {self.stats['packets_processed']}, "
                  f"드롭: {self.stats['packets_dropped']}, "
                  f"샘플링: {self.sampling_rate:.1%}")
            
            # 메모리 정리
            gc.collect()
    
    def start_capture(self, interface, max_packets=0):
        """패킷 캡처 시작"""
        if self.is_running:
            return False
            
        self.is_running = True
        self.active_interface = interface
        self.max_packets = max_packets
        self.packet_count = 0
        
        # 로그에만 기록 (화면 출력 안 함)
        import logging
        logging.getLogger('OptimizedCapture').info(f"패킷 캡처 시작: {interface} (최대: {max_packets if max_packets > 0 else '무제한'})")
        
        # 캡처 스레드 시작
        def capture_thread():
            try:
                sniff(iface=interface, prn=self.packet_callback, store=0,
                      stop_filter=lambda x: not self.is_running)
            except Exception as e:
                # 로그에만 기록 (화면 출력 안 함)
                import logging
                logging.getLogger('OptimizedCapture').error(f"캡처 오류: {e}")
            finally:
                self.is_running = False
                self.capture_completed = True
        
        self.sniff_thread = threading.Thread(target=capture_thread)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        
        # 처리 워커 스레드들 시작
        for i in range(self.num_workers):
            worker_thread = threading.Thread(target=self.processing_worker)
            worker_thread.daemon = True
            worker_thread.start()
            self.processing_threads.append(worker_thread)
        
        # 모니터링 스레드 시작
        monitor_thread = threading.Thread(target=self.monitor_performance)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return True
    
    def stop_capture(self):
        """캡처 중지"""
        # 로그에만 기록 (화면 출력 안 함)
        import logging
        logging.getLogger('OptimizedCapture').info("패킷 캡처 중지 중...")
        self.is_running = False
        
        # 스레드 종료 대기
        if self.sniff_thread:
            self.sniff_thread.join(timeout=5)
            
        for thread in self.processing_threads:
            thread.join(timeout=2)
        
        # 로그에만 기록 (화면 출력 안 함)
        logging.getLogger('OptimizedCapture').info(f"최종 통계 - 캡처: {self.stats['packets_captured']}, "
              f"처리: {self.stats['packets_processed']}, "
              f"드롭: {self.stats['packets_dropped']}")
        
        return self.stats['packets_captured']
    
    def get_packet_dataframe(self):
        """패킷 큐의 데이터를 DataFrame으로 변환"""
        import pandas as pd
        packets = []
        
        while not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get_nowait()
                packets.append(packet)
            except queue.Empty:
                break
                
        return pd.DataFrame(packets) 