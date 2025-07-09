import pandas as pd
import numpy as np
import os
import queue
import threading
import multiprocessing as mp
from multiprocessing import Queue, Pool, Manager
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import time
import psutil
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import deque
import gc
import mmap
import struct
import pickle

# 플랫폼별 임포트
if os.name == 'nt':
    import winreg


class RingBuffer:
    """고성능 링 버퍼 구현 - 메모리 효율적인 순환 버퍼"""
    
    def __init__(self, max_size=1048576):  # 1MB 기본값
        self.max_size = max_size
        self.buffer = bytearray(max_size)
        self.write_pos = 0
        self.read_pos = 0
        self.size = 0
        self.lock = threading.Lock()
        
    def write(self, data):
        """데이터를 링 버퍼에 쓰기"""
        data_bytes = pickle.dumps(data)
        data_len = len(data_bytes)
        
        if data_len > self.max_size:
            return False
            
        with self.lock:
            # 헤더(4바이트)에 데이터 길이 저장
            header = struct.pack('I', data_len)
            
            # 순환 쓰기
            for byte in header + data_bytes:
                self.buffer[self.write_pos] = byte
                self.write_pos = (self.write_pos + 1) % self.max_size
                
            self.size = min(self.size + data_len + 4, self.max_size)
            return True
            
    def read(self):
        """링 버퍼에서 데이터 읽기"""
        with self.lock:
            if self.size == 0:
                return None
                
            # 헤더 읽기
            header_bytes = bytes([self.buffer[(self.read_pos + i) % self.max_size] for i in range(4)])
            data_len = struct.unpack('I', header_bytes)[0]
            self.read_pos = (self.read_pos + 4) % self.max_size
            
            # 데이터 읽기
            data_bytes = bytes([self.buffer[(self.read_pos + i) % self.max_size] for i in range(data_len)])
            self.read_pos = (self.read_pos + data_len) % self.max_size
            
            self.size -= (data_len + 4)
            return pickle.loads(data_bytes)


class MemoryPool:
    """사전 할당된 메모리 풀로 할당/해제 오버헤드 최소화"""
    
    def __init__(self, block_size=1024, num_blocks=1000):
        self.block_size = block_size
        self.num_blocks = num_blocks
        self.pool = [bytearray(block_size) for _ in range(num_blocks)]
        self.available = deque(range(num_blocks))
        self.used = set()
        self.lock = threading.Lock()
        
    def allocate(self):
        """메모리 블록 할당"""
        with self.lock:
            if self.available:
                block_id = self.available.popleft()
                self.used.add(block_id)
                return block_id, self.pool[block_id]
            return None, None
            
    def deallocate(self, block_id):
        """메모리 블록 반환"""
        with self.lock:
            if block_id in self.used:
                self.used.remove(block_id)
                self.available.append(block_id)
                # 메모리 초기화
                self.pool[block_id][:] = bytearray(self.block_size)


class OptimizedPacketCapture:
    """최적화된 멀티프로세싱 패킷 캡처 시스템"""
    
    def __init__(self, num_workers=None):
        # CPU 코어 수에 따른 워커 수 결정
        self.num_workers = num_workers or max(1, mp.cpu_count() - 1)
        
        # 기본 속성들 추가 (PacketCaptureCore와 호환성)
        self.packet_count = 0
        self.max_packets = 300000
        self.capture_completed = False
        self.defense_callback = None
        self.enable_defense = False
        self.active_interface = None
        
        # 멀티프로세싱 매니저로 공유 자원 관리
        self.manager = Manager()
        
        # 적응형 큐 크기 (시작은 10000)
        self.packet_queue = self.manager.Queue(maxsize=10000)
        self.processed_queue = self.manager.Queue(maxsize=50000)
        
        # 통계 정보
        self.stats = self.manager.dict({
            'packets_captured': 0,
            'packets_processed': 0,
            'packets_dropped': 0,
            'queue_size': 10000
        })
        
        # 링 버퍼와 메모리 풀
        self.ring_buffer = RingBuffer(max_size=10485760)  # 10MB
        self.memory_pool = MemoryPool(block_size=2048, num_blocks=5000)
        
        # 프로세스 풀
        self.process_pool = ProcessPoolExecutor(max_workers=self.num_workers)
        self.thread_pool = ThreadPoolExecutor(max_workers=self.num_workers * 2)
        
        # 제어 변수
        self.is_running = False
        self.capture_thread = None
        self.processing_threads = []
        
        # 적응형 샘플링
        self.sampling_rate = 1.0  # 시작은 100%
        self.last_cpu_check = time.time()
        
    def adaptive_queue_sizing(self):
        """큐 크기를 동적으로 조정"""
        drop_rate = self.stats['packets_dropped'] / max(1, self.stats['packets_captured'])
        current_size = self.stats['queue_size']
        
        if drop_rate > 0.01:  # 1% 이상 드롭
            new_size = min(current_size * 1.5, 100000)
            # 새로운 큐 생성 (크기 변경은 새 큐 필요)
            old_queue = self.packet_queue
            self.packet_queue = self.manager.Queue(maxsize=int(new_size))
            
            # 기존 데이터 이전
            while not old_queue.empty():
                try:
                    self.packet_queue.put_nowait(old_queue.get_nowait())
                except:
                    break
                    
            self.stats['queue_size'] = new_size
            print(f"큐 크기 증가: {current_size} -> {new_size}")
            
    def adaptive_sampling(self):
        """CPU 부하에 따른 적응형 샘플링"""
        current_time = time.time()
        if current_time - self.last_cpu_check > 1.0:  # 1초마다 체크
            cpu_percent = psutil.cpu_percent(interval=0.1)
            
            if cpu_percent > 80:
                self.sampling_rate = max(0.1, self.sampling_rate * 0.8)
            elif cpu_percent < 50:
                self.sampling_rate = min(1.0, self.sampling_rate * 1.2)
                
            self.last_cpu_check = current_time
            
    def packet_callback(self, packet):
        """패킷 캡처 콜백 - 최적화됨"""
        if not self.is_running:
            return False
            
        # 최대 패킷 수 체크
        if self.max_packets != float('inf') and self.stats['packets_captured'] >= self.max_packets:
            self.is_running = False
            return False
            
        # 적응형 샘플링
        if np.random.random() > self.sampling_rate:
            return True
            
        try:
            # 메모리 풀에서 블록 할당
            block_id, buffer = self.memory_pool.allocate()
            if buffer is None:
                self.stats['packets_dropped'] += 1
                return True
                
            # Zero-copy 패킷 정보 추출
            if IP in packet:
                packet_info = {
                    'timestamp': time.time(),
                    'source': packet[IP].src,
                    'destination': packet[IP].dst,
                    'protocol': packet[IP].proto,
                    'length': len(packet),
                    'ttl': packet[IP].ttl,
                    'flags': self._extract_flags_fast(packet),
                    'block_id': block_id  # 메모리 블록 ID 저장
                }
                
                # 링 버퍼에 쓰기 시도
                if not self.ring_buffer.write(packet_info):
                    # 실패 시 큐에 직접 추가
                    self.packet_queue.put_nowait(packet_info)
                    
                self.stats['packets_captured'] += 1
                
                # 방어 모듈 콜백 실행
                if self.enable_defense and self.defense_callback:
                    try:
                        self.defense_callback(packet_info)
                    except Exception as e:
                        print(f"방어 모듈 콜백 오류: {e}")
                
        except queue.Full:
            self.stats['packets_dropped'] += 1
            if block_id is not None:
                self.memory_pool.deallocate(block_id)
        except Exception as e:
            if block_id is not None:
                self.memory_pool.deallocate(block_id)
                
        return True
        
    def _extract_flags_fast(self, packet):
        """빠른 플래그 추출"""
        if TCP in packet:
            return packet[TCP].flags
        return 0
        
    def process_packets_batch(self, batch):
        """배치 단위 패킷 처리 - 워커 프로세스에서 실행"""
        processed_batch = []
        
        for packet_info in batch:
            # 여기서 실제 처리 로직 수행
            # ML 모델 적용, 특성 추출 등
            processed_info = packet_info.copy()
            processed_info['processed'] = True
            processed_batch.append(processed_info)
            
            # 메모리 블록 반환
            if 'block_id' in packet_info:
                self.memory_pool.deallocate(packet_info['block_id'])
                
        return processed_batch
        
    def processing_worker(self):
        """패킷 처리 워커 스레드"""
        batch = []
        batch_size = 100
        last_process_time = time.time()
        
        while self.is_running or not self.packet_queue.empty():
            try:
                # 링 버퍼에서 먼저 읽기 시도
                packet_info = self.ring_buffer.read()
                if packet_info is None:
                    # 큐에서 읽기
                    packet_info = self.packet_queue.get(timeout=0.1)
                    
                batch.append(packet_info)
                
                # 배치가 가득 차거나 시간이 지나면 처리
                if len(batch) >= batch_size or (time.time() - last_process_time > 0.5):
                    if batch:
                        # 프로세스 풀에서 병렬 처리
                        future = self.process_pool.submit(self.process_packets_batch, batch)
                        processed_batch = future.result()
                        
                        # 처리된 패킷 저장
                        for item in processed_batch:
                            self.processed_queue.put(item)
                            self.stats['packets_processed'] += 1
                            
                        batch = []
                        last_process_time = time.time()
                        
            except queue.Empty:
                continue
            except Exception as e:
                print(f"처리 워커 오류: {e}")
                
    def start_capture(self, interface, max_packets=0):
        """최적화된 패킷 캡처 시작"""
        if self.is_running:
            return False
            
        self.is_running = True
        self.active_interface = interface
        self.max_packets = max_packets if max_packets > 0 else float('inf')
        
        # 캡처 스레드 시작
        def capture_thread():
            try:
                sniff(iface=interface, prn=self.packet_callback, store=0,
                      stop_filter=lambda x: not self.is_running)
            except Exception as e:
                print(f"캡처 오류: {e}")
            finally:
                self.is_running = False
                
        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
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
        
        print(f"최적화된 캡처 시작: {self.num_workers}개 워커 사용")
        return True
        
    def monitor_performance(self):
        """성능 모니터링 및 자동 조정"""
        while self.is_running:
            time.sleep(5)  # 5초마다 체크
            
            # 적응형 큐 크기 조정
            self.adaptive_queue_sizing()
            
            # 적응형 샘플링 조정
            self.adaptive_sampling()
            
            # 통계 출력
            print(f"캡처: {self.stats['packets_captured']}, "
                  f"처리: {self.stats['packets_processed']}, "
                  f"드롭: {self.stats['packets_dropped']}, "
                  f"샘플링: {self.sampling_rate:.1%}")
            
            # 메모리 정리
            gc.collect()
            
    def stop_capture(self):
        """캡처 중지 및 리소스 정리"""
        print("캡처 중지 중...")
        self.is_running = False
        
        # 스레드 종료 대기
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
            
        for thread in self.processing_threads:
            thread.join(timeout=2)
            
        # 프로세스 풀 종료
        self.process_pool.shutdown(wait=True)
        self.thread_pool.shutdown(wait=True)
        
        print(f"최종 통계 - 캡처: {self.stats['packets_captured']}, "
              f"처리: {self.stats['packets_processed']}, "
              f"드롭: {self.stats['packets_dropped']}")
        
        return self.stats['packets_processed']
    
    # PacketCaptureCore와의 호환성을 위한 메서드들
    def check_npcap(self):
        """Npcap 설치 여부 확인 (Windows)"""
        if os.name != 'nt':
            return True
            
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Npcap')
            winreg.CloseKey(key)
            return True
        except:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Npcap')
                winreg.CloseKey(key)
                return True
            except:
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
        """큐에 패킷 추가 (호환성)"""
        try:
            self.packet_queue.put_nowait(packet)
            self.stats['packets_captured'] += 1
            return True
        except:
            self.stats['packets_dropped'] += 1
            return False 