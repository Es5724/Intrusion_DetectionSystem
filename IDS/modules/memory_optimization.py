"""
메모리 최적화 모듈 - 객체 풀링 구현
안전성을 최우선으로 하는 간단한 구현
"""

import threading
from collections import deque
import time
import logging
import numpy as np

logger = logging.getLogger('MemoryOptimization')


class PacketObjectPool:
    """
    패킷 딕셔너리 객체를 재사용하는 간단한 풀링 시스템
    
    특징:
    - 스레드 안전성 보장
    - 자동 크기 조정
    - 간단한 인터페이스
    """
    
    def __init__(self, initial_size=100, max_size=5000):
        """
        Args:
            initial_size: 초기 풀 크기
            max_size: 최대 풀 크기 (메모리 제한)
        """
        self.initial_size = initial_size
        self.max_size = max_size
        self.pool = deque()
        self.lock = threading.Lock()
        self.total_created = 0
        self.total_reused = 0
        
        # 초기 객체 생성
        self._initialize_pool()
        
    def _initialize_pool(self):
        """초기 객체들을 풀에 생성"""
        for _ in range(self.initial_size):
            obj = self._create_new_object()
            self.pool.append(obj)
            
    def _create_new_object(self):
        """새로운 패킷 딕셔너리 생성"""
        self.total_created += 1
        return {
            'source': '',
            'destination': '',
            'protocol': 0,
            'length': 0,
            'ttl': 0,
            'flags': 0,
            'info': '',
            'timestamp': 0.0
        }
    
    def get(self):
        """풀에서 객체 가져오기 (기존 코드와 호환되도록 간단히)"""
        with self.lock:
            if self.pool:
                self.total_reused += 1
                return self.pool.popleft()
            else:
                # 풀이 비어있으면 새로 생성
                return self._create_new_object()
    
    def put(self, obj):
        """객체를 풀에 반환"""
        if not isinstance(obj, dict):
            return
            
        with self.lock:
            # 풀이 최대 크기를 초과하지 않도록
            if len(self.pool) < self.max_size:
                # 객체 초기화
                obj.clear()
                obj.update({
                    'source': '',
                    'destination': '',
                    'protocol': 0,
                    'length': 0,
                    'ttl': 0,
                    'flags': 0,
                    'info': '',
                    'timestamp': 0.0
                })
                self.pool.append(obj)
    
    def get_stats(self):
        """풀 통계 반환"""
        with self.lock:
            return {
                'pool_size': len(self.pool),
                'total_created': self.total_created,
                'total_reused': self.total_reused,
                'reuse_rate': (self.total_reused / max(1, self.total_created + self.total_reused)) * 100
            }


class ProtocolStatsPool:
    """프로토콜 통계 딕셔너리 전용 풀"""
    
    def __init__(self, size=10):
        self.pool = deque()
        self.lock = threading.Lock()
        
        # 프로토콜 통계 딕셔너리 미리 생성
        for _ in range(size):
            self.pool.append({'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0})
    
    def get(self):
        """통계 딕셔너리 가져오기"""
        with self.lock:
            if self.pool:
                return self.pool.popleft()
            else:
                return {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
    
    def put(self, stats_dict):
        """통계 딕셔너리 반환"""
        with self.lock:
            if len(self.pool) < 10:
                # 값 초기화
                for key in stats_dict:
                    stats_dict[key] = 0
                self.pool.append(stats_dict)


# 전역 풀 인스턴스 (싱글톤 패턴)
_packet_pool = None
_stats_pool = None


def get_packet_pool():
    """전역 패킷 풀 반환"""
    global _packet_pool
    if _packet_pool is None:
        _packet_pool = PacketObjectPool(initial_size=200, max_size=5000)
    return _packet_pool


def get_stats_pool():
    """전역 통계 풀 반환"""
    global _stats_pool
    if _stats_pool is None:
        _stats_pool = ProtocolStatsPool(size=5)
    return _stats_pool


class DataFramePool:
    """
    pandas DataFrame과 numpy 배열을 위한 메모리 풀
    가장 큰 메모리 소비자인 DataFrame 처리를 최적화
    """
    
    def __init__(self, max_rows=200, max_columns=10, pool_size=5):
        self.max_rows = max_rows
        self.max_columns = max_columns
        self.pool_size = pool_size
        self.available_arrays = deque()
        self.lock = threading.Lock()
        self.total_created = 0
        self.total_reused = 0
        
        # numpy 배열을 미리 생성하여 풀에 저장
        for _ in range(pool_size):
            # 2D numpy 배열 생성 (object dtype으로 다양한 데이터 타입 지원)
            array = np.empty((max_rows, max_columns), dtype=object)
            self.available_arrays.append(array)
            self.total_created += 1
    
    def get_array(self, rows, columns):
        """풀에서 numpy 배열 가져오기"""
        with self.lock:
            if (self.available_arrays and 
                rows <= self.max_rows and 
                columns <= self.max_columns):
                
                array = self.available_arrays.popleft()
                self.total_reused += 1
                
                # 크기 정보와 함께 반환 (튜플로 래핑)
                return array, rows, columns
            else:
                # 풀이 비어있거나 크기가 맞지 않으면 새로 생성
                self.total_created += 1
                new_array = np.empty((rows, columns), dtype=object)
                return new_array, rows, columns
    
    def put_array(self, array):
        """배열을 풀에 반환"""
        with self.lock:
            if len(self.available_arrays) < self.pool_size:
                # 배열 초기화
                if hasattr(array, 'fill'):
                    array.fill(None)
                self.available_arrays.append(array)
    
    def get_stats(self):
        """풀 통계"""
        with self.lock:
            return {
                'total_created': self.total_created,
                'total_reused': self.total_reused,
                'pool_size': len(self.available_arrays),
                'reuse_rate': (self.total_reused / max(1, self.total_created + self.total_reused)) * 100
            }


class BatchProcessor:
    """
    대용량 데이터를 작은 배치로 나누어 처리하여 메모리 사용량 제어
    """
    
    def __init__(self, batch_size=50):  # 200에서 50으로 감소
        self.batch_size = batch_size
        self.array_pool = DataFramePool(max_rows=batch_size, pool_size=3)
        
    def process_packets_optimized(self, packet_list, processor_func):
        """패킷 리스트를 배치 단위로 처리"""
        results = []
        
        for i in range(0, len(packet_list), self.batch_size):
            batch = packet_list[i:i + self.batch_size]
            
            # numpy 배열로 직접 처리 (DataFrame 우회)
            batch_array = self.array_pool.get_array(len(batch), 8)  # 8개 컬럼
            
            try:
                # 패킷 데이터를 numpy 배열에 직접 복사
                for j, packet in enumerate(batch):
                    batch_array[j, 0] = packet.get('source', '')
                    batch_array[j, 1] = packet.get('destination', '')
                    batch_array[j, 2] = packet.get('protocol', 0)
                    batch_array[j, 3] = packet.get('length', 0)
                    batch_array[j, 4] = packet.get('ttl', 0)
                    batch_array[j, 5] = packet.get('flags', 0)
                    batch_array[j, 6] = packet.get('info', '')
                    batch_array[j, 7] = packet.get('timestamp', 0.0)
                
                # 처리 함수 실행
                result = processor_func(batch_array[:len(batch)])
                results.extend(result)
                
            finally:
                # 배열을 풀에 반환
                self.array_pool.put_array(batch_array)
        
        return results


# 전역 인스턴스들
_dataframe_pool = None
_batch_processor = None


def get_dataframe_pool():
    """전역 DataFrame 풀 반환"""
    global _dataframe_pool
    if _dataframe_pool is None:
        _dataframe_pool = DataFramePool(max_rows=200, pool_size=3)
    return _dataframe_pool


def get_batch_processor():
    """전역 배치 프로세서 반환"""
    global _batch_processor
    if _batch_processor is None:
        _batch_processor = BatchProcessor(batch_size=50)
    return _batch_processor 