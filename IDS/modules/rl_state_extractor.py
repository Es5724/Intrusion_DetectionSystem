# -*- coding: utf-8 -*-

"""
RL 상태 추출기 (RL State Extractor)

실시간 패킷 데이터와 컨텍스트 정보를 Conservative RL 에이전트가 사용할 수 있는
10차원 상태 벡터로 자동 변환합니다.

핵심 기능:
- 패킷 정보 정규화 (크기, 프로토콜, 플래그 등)
- RF 위협 확률 통합
- 시스템 컨텍스트 반영 (시간대, 연결 빈도, 이력 등)
- 포트 위험도 평가
- 페이로드 엔트로피 계산
"""

import numpy as np
import logging
from datetime import datetime
import collections
from typing import Dict, Any, Optional

logger = logging.getLogger('RLStateExtractor')


class RLStateExtractor:
    """
    실시간 패킷 데이터를 RL 에이전트 상태로 변환
    
    상태 벡터 구조 (10차원):
    [0] packet_size_norm: 정규화된 패킷 크기 (0-1)
    [1] protocol_encoded: 프로토콜 인코딩 (TCP=0.33, UDP=0.66, ICMP=1.0)
    [2] threat_probability: RF 모델의 위협 확률 (0-1)
    [3] port_risk_score: 포트 위험도 점수 (0-1)
    [4] connection_frequency: 연결 빈도 점수 (0-1)
    [5] historical_threat_level: 과거 위협 수준 (0-1)
    [6] time_of_day_factor: 시간대 위험 요소 (0-1)
    [7] packet_direction: 방향 (inbound=0.0, outbound=1.0)
    [8] payload_entropy: 페이로드 엔트로피 (0-1)
    [9] service_impact_score: 서비스 영향도 (0-1)
    """
    
    def __init__(self, max_packet_size: int = 65535):
        """
        Args:
            max_packet_size: 패킷 크기 정규화를 위한 최대값 (기본: 65535)
        """
        self.max_packet_size = max_packet_size
        
        # 프로토콜 인코딩 맵
        self.protocol_map = {
            'TCP': 0.33, '6': 0.33, 'tcp': 0.33,
            'UDP': 0.66, '17': 0.66, 'udp': 0.66,
            'ICMP': 1.0, '1': 1.0, 'icmp': 1.0
        }
        
        # 위험 포트 목록 (점수: 0.0 ~ 1.0)
        self.port_risk_map = {
            # 매우 위험 (1.0)
            4444: 1.0,    # 백도어 (Metasploit)
            31337: 1.0,   # Back Orifice
            1337: 1.0,    # 해커 포트
            6667: 0.9,    # IRC (봇넷)
            6666: 0.9,    # IRC 백도어
            
            # 위험 (0.7)
            23: 0.7,      # Telnet (비암호화)
            21: 0.7,      # FTP (비암호화)
            3389: 0.7,    # RDP (공격 대상)
            445: 0.7,     # SMB (랜섬웨어)
            135: 0.6,     # RPC
            
            # 중간 위험 (0.5)
            80: 0.3,      # HTTP (정상이지만 공격 벡터)
            443: 0.2,     # HTTPS (상대적으로 안전)
            22: 0.4,      # SSH (brute-force 대상)
            3306: 0.5,    # MySQL
            5432: 0.5,    # PostgreSQL
            
            # 낮은 위험 (0.2)
            53: 0.2,      # DNS
            123: 0.1,     # NTP
        }
        
        # 시간대별 위험도 (0-23시)
        self.hourly_risk = self._generate_hourly_risk()
        
        # 연결 이력 추적 (IP별)
        self.connection_history = collections.defaultdict(list)
        self.threat_history = collections.defaultdict(list)
        
        # 히스토리 최대 크기
        self.max_history_size = 100
        
        logger.info("RL 상태 추출기 초기화 완료")
    
    def _generate_hourly_risk(self) -> np.ndarray:
        """
        시간대별 위험도 생성
        
        업무 시간(9-18시): 낮은 위험 (0.3)
        저녁 시간(18-24시): 중간 위험 (0.5)
        새벽 시간(0-6시): 높은 위험 (0.8)
        이른 아침(6-9시): 중간 위험 (0.5)
        
        Returns:
            24시간 위험도 배열
        """
        risk = np.zeros(24)
        risk[0:6] = 0.8    # 새벽 (높은 위험)
        risk[6:9] = 0.5    # 이른 아침
        risk[9:18] = 0.3   # 업무 시간 (낮은 위험)
        risk[18:24] = 0.5  # 저녁
        return risk
    
    def extract_state(self, packet_info: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> np.ndarray:
        """
        패킷 정보를 RL 상태 벡터로 변환
        
        Args:
            packet_info: 패킷 정보 딕셔너리
                - source: 출발지 IP
                - destination: 목적지 IP
                - protocol: 프로토콜 (TCP/UDP/ICMP)
                - length: 패킷 크기
                - flags: TCP 플래그
                - info: 추가 정보
                - timestamp: 타임스탬프
            context: 컨텍스트 정보 (옵션)
                - threat_probability: RF 위협 확률
                - connection_frequency: 연결 빈도
                - historical_threat: 과거 위협 수준
                - service_importance: 서비스 중요도
        
        Returns:
            state (numpy.array): [10] 크기의 상태 벡터
        """
        if context is None:
            context = {}
        
        state = np.zeros(10, dtype=np.float32)
        
        try:
            # [0] 패킷 크기 정규화 (0-1)
            packet_length = packet_info.get('length', 0)
            state[0] = min(float(packet_length) / self.max_packet_size, 1.0)
            
            # [1] 프로토콜 인코딩
            protocol = str(packet_info.get('protocol', 'unknown')).upper()
            state[1] = self.protocol_map.get(protocol, 0.0)
            
            # [2] RF 위협 확률 (컨텍스트에서 제공)
            state[2] = float(context.get('threat_probability', 0.0))
            
            # [3] 포트 위험도
            state[3] = self._calculate_port_risk(packet_info)
            
            # [4] 연결 빈도
            state[4] = self._calculate_connection_frequency(packet_info)
            
            # [5] 과거 위협 수준
            state[5] = self._get_historical_threat_level(packet_info, context)
            
            # [6] 시간대 위험 요소
            state[6] = self._get_time_factor()
            
            # [7] 패킷 방향
            state[7] = self._get_packet_direction(packet_info)
            
            # [8] 페이로드 엔트로피
            state[8] = self._calculate_entropy(packet_info)
            
            # [9] 서비스 영향도
            state[9] = self._get_service_impact(packet_info, context)
            
            # NaN/Inf 체크
            state = np.nan_to_num(state, nan=0.0, posinf=1.0, neginf=0.0)
            
            # 범위 체크 (0-1)
            state = np.clip(state, 0.0, 1.0)
            
            logger.debug(f"상태 벡터 생성: {state}")
            return state
            
        except Exception as e:
            logger.error(f"상태 추출 오류: {e}")
            # 오류 발생 시 중립 상태 반환
            return np.full(10, 0.5, dtype=np.float32)
    
    def _calculate_port_risk(self, packet_info: Dict[str, Any]) -> float:
        """포트 위험도 계산"""
        try:
            # destination에서 포트 추출
            destination = str(packet_info.get('destination', ''))
            if ':' in destination:
                port = int(destination.split(':')[1])
                return self.port_risk_map.get(port, 0.1)  # 기본 위험도 0.1
            return 0.1
        except:
            return 0.1
    
    def _calculate_connection_frequency(self, packet_info: Dict[str, Any]) -> float:
        """
        연결 빈도 계산 (최근 60초 내 연결 수 기반)
        
        Returns:
            0.0 ~ 1.0 (높을수록 빈번한 연결)
        """
        try:
            source_ip = packet_info.get('source', 'unknown')
            current_time = packet_info.get('timestamp', datetime.now().timestamp())
            
            # 최근 연결 이력 업데이트
            self.connection_history[source_ip].append(current_time)
            
            # 60초 이전 기록 제거
            cutoff_time = current_time - 60
            self.connection_history[source_ip] = [
                t for t in self.connection_history[source_ip] if t > cutoff_time
            ]
            
            # 연결 수 정규화 (100개 이상 = 1.0)
            connection_count = len(self.connection_history[source_ip])
            return min(connection_count / 100.0, 1.0)
            
        except Exception as e:
            logger.debug(f"연결 빈도 계산 오류: {e}")
            return 0.0
    
    def _get_historical_threat_level(self, packet_info: Dict[str, Any], 
                                     context: Dict[str, Any]) -> float:
        """
        과거 위협 수준 계산
        
        최근 이 IP에서 탐지된 위협의 평균 확률
        """
        try:
            source_ip = packet_info.get('source', 'unknown')
            threat_prob = context.get('threat_probability', 0.0)
            
            # 위협 이력 업데이트 (0.5 이상만)
            if threat_prob >= 0.5:
                self.threat_history[source_ip].append(threat_prob)
                
                # 최대 크기 유지
                if len(self.threat_history[source_ip]) > self.max_history_size:
                    self.threat_history[source_ip].pop(0)
            
            # 이력이 있으면 평균 반환
            if self.threat_history[source_ip]:
                return float(np.mean(self.threat_history[source_ip]))
            
            # 컨텍스트에서 제공된 값 사용 (Fallback)
            return float(context.get('historical_threat', 0.0))
            
        except Exception as e:
            logger.debug(f"과거 위협 수준 계산 오류: {e}")
            return 0.0
    
    def _get_time_factor(self) -> float:
        """현재 시간대의 위험도 반환"""
        try:
            current_hour = datetime.now().hour
            return float(self.hourly_risk[current_hour])
        except:
            return 0.5  # 중립값
    
    def _get_packet_direction(self, packet_info: Dict[str, Any]) -> float:
        """
        패킷 방향 판단
        
        Returns:
            0.0: inbound (외부 → 내부)
            1.0: outbound (내부 → 외부)
        """
        try:
            source = packet_info.get('source', '')
            
            # 내부 IP 범위 체크
            if source.startswith(('192.168.', '10.', '172.16.', '172.17.', 
                                 '172.18.', '172.19.', '172.20.', '172.21.',
                                 '172.22.', '172.23.', '172.24.', '172.25.',
                                 '172.26.', '172.27.', '172.28.', '172.29.',
                                 '172.30.', '172.31.', '127.')):
                return 1.0  # outbound
            else:
                return 0.0  # inbound
        except:
            return 0.5  # 불명확
    
    def _calculate_entropy(self, packet_info: Dict[str, Any]) -> float:
        """
        페이로드 엔트로피 계산 (정보 이론 기반)
        
        높은 엔트로피 = 암호화/압축된 데이터 (정상 또는 악성)
        낮은 엔트로피 = 일반 텍스트 (정상 가능성 높음)
        
        Returns:
            0.0 ~ 1.0 (정규화된 엔트로피)
        """
        try:
            # raw_data 또는 info에서 페이로드 추출
            payload = packet_info.get('raw_data', packet_info.get('info', ''))
            
            if not payload or len(payload) < 10:
                return 0.3  # 작은 패킷은 중립값
            
            # 바이트 빈도 계산
            byte_counts = collections.Counter(str(payload).encode('utf-8', errors='ignore'))
            total_bytes = sum(byte_counts.values())
            
            if total_bytes == 0:
                return 0.3
            
            # 샤논 엔트로피 계산
            entropy = 0.0
            for count in byte_counts.values():
                probability = count / total_bytes
                if probability > 0:
                    entropy -= probability * np.log2(probability)
            
            # 정규화 (최대 엔트로피 = 8 bits)
            normalized_entropy = entropy / 8.0
            
            return min(normalized_entropy, 1.0)
            
        except Exception as e:
            logger.debug(f"엔트로피 계산 오류: {e}")
            return 0.3
    
    def _get_service_impact(self, packet_info: Dict[str, Any], 
                           context: Dict[str, Any]) -> float:
        """
        서비스 영향도 평가
        
        중요 서비스 포트일수록 높은 점수
        """
        try:
            # 컨텍스트에서 제공된 값 우선
            service_importance = context.get('service_importance')
            if service_importance is not None:
                return float(service_importance)
            
            # 포트 기반 중요도 계산
            destination = str(packet_info.get('destination', ''))
            if ':' not in destination:
                return 0.5
            
            port = int(destination.split(':')[1])
            
            # 중요 서비스 포트
            critical_ports = {
                80: 0.9,    # HTTP (웹 서비스)
                443: 0.9,   # HTTPS (웹 서비스)
                22: 0.8,    # SSH (관리)
                3306: 0.7,  # MySQL (DB)
                5432: 0.7,  # PostgreSQL (DB)
                53: 0.6,    # DNS
                25: 0.6,    # SMTP (메일)
            }
            
            return critical_ports.get(port, 0.5)
            
        except Exception as e:
            logger.debug(f"서비스 영향도 계산 오류: {e}")
            return 0.5
    
    def reset_history(self, ip_address: Optional[str] = None):
        """
        연결 이력 초기화
        
        Args:
            ip_address: 특정 IP의 이력만 초기화 (None이면 전체)
        """
        if ip_address:
            if ip_address in self.connection_history:
                del self.connection_history[ip_address]
            if ip_address in self.threat_history:
                del self.threat_history[ip_address]
            logger.info(f"{ip_address} 이력 초기화")
        else:
            self.connection_history.clear()
            self.threat_history.clear()
            logger.info("전체 이력 초기화")
    
    def get_statistics(self) -> Dict[str, Any]:
        """현재 추적 중인 통계 반환"""
        return {
            'tracked_ips': len(self.connection_history),
            'total_connections': sum(len(v) for v in self.connection_history.values()),
            'threat_records': sum(len(v) for v in self.threat_history.values()),
            'high_threat_ips': sum(1 for threats in self.threat_history.values() 
                                  if threats and np.mean(threats) > 0.7)
        }


# 전역 싱글톤 인스턴스
_global_extractor = None


def get_state_extractor() -> RLStateExtractor:
    """
    전역 상태 추출기 인스턴스 반환 (싱글톤 패턴)
    
    Returns:
        RLStateExtractor 인스턴스
    """
    global _global_extractor
    if _global_extractor is None:
        _global_extractor = RLStateExtractor()
    return _global_extractor

