#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
시스템 상수 정의 모듈

설정 파일 기반으로 시스템 전역 상수를 관리합니다.
하드코딩을 제거하고 설정 파일을 통한 동적 구성을 지원합니다.
"""

import os
import logging
from typing import Optional
from pathlib import Path

logger = logging.getLogger('SystemConstants')


class SystemConstants:
    """설정 파일 기반 시스템 상수
    
    unified_config.yaml 파일로부터 시스템 상수를 로드하고,
    애플리케이션 전체에서 일관된 상수 값을 제공합니다.
    
    Attributes:
        PACKET_SIZE_CRITICAL: 치명적 위협으로 분류할 패킷 크기
        PACKET_SIZE_HIGH: 높은 위협으로 분류할 패킷 크기
        PACKET_SIZE_MEDIUM: 중간 위협으로 분류할 패킷 크기
        THREAT_SCORE_CRITICAL: 치명적 위협 점수 임계값
        THREAT_SCORE_HIGH: 높은 위협 점수 임계값
        THREAT_SCORE_MEDIUM: 중간 위협 점수 임계값
        CPU_HIGH_THRESHOLD: CPU 고부하 임계값 (%)
        CPU_LOW_THRESHOLD: CPU 저부하 임계값 (%)
        MEMORY_HIGH_MB: 메모리 고사용 임계값 (MB)
        MEMORY_LOW_MB: 메모리 저사용 임계값 (MB)
        MAX_QUEUE_SIZE: 최대 큐 크기
        ADAPTIVE_PROCESS_MAX: 적응형 처리 최대 개수
        ADAPTIVE_PROCESS_MEDIUM: 적응형 처리 중간 개수
        ADAPTIVE_PROCESS_NORMAL: 적응형 처리 기본 개수
        DASHBOARD_REFRESH_SECONDS: 대시보드 갱신 주기 (초)
        PACKET_PROCESS_SLEEP_MS: 패킷 처리 대기 시간 (밀리초)
        MEMORY_CLEANUP_INTERVAL_SECONDS: 메모리 정리 주기 (초)
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """SystemConstants 초기화
        
        Args:
            config_path: 설정 파일 경로 (기본값: config/unified_config.yaml)
        """
        self.config = None
        self.config_path = config_path or self._find_config_path()
        
        # 설정 로드 시도
        self._load_config()
        
        # 상수 로드
        self._load_constants()
        
        logger.info(f"SystemConstants 초기화 완료 (config: {self.config_path})")
    
    def _find_config_path(self) -> str:
        """설정 파일 경로 자동 탐색"""
        possible_paths = [
            'config/unified_config.yaml',
            'IDS/config/unified_config.yaml',
            '../config/unified_config.yaml',
            os.path.join(os.path.dirname(__file__), '..', 'config', 'unified_config.yaml')
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # 설정 파일이 없으면 기본 경로 반환 (나중에 생성됨)
        logger.warning("설정 파일을 찾을 수 없습니다. 기본값을 사용합니다.")
        return 'config/unified_config.yaml'
    
    def _load_config(self):
        """설정 파일 로드"""
        try:
            # config_loader를 지연 로딩 (순환 참조 방지)
            # 상대 import 시도 -> 실패 시 절대 import
            try:
                from .config_loader import get_config
            except (ImportError, ValueError):
                from config_loader import get_config
            
            if os.path.exists(self.config_path):
                self.config = get_config(self.config_path)
                logger.info(f"설정 파일 로드 성공: {self.config_path}")
            else:
                logger.warning(f"설정 파일이 없습니다: {self.config_path}. 기본값 사용")
                self.config = None
                
        except Exception as e:
            logger.error(f"설정 파일 로드 실패: {e}. 기본값 사용")
            self.config = None
    
    def _load_constants(self):
        """설정으로부터 상수 로드"""
        # 위협 분석 임계값
        self.PACKET_SIZE_CRITICAL = self._get('monitoring.threat_analysis.packet_size_critical', 8000)
        self.PACKET_SIZE_HIGH = self._get('monitoring.threat_analysis.packet_size_high', 5000)
        self.PACKET_SIZE_MEDIUM = self._get('monitoring.threat_analysis.packet_size_medium', 3000)
        self.PACKET_SIZE_NORMAL = self._get('monitoring.threat_analysis.packet_size_normal', 1500)
        
        self.THREAT_SCORE_CRITICAL = self._get('monitoring.threat_analysis.threat_score_critical', 0.9)
        self.THREAT_SCORE_HIGH = self._get('monitoring.threat_analysis.threat_score_high', 0.8)
        self.THREAT_SCORE_MEDIUM = self._get('monitoring.threat_analysis.threat_score_medium', 0.7)
        self.THREAT_SCORE_LOW = self._get('monitoring.threat_analysis.threat_score_low', 0.6)
        
        # 리소스 모니터링 임계값
        self.CPU_HIGH_THRESHOLD = self._get('monitoring.performance.cpu_threshold_percent', 80)
        self.CPU_LOW_THRESHOLD = self._get('monitoring.performance.cpu_low_threshold', 30)
        self.MEMORY_HIGH_MB = self._get('monitoring.performance.memory_high_mb', 800)
        self.MEMORY_LOW_MB = self._get('monitoring.performance.memory_low_mb', 500)
        
        # 큐 처리 설정
        self.MAX_QUEUE_SIZE = self._get('monitoring.queue.max_size', 50000)
        self.ADAPTIVE_PROCESS_MAX = self._get('monitoring.queue.adaptive_process_max', 1500)
        self.ADAPTIVE_PROCESS_MEDIUM = self._get('monitoring.queue.adaptive_process_medium', 800)
        self.ADAPTIVE_PROCESS_NORMAL = self._get('monitoring.queue.adaptive_process_normal', 150)
        self.ADAPTIVE_PROCESS_MIN = self._get('monitoring.queue.adaptive_process_min', 50)
        
        # 큐 사용률 임계값
        self.QUEUE_UTILIZATION_HIGH = self._get('monitoring.queue.utilization_high', 0.8)
        self.QUEUE_UTILIZATION_MEDIUM = self._get('monitoring.queue.utilization_medium', 0.5)
        
        # 타이밍 설정
        self.DASHBOARD_REFRESH_SECONDS = self._get('monitoring.timing.dashboard_refresh_seconds', 1.0)
        self.PACKET_PROCESS_SLEEP_MS = self._get('monitoring.timing.packet_process_sleep_ms', 10)
        self.MEMORY_CLEANUP_INTERVAL_SECONDS = self._get('monitoring.timing.memory_cleanup_interval_seconds', 60)
        self.STATS_UPDATE_INTERVAL_SECONDS = self._get('monitoring.timing.stats_update_interval_seconds', 1.0)
        
        # 메모리 관리 설정
        self.GC_COLLECTION_ROUNDS = self._get('advanced.memory.gc_collection_rounds', 3)
        self.MEMORY_HIGH_THRESHOLD_MB = self._get('advanced.memory.high_threshold_mb', 150)
        
        # 로깅 설정
        self.MAX_LOG_CACHE_SIZE = self._get('advanced.logging.max_cache_size', 500)
        self.LOG_FLUSH_INTERVAL = self._get('advanced.logging.flush_interval_seconds', 5.0)
        
        # 패킷 처리 설정
        self.PACKET_BUFFER_CHUNK_SIZE = self._get('monitoring.packet_processing.chunk_size', 50)
        self.MAX_PACKET_BUFFER_SIZE = self._get('monitoring.packet_processing.max_buffer_size', 500)
        self.PACKET_SAVE_INTERVAL_SECONDS = self._get('monitoring.packet_processing.save_interval_seconds', 120)
        
        # Conservative RL 하이퍼파라미터
        self.RL_ALPHA_CQL = self._get('machine_learning.reinforcement_learning.hyperparameters.alpha_cql', 1.0)
        self.RL_TAU = self._get('machine_learning.reinforcement_learning.hyperparameters.tau', 0.005)
        self.RL_GAMMA = self._get('machine_learning.reinforcement_learning.hyperparameters.gamma', 0.99)
        self.RL_LEARNING_RATE = self._get('machine_learning.reinforcement_learning.hyperparameters.learning_rate', 0.0001)
        self.RL_EPSILON = self._get('machine_learning.reinforcement_learning.hyperparameters.epsilon', 0.1)
        self.RL_EPSILON_MIN = self._get('machine_learning.reinforcement_learning.hyperparameters.epsilon_min', 0.01)
        self.RL_EPSILON_DECAY = self._get('machine_learning.reinforcement_learning.hyperparameters.epsilon_decay', 0.999)
        
        # Defense Policy Environment 비용 설정
        self.DEFENSE_ATTACK_PREVENTION_VALUE = self._get('defense.policy_environment.costs.attack_prevention_value', 100.0)
        self.DEFENSE_FALSE_POSITIVE_COST = self._get('defense.policy_environment.costs.false_positive_cost', 20.0)
        self.DEFENSE_SYSTEM_IMPACT_PENALTY = self._get('defense.policy_environment.costs.system_impact_penalty', 10.0)
        self.DEFENSE_LATENCY_PENALTY = self._get('defense.policy_environment.costs.latency_penalty', 5.0)
        self.DEFENSE_SERVICE_DISRUPTION_COST = self._get('defense.policy_environment.costs.service_disruption_cost', 50.0)
        
        logger.debug("시스템 상수 로드 완료")
    
    def _get(self, key: str, default):
        """설정 값 조회 (안전)"""
        if self.config is None:
            return default
        
        try:
            return self.config.get(key, default)
        except Exception as e:
            logger.warning(f"설정 조회 실패 ({key}): {e}. 기본값 사용: {default}")
            return default
    
    def reload(self):
        """설정 다시 로드"""
        logger.info("설정 다시 로드 중...")
        self._load_config()
        self._load_constants()
        logger.info("설정 다시 로드 완료")
    
    def get_summary(self) -> dict:
        """상수 요약 정보 반환"""
        return {
            'threat_analysis': {
                'packet_size_critical': self.PACKET_SIZE_CRITICAL,
                'packet_size_high': self.PACKET_SIZE_HIGH,
                'packet_size_medium': self.PACKET_SIZE_MEDIUM,
                'threat_score_critical': self.THREAT_SCORE_CRITICAL,
                'threat_score_high': self.THREAT_SCORE_HIGH,
                'threat_score_medium': self.THREAT_SCORE_MEDIUM
            },
            'performance': {
                'cpu_high_threshold': self.CPU_HIGH_THRESHOLD,
                'cpu_low_threshold': self.CPU_LOW_THRESHOLD,
                'memory_high_mb': self.MEMORY_HIGH_MB,
                'memory_low_mb': self.MEMORY_LOW_MB
            },
            'queue': {
                'max_size': self.MAX_QUEUE_SIZE,
                'adaptive_process_max': self.ADAPTIVE_PROCESS_MAX,
                'adaptive_process_medium': self.ADAPTIVE_PROCESS_MEDIUM,
                'adaptive_process_normal': self.ADAPTIVE_PROCESS_NORMAL
            },
            'timing': {
                'dashboard_refresh': self.DASHBOARD_REFRESH_SECONDS,
                'packet_process_sleep_ms': self.PACKET_PROCESS_SLEEP_MS,
                'memory_cleanup_interval': self.MEMORY_CLEANUP_INTERVAL_SECONDS
            }
        }
    
    def __repr__(self) -> str:
        """문자열 표현"""
        return f"SystemConstants(config_path='{self.config_path}', loaded={self.config is not None})"


# 전역 싱글톤 인스턴스
_global_constants: Optional[SystemConstants] = None


def get_constants(config_path: Optional[str] = None) -> SystemConstants:
    """전역 SystemConstants 인스턴스 반환 (싱글톤)
    
    Args:
        config_path: 설정 파일 경로 (최초 호출 시만 사용)
    
    Returns:
        SystemConstants: 시스템 상수 인스턴스
    """
    global _global_constants
    
    if _global_constants is None:
        _global_constants = SystemConstants(config_path)
    
    return _global_constants


if __name__ == '__main__':
    # 테스트 코드
    print("=" * 60)
    print("SystemConstants 테스트")
    print("=" * 60)
    
    constants = get_constants()
    
    print(f"\n시스템 상수 인스턴스: {constants}")
    print(f"\n상수 요약:")
    
    summary = constants.get_summary()
    for category, values in summary.items():
        print(f"\n[{category}]")
        for key, value in values.items():
            print(f"  {key}: {value}")
    
    print("\n✅ SystemConstants 테스트 완료")

