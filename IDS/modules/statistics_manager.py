#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
통계 관리 모듈

시스템 전체의 통계 정보를 수집하고 관리합니다.
전역 변수 대신 클래스 기반으로 통계를 관리하여 
코드의 응집도를 높이고 테스트 가능성을 향상시킵니다.
"""

import time
import threading
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

# 로깅 설정
logger = logging.getLogger('StatisticsManager')
logger.setLevel(logging.INFO)


@dataclass
class SystemStatistics:
    """시스템 통계 데이터 클래스
    
    시스템의 모든 통계 정보를 하나의 데이터 클래스로 관리합니다.
    
    Attributes:
        threat_stats: 위협 탐지 통계 (5단계: critical, high, medium, low, safe)
        defense_stats: 방어 조치 통계
        ml_stats: 머신러닝 모델 통계
        start_time: 시스템 시작 시간
    """
    
    threat_stats: Dict[str, int] = field(default_factory=lambda: {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'safe': 0
    })
    
    defense_stats: Dict[str, int] = field(default_factory=lambda: {
        'blocked': 0,              # 총 차단 수
        'permanent_block': 0,      # 영구 차단
        'temp_block': 0,           # 임시 차단
        'warning_block': 0,        # 경고 차단
        'monitored': 0,            # 모니터링 중
        'alerts': 0,               # 발송 알림 수
        'accumulated_blocks': 0    # 누적 패턴 차단
    })
    
    ml_stats: Dict[str, float] = field(default_factory=lambda: {
        'predictions': 0,
        'accuracy': 0.0,
        'model_updates': 0
    })
    
    start_time: float = field(default_factory=time.time)
    
    def get_uptime(self) -> float:
        """시스템 가동 시간 반환 (초)"""
        return time.time() - self.start_time
    
    def get_total_threats(self) -> int:
        """총 탐지된 위협 수 반환 (critical + high + medium)"""
        return (self.threat_stats['critical'] + 
                self.threat_stats['high'] + 
                self.threat_stats['medium'])
    
    def get_total_analyzed(self) -> int:
        """총 분석된 패킷 수 반환"""
        return sum(self.threat_stats.values())
    
    def get_threat_rate(self) -> float:
        """위협 탐지율 반환 (0.0 ~ 1.0)"""
        total = self.get_total_analyzed()
        if total == 0:
            return 0.0
        return self.get_total_threats() / total
    
    def reset(self):
        """통계 초기화"""
        self.threat_stats = {
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'safe': 0
        }
        self.defense_stats = {
            'blocked': 0, 'permanent_block': 0, 'temp_block': 0,
            'warning_block': 0, 'monitored': 0, 'alerts': 0, 'accumulated_blocks': 0
        }
        self.ml_stats = {
            'predictions': 0, 'accuracy': 0.0, 'model_updates': 0
        }
        self.start_time = time.time()


class StatisticsManager:
    """통계 수집 및 관리 클래스
    
    시스템 전체의 통계를 수집하고 관리합니다.
    스레드 안전성을 보장하며, 통계 업데이트와 조회 기능을 제공합니다.
    
    Features:
        - 스레드 안전한 통계 업데이트
        - 통계 스냅샷 생성
        - 통계 초기화
        - 실시간 통계 조회
    
    Example:
        >>> manager = StatisticsManager()
        >>> manager.update_threat('critical')
        >>> manager.update_defense('permanent_block')
        >>> summary = manager.get_summary()
        >>> print(summary)
    """
    
    def __init__(self):
        """StatisticsManager 초기화"""
        self.stats = SystemStatistics()
        self._lock = threading.Lock()
        
        logger.info("StatisticsManager 초기화 완료")
    
    def update_threat(self, level: str) -> bool:
        """위협 통계 업데이트
        
        Args:
            level: 위협 수준 ('critical', 'high', 'medium', 'low', 'safe')
        
        Returns:
            bool: 업데이트 성공 여부
        """
        with self._lock:
            if level in self.stats.threat_stats:
                self.stats.threat_stats[level] += 1
                return True
            else:
                logger.warning(f"알 수 없는 위협 수준: {level}")
                return False
    
    def update_defense(self, action_type: str) -> bool:
        """방어 통계 업데이트
        
        Args:
            action_type: 방어 조치 유형
        
        Returns:
            bool: 업데이트 성공 여부
        """
        with self._lock:
            if action_type in self.stats.defense_stats:
                self.stats.defense_stats[action_type] += 1
                
                # 총 차단 수 자동 계산
                self.stats.defense_stats['blocked'] = (
                    self.stats.defense_stats['permanent_block'] +
                    self.stats.defense_stats['temp_block'] +
                    self.stats.defense_stats['warning_block']
                )
                return True
            else:
                logger.warning(f"알 수 없는 방어 조치: {action_type}")
                return False
    
    def update_ml_stat(self, stat_name: str, value: float) -> bool:
        """머신러닝 통계 업데이트
        
        Args:
            stat_name: 통계 이름 ('predictions', 'accuracy', 'model_updates')
            value: 통계 값
        
        Returns:
            bool: 업데이트 성공 여부
        """
        with self._lock:
            if stat_name in self.stats.ml_stats:
                if stat_name == 'predictions' or stat_name == 'model_updates':
                    self.stats.ml_stats[stat_name] += value
                else:
                    self.stats.ml_stats[stat_name] = value
                return True
            else:
                logger.warning(f"알 수 없는 ML 통계: {stat_name}")
                return False
    
    def increment_ml_predictions(self, count: int = 1):
        """ML 예측 횟수 증가"""
        self.update_ml_stat('predictions', count)
    
    def set_ml_accuracy(self, accuracy: float):
        """ML 정확도 설정"""
        self.update_ml_stat('accuracy', accuracy)
    
    def increment_ml_updates(self, count: int = 1):
        """ML 모델 업데이트 횟수 증가"""
        self.update_ml_stat('model_updates', count)
    
    def get_stats(self) -> SystemStatistics:
        """현재 통계 반환 (스레드 안전)
        
        Returns:
            SystemStatistics: 통계 데이터 (복사본)
        """
        with self._lock:
            # 깊은 복사 대신 필드별 복사 (성능 최적화)
            return SystemStatistics(
                threat_stats=self.stats.threat_stats.copy(),
                defense_stats=self.stats.defense_stats.copy(),
                ml_stats=self.stats.ml_stats.copy(),
                start_time=self.stats.start_time
            )
    
    def get_summary(self) -> Dict[str, Any]:
        """통계 요약 정보 반환
        
        Returns:
            Dict: 통계 요약 딕셔너리
        """
        with self._lock:
            return {
                'threat_stats': self.stats.threat_stats.copy(),
                'defense_stats': self.stats.defense_stats.copy(),
                'ml_stats': self.stats.ml_stats.copy(),
                'uptime_seconds': self.stats.get_uptime(),
                'total_threats': self.stats.get_total_threats(),
                'total_analyzed': self.stats.get_total_analyzed(),
                'threat_rate': self.stats.get_threat_rate(),
                'timestamp': datetime.now().isoformat()
            }
    
    def reset(self):
        """통계 초기화"""
        with self._lock:
            self.stats.reset()
            logger.info("통계 초기화 완료")
    
    def __repr__(self) -> str:
        """문자열 표현"""
        uptime = self.stats.get_uptime()
        total_threats = self.stats.get_total_threats()
        return f"StatisticsManager(uptime={uptime:.1f}s, threats={total_threats})"


# 전역 싱글톤 인스턴스
_global_stats_manager: Optional[StatisticsManager] = None


def get_statistics_manager() -> StatisticsManager:
    """전역 StatisticsManager 인스턴스 반환 (싱글톤)
    
    Returns:
        StatisticsManager: 통계 관리자 인스턴스
    """
    global _global_stats_manager
    
    if _global_stats_manager is None:
        _global_stats_manager = StatisticsManager()
    
    return _global_stats_manager


if __name__ == '__main__':
    # 테스트 코드
    print("=" * 60)
    print("StatisticsManager 테스트")
    print("=" * 60)
    
    manager = get_statistics_manager()
    
    # 통계 업데이트 테스트
    print("\n통계 업데이트 테스트:")
    manager.update_threat('critical')
    manager.update_threat('high')
    manager.update_threat('high')
    manager.update_threat('safe')
    
    manager.update_defense('permanent_block')
    manager.update_defense('temp_block')
    manager.update_defense('temp_block')
    
    manager.increment_ml_predictions(10)
    manager.set_ml_accuracy(0.95)
    manager.increment_ml_updates()
    
    # 통계 조회
    print("\n통계 요약:")
    summary = manager.get_summary()
    
    print(f"\n위협 통계:")
    for level, count in summary['threat_stats'].items():
        print(f"  {level}: {count}")
    
    print(f"\n방어 통계:")
    for action, count in summary['defense_stats'].items():
        print(f"  {action}: {count}")
    
    print(f"\nML 통계:")
    for stat, value in summary['ml_stats'].items():
        print(f"  {stat}: {value}")
    
    print(f"\n가동 시간: {summary['uptime_seconds']:.2f}초")
    print(f"총 위협: {summary['total_threats']}")
    print(f"총 분석: {summary['total_analyzed']}")
    print(f"위협 탐지율: {summary['threat_rate']:.2%}")
    
    print("\n✅ StatisticsManager 테스트 완료")

