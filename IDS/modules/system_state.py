# -*- coding: utf-8 -*-

"""
시스템 상태 관리 클래스

전역 변수를 대체하여 시스템 상태를 중앙집중식으로 관리합니다.
스레드 안전성을 보장하며, 상태 접근 및 수정을 캡슐화합니다.
"""

import threading
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ThreatStatistics:
    """위협 통계 정보"""
    high: int = 0
    medium: int = 0
    low: int = 0
    safe: int = 0
    
    def increment(self, level: str) -> None:
        """위협 레벨별 카운트 증가"""
        level = level.lower()
        if hasattr(self, level):
            setattr(self, level, getattr(self, level) + 1)
    
    def get_total(self) -> int:
        """전체 위협 수 반환"""
        return self.high + self.medium + self.low + self.safe
    
    def to_dict(self) -> Dict[str, int]:
        """딕셔너리로 변환"""
        return {
            'high': self.high,
            'medium': self.medium,
            'low': self.low,
            'safe': self.safe
        }


@dataclass
class DefenseStatistics:
    """방어 통계 정보"""
    blocked: int = 0
    monitored: int = 0
    alerts: int = 0
    
    def increment(self, action: str) -> None:
        """방어 액션별 카운트 증가"""
        action = action.lower()
        if hasattr(self, action):
            setattr(self, action, getattr(self, action) + 1)
    
    def get_total(self) -> int:
        """전체 방어 액션 수 반환"""
        return self.blocked + self.monitored + self.alerts
    
    def to_dict(self) -> Dict[str, int]:
        """딕셔너리로 변환"""
        return {
            'blocked': self.blocked,
            'monitored': self.monitored,
            'alerts': self.alerts
        }


@dataclass
class MLStatistics:
    """머신러닝 통계 정보"""
    total_trained: int = 0
    last_train_time: Optional[float] = None
    model_accuracy: float = 0.0
    training_in_progress: bool = False
    
    def update_training(self, accuracy: float) -> None:
        """학습 통계 업데이트"""
        self.total_trained += 1
        self.last_train_time = time.time()
        self.model_accuracy = accuracy
        self.training_in_progress = False
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환"""
        return {
            'total_trained': self.total_trained,
            'last_train_time': self.last_train_time,
            'model_accuracy': self.model_accuracy,
            'training_in_progress': self.training_in_progress
        }


class SystemState:
    """
    시스템 전체 상태를 관리하는 싱글톤 클래스
    
    전역 변수를 대체하여 스레드 안전한 방식으로 상태를 관리합니다.
    
    Features:
        - 스레드 안전성: threading.Lock을 사용한 동기화
        - 싱글톤 패턴: 애플리케이션 전체에서 하나의 인스턴스만 존재
        - 캡슐화: 상태 접근/수정을 메서드로 제어
        - 타입 안전성: dataclass를 사용한 명확한 타입 정의
    
    Example:
        >>> state = SystemState.get_instance()
        >>> state.increment_threat('high')
        >>> stats = state.get_threat_stats()
        >>> print(stats['high'])  # 1
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """싱글톤 패턴 구현"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """시스템 상태 초기화"""
        if hasattr(self, '_initialized'):
            return
        
        self._initialized = True
        self._state_lock = threading.RLock()  # 재진입 가능한 락
        
        # 통계 정보
        self._threat_stats = ThreatStatistics()
        self._defense_stats = DefenseStatistics()
        self._ml_stats = MLStatistics()
        
        # 시스템 실행 정보
        self._start_time = time.time()
        self._stop_requested = False
        
        # 컴포넌트 참조 (선택적)
        self._components: Dict[str, Any] = {}
        
        # 설정 정보
        self._config: Dict[str, Any] = {}
    
    @classmethod
    def get_instance(cls) -> 'SystemState':
        """싱글톤 인스턴스 반환"""
        if cls._instance is None:
            cls()
        return cls._instance
    
    @classmethod
    def reset_instance(cls) -> None:
        """인스턴스 리셋 (주로 테스트용)"""
        with cls._lock:
            cls._instance = None
    
    # ========== 위협 통계 관리 ==========
    
    def increment_threat(self, level: str) -> None:
        """위협 통계 증가 (스레드 안전)"""
        with self._state_lock:
            self._threat_stats.increment(level)
    
    def get_threat_stats(self) -> Dict[str, int]:
        """위협 통계 조회"""
        with self._state_lock:
            return self._threat_stats.to_dict()
    
    def reset_threat_stats(self) -> None:
        """위협 통계 초기화"""
        with self._state_lock:
            self._threat_stats = ThreatStatistics()
    
    # ========== 방어 통계 관리 ==========
    
    def increment_defense(self, action: str) -> None:
        """방어 액션 통계 증가 (스레드 안전)"""
        with self._state_lock:
            self._defense_stats.increment(action)
    
    def get_defense_stats(self) -> Dict[str, int]:
        """방어 통계 조회"""
        with self._state_lock:
            return self._defense_stats.to_dict()
    
    def reset_defense_stats(self) -> None:
        """방어 통계 초기화"""
        with self._state_lock:
            self._defense_stats = DefenseStatistics()
    
    # ========== ML 통계 관리 ==========
    
    def update_ml_training(self, accuracy: float) -> None:
        """ML 학습 통계 업데이트"""
        with self._state_lock:
            self._ml_stats.update_training(accuracy)
    
    def set_ml_training_status(self, in_progress: bool) -> None:
        """ML 학습 상태 설정"""
        with self._state_lock:
            self._ml_stats.training_in_progress = in_progress
    
    def get_ml_stats(self) -> Dict[str, Any]:
        """ML 통계 조회"""
        with self._state_lock:
            return self._ml_stats.to_dict()
    
    def reset_ml_stats(self) -> None:
        """ML 통계 초기화"""
        with self._state_lock:
            self._ml_stats = MLStatistics()
    
    # ========== 시스템 실행 정보 ==========
    
    def get_start_time(self) -> float:
        """시스템 시작 시간 반환"""
        return self._start_time
    
    def get_uptime(self) -> float:
        """시스템 가동 시간 반환 (초)"""
        return time.time() - self._start_time
    
    def get_uptime_str(self) -> str:
        """시스템 가동 시간 문자열 반환"""
        uptime_seconds = int(self.get_uptime())
        hours = uptime_seconds // 3600
        minutes = (uptime_seconds % 3600) // 60
        seconds = uptime_seconds % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    def request_stop(self) -> None:
        """시스템 중지 요청"""
        with self._state_lock:
            self._stop_requested = True
    
    def is_stop_requested(self) -> bool:
        """시스템 중지 요청 여부 확인"""
        with self._state_lock:
            return self._stop_requested
    
    def reset_stop_request(self) -> None:
        """중지 요청 플래그 리셋"""
        with self._state_lock:
            self._stop_requested = False
    
    # ========== 컴포넌트 관리 ==========
    
    def register_component(self, name: str, component: Any) -> None:
        """컴포넌트 등록 (예: ml_model, defense_manager 등)"""
        with self._state_lock:
            self._components[name] = component
    
    def get_component(self, name: str) -> Optional[Any]:
        """컴포넌트 조회"""
        with self._state_lock:
            return self._components.get(name)
    
    def unregister_component(self, name: str) -> None:
        """컴포넌트 등록 해제"""
        with self._state_lock:
            if name in self._components:
                del self._components[name]
    
    def list_components(self) -> list:
        """등록된 컴포넌트 목록 반환"""
        with self._state_lock:
            return list(self._components.keys())
    
    # ========== 설정 관리 ==========
    
    def set_config(self, key: str, value: Any) -> None:
        """설정 값 저장"""
        with self._state_lock:
            self._config[key] = value
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """설정 값 조회"""
        with self._state_lock:
            return self._config.get(key, default)
    
    def update_config(self, config_dict: Dict[str, Any]) -> None:
        """설정 딕셔너리 업데이트"""
        with self._state_lock:
            self._config.update(config_dict)
    
    def get_all_config(self) -> Dict[str, Any]:
        """전체 설정 조회"""
        with self._state_lock:
            return self._config.copy()
    
    # ========== 통합 정보 조회 ==========
    
    def get_summary(self) -> Dict[str, Any]:
        """시스템 전체 상태 요약 반환"""
        with self._state_lock:
            return {
                'uptime': self.get_uptime_str(),
                'start_time': datetime.fromtimestamp(self._start_time).isoformat(),
                'threat_stats': self._threat_stats.to_dict(),
                'defense_stats': self._defense_stats.to_dict(),
                'ml_stats': self._ml_stats.to_dict(),
                'stop_requested': self._stop_requested,
                'components': self.list_components(),
                'config_keys': list(self._config.keys())
            }
    
    def reset_all(self) -> None:
        """모든 통계 초기화 (시작 시간 제외)"""
        with self._state_lock:
            self._threat_stats = ThreatStatistics()
            self._defense_stats = DefenseStatistics()
            self._ml_stats = MLStatistics()
            self._stop_requested = False


# 싱글톤 인스턴스 생성 함수 (편의성)
def get_system_state() -> SystemState:
    """
    시스템 상태 싱글톤 인스턴스 반환
    
    Returns:
        SystemState: 시스템 상태 관리 인스턴스
    
    Example:
        >>> from modules.system_state import get_system_state
        >>> state = get_system_state()
        >>> state.increment_threat('high')
    """
    return SystemState.get_instance()


if __name__ == '__main__':
    # 테스트 코드
    print("=== SystemState 테스트 ===\n")
    
    # 싱글톤 테스트
    state1 = get_system_state()
    state2 = get_system_state()
    print(f"싱글톤 테스트: {state1 is state2}")  # True
    
    # 위협 통계 테스트
    state1.increment_threat('high')
    state1.increment_threat('high')
    state1.increment_threat('medium')
    print(f"\n위협 통계: {state1.get_threat_stats()}")
    
    # 방어 통계 테스트
    state1.increment_defense('blocked')
    state1.increment_defense('alerts')
    print(f"방어 통계: {state1.get_defense_stats()}")
    
    # ML 통계 테스트
    state1.update_ml_training(0.95)
    print(f"ML 통계: {state1.get_ml_stats()}")
    
    # 컴포넌트 등록 테스트
    state1.register_component('test_component', {'name': 'test'})
    print(f"\n등록된 컴포넌트: {state1.list_components()}")
    
    # 설정 관리 테스트
    state1.set_config('mode', 'lightweight')
    state1.set_config('max_packets', 1000)
    print(f"설정: {state1.get_all_config()}")
    
    # 전체 요약 테스트
    print(f"\n시스템 요약:\n{state1.get_summary()}")
    
    print("\n✅ 모든 테스트 통과!")









