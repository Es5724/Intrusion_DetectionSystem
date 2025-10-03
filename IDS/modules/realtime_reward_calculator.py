# -*- coding: utf-8 -*-

"""
실시간 보상 계산 시스템 (Realtime Reward Calculator)

RL 에이전트의 대응 액션 결과를 즉각적인 보상 값으로 변환합니다.
DefensePolicyEnv의 _calculate_reward 로직을 실시간 환경에 최적화한 버전입니다.

핵심 기능:
- 대응 액션의 즉각적 효과 평가
- 오탐/미탐 비용 계산
- 시스템 부하 패널티 적용
- 보상 이력 추적 및 통계
"""

import numpy as np
import logging
from typing import Dict, Any, Tuple, Optional
from collections import deque
from datetime import datetime

logger = logging.getLogger('RealtimeRewardCalculator')


class RealtimeRewardCalculator:
    """
    실시간 보상 계산기
    
    보상 체계:
    - True Positive (위협 정확 차단): +100
    - True Negative (정상 정확 허용): +5
    - False Positive (정상 오차단): -50
    - False Negative (위협 미탐): -200
    - 시스템 부하 패널티: -0 ~ -20
    - 과도한 차단 패널티: -10
    """
    
    def __init__(self, 
                 max_history: int = 1000,
                 fp_penalty: float = -50.0,
                 fn_penalty: float = -200.0,
                 tp_reward: float = 100.0,
                 tn_reward: float = 5.0):
        """
        Args:
            max_history: 보상 이력 최대 크기
            fp_penalty: False Positive 패널티
            fn_penalty: False Negative 패널티
            tp_reward: True Positive 보상
            tn_reward: True Negative 보상
        """
        self.max_history = max_history
        self.fp_penalty = fp_penalty
        self.fn_penalty = fn_penalty
        self.tp_reward = tp_reward
        self.tn_reward = tn_reward
        
        # 보상 이력
        self.reward_history = deque(maxlen=max_history)
        
        # 통계 추적
        self.stats = {
            'total_rewards': 0,
            'tp_count': 0,
            'tn_count': 0,
            'fp_count': 0,
            'fn_count': 0,
            'avg_reward': 0.0,
            'max_reward': float('-inf'),
            'min_reward': float('inf')
        }
        
        # 액션별 이력
        self.action_rewards = {i: [] for i in range(6)}  # 6개 액션
        
        logger.info("실시간 보상 계산기 초기화 완료")
    
    def calculate_reward(self, 
                        threat_probability: float,
                        action_taken: int,
                        actual_threat: Optional[bool] = None,
                        system_load: float = 0.0,
                        response_time: float = 0.0,
                        additional_context: Optional[Dict[str, Any]] = None) -> Tuple[float, Dict[str, Any]]:
        """
        대응 액션의 보상 계산
        
        Args:
            threat_probability: RF 모델의 위협 확률 (0.0 ~ 1.0)
            action_taken: 실행된 액션 (0=허용, 1=임시차단, 2=영구차단, 3=레이트제한, 4=추가검사, 5=격리)
            actual_threat: 실제 위협 여부 (검증 가능한 경우)
            system_load: 시스템 부하 (0.0 ~ 1.0)
            response_time: 대응 소요 시간 (초)
            additional_context: 추가 컨텍스트 정보
        
        Returns:
            (reward, details): 보상 값과 상세 정보
        """
        if additional_context is None:
            additional_context = {}
        
        reward = 0.0
        details = {
            'base_reward': 0.0,
            'system_penalty': 0.0,
            'timing_penalty': 0.0,
            'classification': 'unknown',
            'confidence': threat_probability
        }
        
        try:
            # ========== 1. 기본 보상 계산 ==========
            
            if actual_threat is not None:
                # 실제 레이블이 있는 경우 (검증 완료)
                if actual_threat:
                    # 실제 위협인 경우
                    if action_taken in [1, 2, 5]:  # 차단/격리 액션
                        # True Positive (위협 정확 차단)
                        reward = self.tp_reward
                        details['classification'] = 'TP'
                        details['base_reward'] = self.tp_reward
                        self.stats['tp_count'] += 1
                    else:
                        # False Negative (위협 미탐)
                        reward = self.fn_penalty
                        details['classification'] = 'FN'
                        details['base_reward'] = self.fn_penalty
                        self.stats['fn_count'] += 1
                else:
                    # 실제 정상인 경우
                    if action_taken in [1, 2, 5]:  # 차단/격리 액션
                        # False Positive (정상 오차단)
                        reward = self.fp_penalty
                        details['classification'] = 'FP'
                        details['base_reward'] = self.fp_penalty
                        self.stats['fp_count'] += 1
                    else:
                        # True Negative (정상 정확 허용)
                        reward = self.tn_reward
                        details['classification'] = 'TN'
                        details['base_reward'] = self.tn_reward
                        self.stats['tn_count'] += 1
            
            else:
                # 실제 레이블 없음 - RF 확률 기반 추정 보상
                reward, classification = self._estimate_reward_from_probability(
                    threat_probability, action_taken
                )
                details['base_reward'] = reward
                details['classification'] = f'{classification} (estimated)'
            
            # ========== 2. 시스템 부하 패널티 ==========
            
            if system_load > 0.7:  # 부하 70% 이상
                # 차단 액션은 시스템에 추가 부하
                if action_taken in [1, 2, 5]:
                    load_penalty = -(system_load - 0.7) * 50  # 최대 -15
                    reward += load_penalty
                    details['system_penalty'] = load_penalty
            
            # ========== 3. 응답 시간 패널티 ==========
            
            if response_time > 1.0:  # 1초 이상 소요
                timing_penalty = -min((response_time - 1.0) * 5, 10.0)  # 최대 -10
                reward += timing_penalty
                details['timing_penalty'] = timing_penalty
            
            # ========== 4. 액션별 추가 보상/패널티 ==========
            
            # 영구 차단 (action=2)은 신중해야 함
            if action_taken == 2:
                if threat_probability < 0.9:  # 확신이 낮은데 영구 차단
                    cautious_penalty = -(0.9 - threat_probability) * 20  # 최대 -18
                    reward += cautious_penalty
                    details['cautious_penalty'] = cautious_penalty
            
            # 추가 검사 (action=4)는 시간이 걸리지만 안전
            if action_taken == 4:
                if 0.3 < threat_probability < 0.7:  # 애매한 경우
                    careful_bonus = 10.0
                    reward += careful_bonus
                    details['careful_bonus'] = careful_bonus
            
            # ========== 5. 보상 정규화 및 기록 ==========
            
            # 보상 범위 제한 (-250 ~ +120)
            reward = np.clip(reward, -250.0, 120.0)
            
            # 이력 기록
            self._record_reward(reward, action_taken, details)
            
            # 상세 정보 보완
            details['final_reward'] = reward
            details['action'] = action_taken
            details['timestamp'] = datetime.now().isoformat()
            
            logger.debug(f"보상 계산: {details['classification']}, "
                        f"액션={action_taken}, 보상={reward:.2f}")
            
            return reward, details
            
        except Exception as e:
            logger.error(f"보상 계산 오류: {e}")
            # 오류 시 중립 보상
            return 0.0, {'error': str(e), 'classification': 'error'}
    
    def _estimate_reward_from_probability(self, 
                                          threat_probability: float, 
                                          action: int) -> Tuple[float, str]:
        """
        실제 레이블 없이 RF 확률 기반으로 보상 추정
        
        Args:
            threat_probability: 위협 확률
            action: 실행된 액션
        
        Returns:
            (reward, classification): 추정 보상과 분류
        """
        is_blocking_action = action in [1, 2, 5]  # 차단/격리
        
        # 높은 위협 확률 (0.7 이상)
        if threat_probability >= 0.7:
            if is_blocking_action:
                # 높은 위협에 차단 → TP로 추정
                confidence_factor = (threat_probability - 0.7) / 0.3  # 0~1
                reward = self.tp_reward * confidence_factor
                return reward, 'TP'
            else:
                # 높은 위협에 허용 → FN로 추정
                confidence_factor = (threat_probability - 0.7) / 0.3
                reward = self.fn_penalty * confidence_factor
                return reward, 'FN'
        
        # 낮은 위협 확률 (0.3 미만)
        elif threat_probability < 0.3:
            if is_blocking_action:
                # 낮은 위협에 차단 → FP로 추정
                confidence_factor = (0.3 - threat_probability) / 0.3
                reward = self.fp_penalty * confidence_factor
                return reward, 'FP'
            else:
                # 낮은 위협에 허용 → TN로 추정
                confidence_factor = (0.3 - threat_probability) / 0.3
                reward = self.tn_reward * confidence_factor
                return reward, 'TN'
        
        # 중간 확률 (0.3 ~ 0.7) - 불확실한 영역
        else:
            # 보수적 접근: 작은 보상/패널티
            if is_blocking_action:
                # 차단했지만 불확실 → 작은 음수
                return -5.0, 'uncertain_block'
            else:
                # 허용했지만 불확실 → 작은 양수
                return 2.0, 'uncertain_allow'
    
    def _record_reward(self, reward: float, action: int, details: Dict[str, Any]):
        """보상 이력 기록 및 통계 업데이트"""
        # 보상 이력
        self.reward_history.append(reward)
        
        # 액션별 이력
        self.action_rewards[action].append(reward)
        
        # 통계 업데이트
        self.stats['total_rewards'] += reward
        self.stats['max_reward'] = max(self.stats['max_reward'], reward)
        self.stats['min_reward'] = min(self.stats['min_reward'], reward)
        
        if len(self.reward_history) > 0:
            self.stats['avg_reward'] = np.mean(self.reward_history)
    
    def get_statistics(self) -> Dict[str, Any]:
        """현재 통계 반환"""
        stats = self.stats.copy()
        
        # 추가 계산
        total_decisions = (stats['tp_count'] + stats['tn_count'] + 
                          stats['fp_count'] + stats['fn_count'])
        
        if total_decisions > 0:
            stats['accuracy'] = (stats['tp_count'] + stats['tn_count']) / total_decisions
            stats['precision'] = stats['tp_count'] / max(stats['tp_count'] + stats['fp_count'], 1)
            stats['recall'] = stats['tp_count'] / max(stats['tp_count'] + stats['fn_count'], 1)
        else:
            stats['accuracy'] = 0.0
            stats['precision'] = 0.0
            stats['recall'] = 0.0
        
        # 액션별 평균 보상
        stats['action_avg_rewards'] = {
            f'action_{i}': np.mean(rewards) if rewards else 0.0
            for i, rewards in self.action_rewards.items()
        }
        
        stats['total_decisions'] = total_decisions
        stats['history_size'] = len(self.reward_history)
        
        return stats
    
    def get_recent_rewards(self, n: int = 10) -> list:
        """최근 N개 보상 반환"""
        return list(self.reward_history)[-n:]
    
    def reset_statistics(self):
        """통계 초기화"""
        self.reward_history.clear()
        self.stats = {
            'total_rewards': 0,
            'tp_count': 0,
            'tn_count': 0,
            'fp_count': 0,
            'fn_count': 0,
            'avg_reward': 0.0,
            'max_reward': float('-inf'),
            'min_reward': float('inf')
        }
        self.action_rewards = {i: [] for i in range(6)}
        logger.info("보상 통계 초기화 완료")


# 전역 싱글톤 인스턴스
_global_calculator = None


def get_reward_calculator() -> RealtimeRewardCalculator:
    """
    전역 보상 계산기 인스턴스 반환 (싱글톤 패턴)
    
    Returns:
        RealtimeRewardCalculator 인스턴스
    """
    global _global_calculator
    if _global_calculator is None:
        _global_calculator = RealtimeRewardCalculator()
    return _global_calculator

