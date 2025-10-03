# -*- coding: utf-8 -*-

"""
RL 통합 방어 Wrapper (RL-Integrated Defense Wrapper)

기존 AutoDefenseActions를 래핑하여 RL 에이전트가 직접 방어 액션을 선택하도록 통합합니다.

핵심 기능:
- RF 탐지 → RL 액션 선택 → 실제 방어 실행
- 기존 방어 메커니즘 재사용
- 실시간 피드백 루프
"""

import logging
from typing import Dict, Any, Optional, Tuple
import numpy as np

logger = logging.getLogger('RLDefenseWrapper')


class RLDefenseWrapper:
    """
    RL 통합 방어 Wrapper
    
    RL 에이전트의 액션 결정을 실제 방어 조치로 변환합니다.
    """
    
    def __init__(self, 
                 auto_defense_actions,
                 rl_integrator,
                 enable_rl: bool = True):
        """
        Args:
            auto_defense_actions: 기존 AutoDefenseActions 인스턴스
            rl_integrator: RealTimeRLIntegrator 인스턴스
            enable_rl: RL 기반 방어 활성화 여부
        """
        self.auto_defense = auto_defense_actions
        self.rl_integrator = rl_integrator
        self.enable_rl = enable_rl
        
        # 액션 매핑 (RL 액션 → 방어 조치)
        self.action_map = {
            0: 'allow',           # 허용
            1: 'temporary_block', # 임시 차단 (30분)
            2: 'permanent_block', # 영구 차단
            3: 'rate_limit',      # 레이트 제한
            4: 'deep_inspect',    # 심층 검사
            5: 'isolate'          # 격리
        }
        
        logger.info(f"RL 통합 방어 Wrapper 초기화 (RL 활성화: {enable_rl})")
    
    def process_packet(self, packet: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """
        패킷 처리 및 방어 액션 결정
        
        Args:
            packet: 패킷 정보
        
        Returns:
            (action_name, details): 액션 이름과 상세 정보
        """
        try:
            # 1. RF 위협 탐지
            prediction, rf_confidence = self.auto_defense.analyze_packet(packet)
            rf_threat_probability = rf_confidence if prediction == 1 else (1 - rf_confidence)
            
            # 2. RL 활성화 여부에 따라 분기
            if self.enable_rl:
                # RL 기반 액션 선택
                action_id, rl_details = self.rl_integrator.process_packet_with_rl(
                    packet, rf_threat_probability
                )
                action_name = self.action_map.get(action_id, 'allow')
                
                logger.debug(f"RL 액션 선택: {action_name} (ID: {action_id})")
            else:
                # 기존 방식 (RF 확률 기반)
                action_name = self._legacy_action_selection(rf_threat_probability)
                rl_details = {'mode': 'legacy'}
            
            # 3. 액션 실행
            execution_result = self._execute_action(action_name, packet, rf_threat_probability)
            
            # 4. 상세 정보 구성
            details = {
                'rf_prediction': prediction,
                'rf_confidence': rf_confidence,
                'rf_threat_probability': rf_threat_probability,
                'selected_action': action_name,
                'execution_result': execution_result,
                'rl_mode': self.enable_rl
            }
            
            if self.enable_rl:
                details['rl_details'] = rl_details
            
            return action_name, details
            
        except Exception as e:
            logger.error(f"패킷 처리 오류: {e}")
            # 오류 시 보수적 액션
            return 'deep_inspect', {'error': str(e)}
    
    def _legacy_action_selection(self, threat_probability: float) -> str:
        """
        기존 방식의 액션 선택 (RF 확률 기반)
        
        Args:
            threat_probability: 위협 확률 (0-1)
        
        Returns:
            액션 이름
        """
        if threat_probability >= 0.9:
            return 'permanent_block'
        elif threat_probability >= 0.7:
            return 'temporary_block'
        elif threat_probability >= 0.5:
            return 'rate_limit'
        elif threat_probability >= 0.3:
            return 'deep_inspect'
        else:
            return 'allow'
    
    def _execute_action(self, 
                       action_name: str, 
                       packet: Dict[str, Any],
                       threat_probability: float) -> Dict[str, Any]:
        """
        실제 방어 액션 실행
        
        Args:
            action_name: 액션 이름
            packet: 패킷 정보
            threat_probability: 위협 확률
        
        Returns:
            실행 결과
        """
        source_ip = packet.get('source', '').split(':')[0]
        
        result = {
            'action': action_name,
            'success': False,
            'message': ''
        }
        
        try:
            if action_name == 'allow':
                # 허용 - 아무 조치 없음
                result['success'] = True
                result['message'] = f'{source_ip} 허용'
                logger.debug(f"허용: {source_ip}")
            
            elif action_name == 'temporary_block':
                # 임시 차단 (30분)
                self.auto_defense._medium_threat_response(packet, threat_probability)
                result['success'] = True
                result['message'] = f'{source_ip} 30분 임시 차단'
                logger.info(f"임시 차단: {source_ip}")
            
            elif action_name == 'permanent_block':
                # 영구 차단
                self.auto_defense._high_threat_response(packet, threat_probability)
                result['success'] = True
                result['message'] = f'{source_ip} 영구 차단'
                logger.warning(f"영구 차단: {source_ip}")
            
            elif action_name == 'rate_limit':
                # 레이트 제한 (연결 제한)
                result['success'] = True
                result['message'] = f'{source_ip} 레이트 제한 적용'
                logger.info(f"레이트 제한: {source_ip}")
                # TODO: 실제 레이트 제한 구현
            
            elif action_name == 'deep_inspect':
                # 심층 검사 (모니터링 강화)
                result['success'] = True
                result['message'] = f'{source_ip} 심층 검사 모드'
                logger.debug(f"심층 검사: {source_ip}")
                # TODO: 심층 검사 로직 구현
            
            elif action_name == 'isolate':
                # 격리 (세션 분리)
                self.auto_defense._high_threat_response(packet, threat_probability)
                result['success'] = True
                result['message'] = f'{source_ip} 격리'
                logger.warning(f"격리: {source_ip}")
            
            else:
                # 알 수 없는 액션
                result['message'] = f'알 수 없는 액션: {action_name}'
                logger.error(result['message'])
            
        except Exception as e:
            result['success'] = False
            result['message'] = f'실행 오류: {str(e)}'
            logger.error(f"액션 실행 오류 ({action_name}): {e}")
        
        return result
    
    def provide_feedback(self, 
                        packet: Dict[str, Any],
                        actual_threat: Optional[bool] = None):
        """
        RL에 피드백 제공
        
        Args:
            packet: 패킷 정보
            actual_threat: 실제 위협 여부
        """
        if not self.enable_rl:
            return
        
        try:
            # 결정 키 생성 (타임스탬프 기반)
            source_ip = packet.get('source', '').split(':')[0]
            import time
            decision_key = f"{source_ip}_{int(time.time())}"
            
            # 피드백 제공
            self.rl_integrator.provide_feedback(
                decision_key=decision_key,
                actual_threat=actual_threat,
                system_load=0.0,  # TODO: 실제 시스템 부하 측정
                response_time=0.0  # TODO: 실제 응답 시간 측정
            )
            
        except Exception as e:
            logger.error(f"피드백 제공 오류: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """통계 정보 반환"""
        stats = {
            'rl_enabled': self.enable_rl,
            'auto_defense_stats': {
                'enabled': self.auto_defense.is_enabled,
                'threshold': self.auto_defense.threshold
            }
        }
        
        if self.enable_rl:
            stats['rl_integrator_stats'] = self.rl_integrator.get_statistics()
        
        return stats
    
    def toggle_rl(self, enable: bool):
        """RL 모드 토글"""
        self.enable_rl = enable
        logger.info(f"RL 모드 {'활성화' if enable else '비활성화'}")


def create_rl_defense_system(config, mode, rl_agent, state_extractor, 
                             reward_calculator, online_trainer) -> RLDefenseWrapper:
    """
    RL 통합 방어 시스템 생성 (팩토리 함수)
    
    Args:
        config: 방어 설정
        mode: 운영 모드
        rl_agent: RL 에이전트
        state_extractor: 상태 추출기
        reward_calculator: 보상 계산기
        online_trainer: 온라인 학습기
    
    Returns:
        RLDefenseWrapper 인스턴스
    """
    from .defense_mechanism import AutoDefenseActions
    from .online_rl_trainer import get_rl_integrator
    
    # 기존 방어 메커니즘 생성
    auto_defense = AutoDefenseActions(config, mode)
    
    # RL 통합기 생성
    rl_integrator = get_rl_integrator(
        rl_agent, state_extractor, reward_calculator, online_trainer
    )
    
    # Wrapper 생성
    rl_defense = RLDefenseWrapper(auto_defense, rl_integrator, enable_rl=True)
    
    logger.info("RL 통합 방어 시스템 생성 완료")
    return rl_defense

