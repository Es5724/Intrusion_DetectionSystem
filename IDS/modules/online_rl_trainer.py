# -*- coding: utf-8 -*-

"""
온라인 RL 학습기 (Online RL Trainer)

실시간으로 경험을 수집하고 주기적으로 RL 에이전트를 학습시킵니다.

핵심 기능:
- 10초 주기 경량 학습
- 경험 버퍼 관리
- 학습 성능 모니터링
- 메모리 효율적 학습
"""

import threading
import time
import logging
from typing import Dict, Any, Optional, Tuple
from collections import deque
import numpy as np

logger = logging.getLogger('OnlineRLTrainer')


class OnlineRLTrainer:
    """
    온라인 RL 학습기
    
    실시간으로 RL 에이전트를 학습시키는 백그라운드 스레드를 관리합니다.
    """
    
    def __init__(self, 
                 rl_agent,
                 learning_interval: int = 10,
                 min_experiences: int = 32,
                 batch_size: int = 32):
        """
        Args:
            rl_agent: Conservative RL 에이전트 인스턴스
            learning_interval: 학습 주기 (초)
            min_experiences: 최소 경험 수 (이 이상이면 학습 시작)
            batch_size: 배치 크기
        """
        self.rl_agent = rl_agent
        self.learning_interval = learning_interval
        self.min_experiences = min_experiences
        self.batch_size = batch_size
        
        # 스레드 제어
        self.running = False
        self.learning_thread = None
        
        # 통계
        self.stats = {
            'total_learning_cycles': 0,
            'total_experiences_learned': 0,
            'avg_loss': 0.0,
            'last_learning_time': None,
            'learning_errors': 0
        }
        
        # 학습 이력
        self.loss_history = deque(maxlen=100)
        
        logger.info(f"온라인 RL 학습기 초기화: 주기={learning_interval}초, 최소경험={min_experiences}")
    
    def start(self):
        """학습 스레드 시작"""
        if self.running:
            logger.warning("온라인 학습 스레드가 이미 실행 중입니다")
            return
        
        self.running = True
        self.learning_thread = threading.Thread(
            target=self._learning_worker,
            daemon=True,
            name="OnlineRLLearningThread"
        )
        self.learning_thread.start()
        logger.info("온라인 RL 학습 스레드 시작됨")
    
    def stop(self):
        """학습 스레드 중지"""
        if not self.running:
            logger.warning("온라인 학습 스레드가 실행 중이 아닙니다")
            return
        
        self.running = False
        if self.learning_thread:
            self.learning_thread.join(timeout=15)
        logger.info("온라인 RL 학습 스레드 중지됨")
    
    def _learning_worker(self):
        """학습 워커 스레드"""
        logger.info("온라인 학습 워커 시작")
        
        # 첫 학습은 30초 후 시작 (초기화 대기)
        time.sleep(30)
        
        while self.running:
            try:
                # 학습 수행
                self._perform_learning_cycle()
                
                # 다음 학습까지 대기
                time.sleep(self.learning_interval)
                
            except Exception as e:
                logger.error(f"온라인 학습 워커 오류: {e}")
                self.stats['learning_errors'] += 1
                time.sleep(30)  # 오류 시 30초 대기
        
        logger.info("온라인 학습 워커 종료")
    
    def _perform_learning_cycle(self):
        """단일 학습 사이클 수행"""
        try:
            # 버퍼 상태 확인
            buffer_stats = self.rl_agent.get_buffer_stats()
            experience_count = buffer_stats.get('total_experiences', 0)
            
            if experience_count < self.min_experiences:
                logger.debug(f"경험 부족 - 학습 스킵 ({experience_count}/{self.min_experiences})")
                return
            
            logger.debug(f"온라인 학습 시작 - 경험: {experience_count}개")
            
            # 학습 수행
            loss = self.rl_agent.train(batch_size=self.batch_size)
            
            if loss is not None:
                # 통계 업데이트
                self.stats['total_learning_cycles'] += 1
                self.stats['total_experiences_learned'] += self.batch_size
                self.stats['last_learning_time'] = time.time()
                
                self.loss_history.append(loss)
                self.stats['avg_loss'] = float(np.mean(self.loss_history))
                
                logger.info(f"온라인 학습 완료 - Loss: {loss:.4f}, "
                           f"평균 Loss: {self.stats['avg_loss']:.4f}, "
                           f"사이클: {self.stats['total_learning_cycles']}")
            else:
                logger.debug("학습 실패 - 경험 샘플링 오류 가능")
            
        except Exception as e:
            logger.error(f"학습 사이클 오류: {e}")
            self.stats['learning_errors'] += 1
    
    def add_experience(self, state: np.ndarray, action: int, reward: float, 
                       next_state: np.ndarray, done: bool):
        """
        경험 추가 (외부에서 호출)
        
        Args:
            state: 현재 상태
            action: 실행한 액션
            reward: 받은 보상
            next_state: 다음 상태
            done: 에피소드 종료 여부
        """
        try:
            self.rl_agent.remember(state, action, reward, next_state, done)
            logger.debug(f"경험 추가 - 액션: {action}, 보상: {reward:.2f}")
        except Exception as e:
            logger.error(f"경험 추가 오류: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """학습 통계 반환"""
        buffer_stats = self.rl_agent.get_buffer_stats()
        
        return {
            **self.stats,
            'buffer_size': buffer_stats.get('total_experiences', 0),
            'buffer_utilization': buffer_stats.get('buffer_utilization', 0.0),
            'running': self.running,
            'loss_history': list(self.loss_history)[-10:]  # 최근 10개
        }


class RealTimeRLIntegrator:
    """
    실시간 RL 통합기
    
    패킷 처리 흐름에 RL 에이전트를 통합하여 실시간 학습과 대응을 수행합니다.
    """
    
    def __init__(self, 
                 rl_agent,
                 state_extractor,
                 reward_calculator,
                 online_trainer: Optional[OnlineRLTrainer] = None):
        """
        Args:
            rl_agent: Conservative RL 에이전트
            state_extractor: RL 상태 추출기
            reward_calculator: 실시간 보상 계산기
            online_trainer: 온라인 RL 학습기 (옵션)
        """
        self.rl_agent = rl_agent
        self.state_extractor = state_extractor
        self.reward_calculator = reward_calculator
        self.online_trainer = online_trainer
        
        # 최근 결정 캐시 (피드백 수집용)
        self.recent_decisions = {}
        
        logger.info("실시간 RL 통합기 초기화 완료")
    
    def process_packet_with_rl(self, 
                               packet_info: Dict[str, Any],
                               rf_threat_probability: float) -> Tuple[int, Dict[str, Any]]:
        """
        패킷을 RL 에이전트로 처리하여 액션 결정
        
        Args:
            packet_info: 패킷 정보
            rf_threat_probability: RF 위협 확률
        
        Returns:
            (action, details): 선택된 액션과 상세 정보
        """
        try:
            # 1. 상태 추출
            context = {'threat_probability': rf_threat_probability}
            state = self.state_extractor.extract_state(packet_info, context)
            
            # 2. RL 에이전트 액션 선택
            action = self.rl_agent.act(state)
            
            # 3. 결정 정보 구성
            decision_info = {
                'state': state,
                'action': action,
                'rf_probability': rf_threat_probability,
                'timestamp': time.time(),
                'packet_source': packet_info.get('source', 'unknown')
            }
            
            # 4. 최근 결정 캐시 (피드백용)
            decision_key = f"{packet_info.get('source', '')}_{int(time.time())}"
            self.recent_decisions[decision_key] = decision_info
            
            # 캐시 크기 제한
            if len(self.recent_decisions) > 1000:
                # 가장 오래된 결정 제거
                oldest_key = min(self.recent_decisions.keys(), 
                               key=lambda k: self.recent_decisions[k]['timestamp'])
                del self.recent_decisions[oldest_key]
            
            logger.debug(f"RL 액션 선택: {action} (위협확률: {rf_threat_probability:.2f})")
            
            return action, decision_info
            
        except Exception as e:
            logger.error(f"RL 패킷 처리 오류: {e}")
            # 오류 시 보수적 액션 (추가 검사)
            return 4, {'error': str(e)}
    
    def provide_feedback(self, 
                        decision_key: str,
                        actual_threat: Optional[bool] = None,
                        system_load: float = 0.0,
                        response_time: float = 0.0):
        """
        RL 결정에 대한 피드백 제공 (학습용)
        
        Args:
            decision_key: 결정 키
            actual_threat: 실제 위협 여부 (검증된 경우)
            system_load: 시스템 부하
            response_time: 응답 시간
        """
        try:
            if decision_key not in self.recent_decisions:
                logger.debug(f"결정 키 없음: {decision_key}")
                return
            
            decision = self.recent_decisions[decision_key]
            state = decision['state']
            action = decision['action']
            rf_probability = decision['rf_probability']
            
            # 보상 계산
            reward, reward_details = self.reward_calculator.calculate_reward(
                threat_probability=rf_probability,
                action_taken=action,
                actual_threat=actual_threat,
                system_load=system_load,
                response_time=response_time
            )
            
            # 다음 상태 (단순화: 현재와 동일)
            next_state = state
            done = False
            
            # 온라인 학습기에 경험 추가
            if self.online_trainer:
                self.online_trainer.add_experience(
                    state, action, reward, next_state, done
                )
            
            logger.debug(f"피드백 제공 - 보상: {reward:.2f}, "
                        f"분류: {reward_details.get('classification', 'unknown')}")
            
            # 처리된 결정 제거
            del self.recent_decisions[decision_key]
            
        except Exception as e:
            logger.error(f"피드백 제공 오류: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """통합기 통계 반환"""
        stats = {
            'pending_decisions': len(self.recent_decisions),
            'rl_agent_mode': getattr(self.rl_agent, 'mode', 'unknown')
        }
        
        if self.online_trainer:
            stats['online_learning'] = self.online_trainer.get_statistics()
        
        return stats


# 전역 싱글톤 인스턴스들
_global_online_trainer = None
_global_integrator = None


def get_online_trainer(rl_agent, **kwargs) -> OnlineRLTrainer:
    """
    전역 온라인 학습기 인스턴스 반환 (싱글톤 패턴)
    
    Args:
        rl_agent: RL 에이전트
        **kwargs: OnlineRLTrainer 추가 인자
    
    Returns:
        OnlineRLTrainer 인스턴스
    """
    global _global_online_trainer
    if _global_online_trainer is None:
        _global_online_trainer = OnlineRLTrainer(rl_agent, **kwargs)
    return _global_online_trainer


def get_rl_integrator(rl_agent, state_extractor, reward_calculator, 
                      online_trainer=None) -> RealTimeRLIntegrator:
    """
    전역 RL 통합기 인스턴스 반환 (싱글톤 패턴)
    
    Returns:
        RealTimeRLIntegrator 인스턴스
    """
    global _global_integrator
    if _global_integrator is None:
        _global_integrator = RealTimeRLIntegrator(
            rl_agent, state_extractor, reward_calculator, online_trainer
        )
    return _global_integrator

