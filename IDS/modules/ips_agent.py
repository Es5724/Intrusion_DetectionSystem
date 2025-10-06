# -*- coding: utf-8 -*-

"""
IPS Agent 클래스

IPSAgent_RL.py의 main() 함수를 클래스로 캡슐화하여
모듈화, 테스트 가능성, 재사용성을 향상시킵니다.
"""

import os
import sys
import time
import logging
import joblib
import pandas as pd
from typing import Optional, Dict, Any
from datetime import datetime

# 시스템 관리 모듈
from .system_state import get_system_state, SystemState
from .thread_manager import get_thread_manager, ThreadManager
from .lazy_loading import get_lazy_importer

logger = logging.getLogger('IPSAgent')


class IPSAgent:
    """
    침입 방지 시스템 (IPS) 에이전트 클래스
    
    메인 시스템을 캡슐화하여 생명주기를 관리하고,
    모든 컴포넌트를 통합합니다.
    
    Attributes:
        mode (str): 운영 모드 ('lightweight' 또는 'performance')
        max_packets (int): 최대 캡처 패킷 수 (0이면 무제한)
        state (SystemState): 시스템 상태 관리자
        thread_manager (ThreadManager): 스레드 관리자
        
    Example:
        >>> agent = IPSAgent(mode='lightweight')
        >>> agent.initialize()
        >>> agent.start()
        >>> # ... 시스템 실행 ...
        >>> agent.stop()
    """
    
    def __init__(
        self,
        mode: str = 'lightweight',
        max_packets: int = 0,
        model_path: str = 'kisti_random_forest_model.pkl',
        config_path: str = 'defense_config.json'
    ):
        """
        IPSAgent 초기화
        
        Args:
            mode: 운영 모드 ('lightweight' 또는 'performance')
            max_packets: 최대 캡처 패킷 수
            model_path: RF 모델 파일 경로
            model_path: RF 모델 파일 경로
            config_path: 방어 설정 파일 경로
        """
        self.mode = mode
        self.max_packets = max_packets
        self.model_path = model_path
        self.config_path = config_path
        
        # 시스템 관리
        self.state = get_system_state()
        self.thread_manager = get_thread_manager()
        self.lazy_importer = get_lazy_importer()
        
        # 설정 저장
        self.state.set_config('mode', mode)
        self.state.set_config('max_packets', max_packets)
        self.state.set_config('model_path', model_path)
        self.state.set_config('config_path', config_path)
        
        # 컴포넌트 (초기화 후 설정됨)
        self.ml_model = None
        self.defense_manager = None
        self.packet_capture = None
        self.online_trainer = None
        self.vuln_scanner = None
        self.integrated_mode = False
        
        logger.info(f"IPSAgent 생성됨 (mode={mode}, max_packets={max_packets})")
    
    def initialize(self) -> bool:
        """
        시스템 컴포넌트 초기화
        
        Returns:
            bool: 초기화 성공 여부
        """
        try:
            logger.info("=" * 60)
            logger.info("IPS 에이전트 초기화 시작")
            logger.info("=" * 60)
            
            # 1. ML 모델 로드
            if not self._load_ml_model():
                logger.error("ML 모델 로드 실패")
                return False
            
            # 2. 방어 메커니즘 초기화
            if not self._initialize_defense():
                logger.error("방어 메커니즘 초기화 실패")
                return False
            
            # 3. 패킷 캡처 초기화
            if not self._initialize_packet_capture():
                logger.error("패킷 캡처 초기화 실패")
                return False
            
            # 4. 통합 모듈 초기화 (RL + 취약점 스캐너)
            self._initialize_integrated_modules()
            
            logger.info("✅ IPS 에이전트 초기화 완료")
            return True
            
        except Exception as e:
            logger.error(f"초기화 중 오류 발생: {e}")
            return False
    
    def _load_ml_model(self) -> bool:
        """ML 모델 로드"""
        try:
            if not os.path.exists(self.model_path):
                logger.warning(f"모델 파일이 없습니다: {self.model_path}")
                return False
            
            self.ml_model = joblib.load(self.model_path)
            self.state.register_component('ml_model', self.ml_model)
            logger.info(f"✅ RF 모델 로드 완료: {self.model_path}")
            return True
            
        except Exception as e:
            logger.error(f"모델 로드 실패: {e}")
            return False
    
    def _initialize_defense(self) -> bool:
        """방어 메커니즘 초기화"""
        try:
            defense_modules = self.lazy_importer.get_module('defense')
            create_defense_manager = defense_modules['create_defense_manager']
            
            self.defense_manager = create_defense_manager(
                config_file=self.config_path,
                rf_model=self.ml_model,
                mode=self.mode
            )
            
            self.state.register_component('defense_manager', self.defense_manager)
            logger.info("✅ 방어 메커니즘 초기화 완료")
            return True
            
        except Exception as e:
            logger.error(f"방어 메커니즘 초기화 실패: {e}")
            return False
    
    def _initialize_packet_capture(self) -> bool:
        """패킷 캡처 초기화"""
        try:
            packet_modules = self.lazy_importer.get_module('packet_capture')
            OptimizedPacketCapture = packet_modules['OptimizedPacketCapture']
            
            self.packet_capture = OptimizedPacketCapture(
                interface=None,  # 자동 선택
                max_packets=self.max_packets
            )
            
            self.state.register_component('packet_capture', self.packet_capture)
            logger.info("✅ 패킷 캡처 초기화 완료")
            return True
            
        except Exception as e:
            logger.error(f"패킷 캡처 초기화 실패: {e}")
            return False
    
    def _initialize_integrated_modules(self) -> None:
        """통합 모듈 초기화 (RL + 취약점 스캐너)"""
        try:
            integrated_modules = self.lazy_importer.get_module('integrated_modules')
            if not integrated_modules:
                logger.info("통합 모듈 비활성화 - 기본 모드로 실행")
                return
            
            # RL 시스템 초기화
            state_extractor = integrated_modules['get_state_extractor']()
            reward_calculator = integrated_modules['get_reward_calculator']()
            
            self.state.register_component('state_extractor', state_extractor)
            self.state.register_component('reward_calculator', reward_calculator)
            
            # Conservative RL 에이전트 초기화
            rl_modules = self.lazy_importer.get_module('conservative_rl')
            if rl_modules:
                ConservativeRLAgent = rl_modules['ConservativeRLAgent']
                DefensePolicyEnv = rl_modules['DefensePolicyEnv']
                
                env = DefensePolicyEnv()
                agent = ConservativeRLAgent(
                    state_size=10,
                    action_size=6,
                    mode="standard",
                    use_prioritized_replay=True,
                    buffer_capacity=10000
                )
                
                # 기존 모델 로드
                agent_path = 'defense_policy_agent.pth'
                if os.path.exists(agent_path):
                    agent.load_model(agent_path)
                    logger.info("기존 Conservative RL 모델 로드 완료")
                
                self.state.register_component('rl_agent', agent)
                self.state.register_component('rl_env', env)
                
                # 온라인 학습기 초기화
                self.online_trainer = integrated_modules['get_online_trainer'](
                    agent,
                    learning_interval=10,
                    min_experiences=32,
                    batch_size=32
                )
                
                self.state.register_component('online_trainer', self.online_trainer)
                
                # RL 통합기 초기화
                rl_integrator = integrated_modules['get_rl_integrator'](
                    agent,
                    state_extractor,
                    reward_calculator,
                    self.online_trainer
                )
                
                self.state.register_component('rl_integrator', rl_integrator)
            
            # 취약점 스캐너 초기화
            try:
                self.vuln_scanner = integrated_modules['get_auto_scanner'](
                    network_range="192.168.0.0/24"
                )
                self.state.register_component('vuln_scanner', self.vuln_scanner)
            except Exception as e:
                logger.warning(f"취약점 스캐너 초기화 실패: {e}")
            
            # 우선순위 분석기 초기화
            try:
                priority_analyzer = integrated_modules['get_priority_analyzer']()
                self.state.register_component('priority_analyzer', priority_analyzer)
            except Exception as e:
                logger.warning(f"우선순위 분석기 초기화 실패: {e}")
            
            self.integrated_mode = True
            logger.info("✅ 통합 모듈 초기화 완료 (반응형 AI + 취약점 진단)")
            
        except Exception as e:
            logger.warning(f"통합 모듈 초기화 실패: {e}")
            self.integrated_mode = False
    
    def start(self) -> bool:
        """
        시스템 시작
        
        Returns:
            bool: 시작 성공 여부
        """
        try:
            logger.info("=" * 60)
            logger.info("IPS 에이전트 시작")
            logger.info("=" * 60)
            
            # 스레드 등록 및 시작은 여기서 구현
            # (현재는 초기 구조만 작성)
            
            logger.info("✅ IPS 에이전트 시작 완료")
            return True
            
        except Exception as e:
            logger.error(f"시작 중 오류 발생: {e}")
            return False
    
    def stop(self, timeout: float = 10.0) -> bool:
        """
        시스템 정지 (graceful shutdown)
        
        Args:
            timeout: 최대 대기 시간 (초)
        
        Returns:
            bool: 정지 성공 여부
        """
        try:
            logger.info("=" * 60)
            logger.info("IPS 에이전트 정지 시작")
            logger.info("=" * 60)
            
            # 중지 요청
            self.state.request_stop()
            
            # 통합 서비스 중지
            if self.online_trainer:
                self.online_trainer.stop()
                logger.info("온라인 RL 학습기 중지됨")
            
            if self.vuln_scanner:
                self.vuln_scanner.stop()
                logger.info("취약점 스캐너 중지됨")
            
            # 모든 스레드 중지
            stop_results = self.thread_manager.stop_all(timeout=timeout)
            success_count = sum(stop_results.values())
            total_count = len(stop_results)
            
            logger.info(f"{success_count}/{total_count}개 스레드 정상 종료됨")
            
            # 정리
            self.thread_manager.cleanup()
            
            logger.info("✅ IPS 에이전트 정지 완료")
            return all(stop_results.values())
            
        except Exception as e:
            logger.error(f"정지 중 오류 발생: {e}")
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """
        시스템 상태 조회
        
        Returns:
            Dict: 시스템 상태 정보
        """
        return {
            'mode': self.mode,
            'integrated_mode': self.integrated_mode,
            'system_state': self.state.get_summary(),
            'threads': self.thread_manager.get_all_status(),
            'components': self.state.list_components()
        }
    
    def __repr__(self) -> str:
        """문자열 표현"""
        return f"IPSAgent(mode='{self.mode}', integrated={self.integrated_mode})"


# 팩토리 함수
def create_ips_agent(
    mode: str = 'lightweight',
    max_packets: int = 0,
    model_path: str = 'kisti_random_forest_model.pkl',
    config_path: str = 'defense_config.json'
) -> IPSAgent:
    """
    IPSAgent 인스턴스 생성 (팩토리 함수)
    
    Args:
        mode: 운영 모드
        max_packets: 최대 패킷 수
        model_path: 모델 파일 경로
        config_path: 설정 파일 경로
    
    Returns:
        IPSAgent: 생성된 에이전트 인스턴스
    """
    return IPSAgent(
        mode=mode,
        max_packets=max_packets,
        model_path=model_path,
        config_path=config_path
    )


if __name__ == '__main__':
    # 간단한 테스트
    print("=" * 60)
    print("IPSAgent 클래스 테스트")
    print("=" * 60)
    
    agent = create_ips_agent(mode='lightweight')
    print(f"\n✅ 에이전트 생성: {agent}")
    
    print("\n초기화 중...")
    if agent.initialize():
        print("✅ 초기화 성공")
        
        print("\n상태 조회:")
        status = agent.get_status()
        for key, value in status.items():
            print(f"  {key}: {value}")
        
        print("\n정지 중...")
        if agent.stop():
            print("✅ 정지 성공")
    else:
        print("❌ 초기화 실패")

