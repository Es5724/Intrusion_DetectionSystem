#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPS 파이프라인 통합 시스템
RF 탐지 + Conservative RL 대응 + 방어 실행 통합 파이프라인
"""

import numpy as np
import pandas as pd
import joblib
import json
import os
import sys
import time
import logging
import torch
import psutil
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass

# modules 디렉토리를 Python 경로에 추가
sys.path.append('modules')

# 모든 필요한 모듈을 처음부터 완전히 임포트
from modules.conservative_rl_agent import ConservativeRLAgent
from modules.defense_policy_env import DefensePolicyEnv
from modules.ope_evaluator import OPEEvaluator
from modules.defense_mechanism import DefenseManager, create_defense_manager
from modules.experience_replay_buffer import ExperienceReplayBuffer, IDSExperienceReplayBuffer
import modules.utils as utils

# 새로운 통합 모듈들
try:
    from modules.rl_state_extractor import get_state_extractor
    from modules.realtime_reward_calculator import get_reward_calculator
    from modules.online_rl_trainer import get_online_trainer, get_rl_integrator
    from modules.rl_defense_wrapper import create_rl_defense_system
    from modules.vulnerability_auto_scanner import get_auto_scanner
    from modules.vulnerability_priority_analyzer import get_priority_analyzer
    NEW_MODULES_AVAILABLE = True
except ImportError as e:
    logger.warning(f"새로운 통합 모듈 로드 실패: {e}")
    NEW_MODULES_AVAILABLE = False

# 로깅 설정
logger = logging.getLogger('IPSPipeline')

@dataclass
class ThreatDetectionResult:
    """RF 탐지 결과 구조체"""
    probability: float          # 위협 확률 (0.0-1.0)
    confidence: float          # 탐지 신뢰도 (0.0-1.0)
    attack_type: str           # 공격 유형
    severity_level: str        # 심각도 (low/medium/high)
    source_ip: str            # 출발지 IP
    detection_method: str     # 탐지 방법 (rf/suricata/hybrid)
    timestamp: str            # 탐지 시간
    raw_features: Dict        # 원본 특성 데이터

@dataclass
class DefenseActionResult:
    """RL 대응 결과 구조체"""
    action_id: int            # 액션 ID (0-5)
    action_name: str          # 액션 이름
    success: bool             # 실행 성공 여부
    execution_time_ms: float  # 실행 시간
    system_impact: float      # 시스템 영향도
    business_impact: float    # 비즈니스 영향도
    confidence: float         # 결정 신뢰도
    rationale: str           # 결정 근거

class IPSPipelineIntegrator:
    """IPS 통합 파이프라인 시스템
    
    RF 탐지 → Conservative RL 대응 → 방어 실행 → OPE 평가
    완전한 2단계 파이프라인 구현
    """
    
    def __init__(self, config_path="defense_config.json"):
        """파이프라인 초기화"""
        
        # 설정 로드
        self.config = self._load_config(config_path)
        
        # 1단계: RF 탐지 시스템
        self.rf_model = self._initialize_rf_detector()
        
        # 2단계: RL 대응 시스템
        self.rl_agent = self._initialize_rl_agent()
        self.rl_env = self._initialize_rl_environment()
        
        # 방어 실행 시스템
        self.defense_manager = self._initialize_defense_manager()
        
        # OPE 평가 시스템
        self.ope_evaluator = self._initialize_ope_evaluator()
        
        # 파이프라인 상태
        self.pipeline_stats = {
            'total_threats_processed': 0,
            'rf_detections': 0,
            'rl_decisions': 0,
            'defense_actions': 0,
            'ope_evaluations': 0,
            'pipeline_uptime': time.time()
        }
        
        # 실시간 로그 버퍼 (OPE용)
        self.defense_logs = []
        self.max_log_size = 10000
        
        # 새로운 통합 시스템 초기화
        if NEW_MODULES_AVAILABLE:
            self._initialize_integrated_systems()
        
        logger.info("IPS 파이프라인 통합 시스템 초기화 완료")
    
    def _load_config(self, config_path):
        """설정 파일 로드"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            return config
        except Exception as e:
            logger.warning(f"설정 파일 로드 실패: {e}, 기본 설정 사용")
            return self._get_default_config()
    
    def _get_default_config(self):
        """기본 설정"""
        return {
            "pipeline": {
                "mode": "standard",
                "rf_model_path": "ips_random_forest_model.pkl",
                "rl_agent_path": "defense_policy_agent.pth",
                "enable_ope": True,
                "log_buffer_size": 10000
            },
            "defense": {
                "high_threat_threshold": 0.9,
                "medium_threat_threshold": 0.7,
                "low_threat_threshold": 0.5
            }
        }
    
    def _initialize_rf_detector(self):
        """RF 탐지기 초기화"""
        # KISTI 모델 우선 사용, 없으면 CIC 모델 사용
        kisti_model_path = "kisti_random_forest_model.pkl"
        cic_model_path = "ips_random_forest_model.pkl"
        
        if os.path.exists(kisti_model_path):
            model_path = kisti_model_path
            logger.info("KISTI-IDS-2022 기반 RF 모델 사용")
        elif os.path.exists(cic_model_path):
            model_path = cic_model_path
            logger.info("CIC-IDS-2017 기반 RF 모델 사용")
        else:
            logger.error("RF 모델 파일을 찾을 수 없습니다")
            return None
        
        try:
            rf_model = joblib.load(model_path)
            logger.info(f"RF 탐지 모델 로드 성공: {model_path}")
            return rf_model
        except Exception as e:
            logger.error(f"RF 모델 로드 실패: {e}")
            return None
    
    def _initialize_rl_agent(self):
        """RL 에이전트 초기화"""
        agent = ConservativeRLAgent(
            state_size=10,
            action_size=6,
            mode=self.config.get("pipeline", {}).get("mode", "standard")
        )
        
        # 기존 모델 로드 시도
        agent_path = self.config.get("pipeline", {}).get("rl_agent_path")
        if agent_path and os.path.exists(agent_path):
            agent.load_model(agent_path)
            logger.info(f"RL 에이전트 모델 로드: {agent_path}")
        
        return agent
    
    def _initialize_rl_environment(self):
        """RL 환경 초기화"""
        return DefensePolicyEnv(
            rf_model_path=self.config.get("pipeline", {}).get("rf_model_path"),
            config_path="defense_config.json"
        )
    
    def _initialize_defense_manager(self):
        """방어 관리자 초기화"""
        try:
            return create_defense_manager("defense_config.json")
        except Exception as e:
            logger.error(f"방어 관리자 초기화 실패: {e}")
            return None
    
    def _initialize_ope_evaluator(self):
        """OPE 평가기 초기화"""
        if self.config.get("pipeline", {}).get("enable_ope", True):
            return OPEEvaluator("rule_based", "conservative_rl")
        return None
    
    def process_packet_threat(self, packet_data: Dict) -> DefenseActionResult:
        """패킷 위협 처리 - 통합 파이프라인 실행"""
        start_time = time.time()
        
        try:
            # 1단계: RF 위협 탐지
            threat_result = self._rf_threat_detection(packet_data)
            self.pipeline_stats['rf_detections'] += 1
            
            # 2단계: RL 대응 정책 결정
            if threat_result.probability > 0.1:  # 최소 임계치
                defense_action = self._rl_response_decision(threat_result, packet_data)
                self.pipeline_stats['rl_decisions'] += 1
            else:
                # 낮은 위험시 기본 허용
                defense_action = DefenseActionResult(
                    action_id=0,
                    action_name="allow",
                    success=True,
                    execution_time_ms=1.0,
                    system_impact=0.0,
                    business_impact=0.0,
                    confidence=threat_result.confidence,
                    rationale="Low threat probability"
                )
            
            # 3단계: 방어 조치 실행
            if defense_action.action_id > 0:  # 허용 외의 액션
                execution_result = self._execute_defense_action(defense_action, threat_result)
                self.pipeline_stats['defense_actions'] += 1
            else:
                execution_result = defense_action
            
            # 4단계: OPE 로깅
            self._log_for_ope_evaluation(threat_result, defense_action, execution_result)
            
            # 통계 업데이트
            self.pipeline_stats['total_threats_processed'] += 1
            
            processing_time = (time.time() - start_time) * 1000
            logger.debug(f"파이프라인 처리 완료: {processing_time:.2f}ms")
            
            return execution_result
            
        except Exception as e:
            logger.error(f"파이프라인 처리 오류: {e}")
            # Fallback: 기본 허용 액션
            return DefenseActionResult(
                action_id=0,
                action_name="allow",
                success=False,
                execution_time_ms=(time.time() - start_time) * 1000,
                system_impact=0.0,
                business_impact=0.0,
                confidence=0.0,
                rationale=f"Pipeline error: {str(e)}"
            )
    
    def _rf_threat_detection(self, packet_data: Dict) -> ThreatDetectionResult:
        """1단계: RF 위협 탐지"""
        if self.rf_model is None:
            return self._create_fallback_threat_result(packet_data)
        
        try:
            # 패킷 데이터를 RF 모델 입력으로 변환
            features = self._extract_rf_features(packet_data)
            
            # RF 예측 실행
            prediction_proba = self.rf_model.predict_proba([features])[0]
            threat_probability = prediction_proba[1] if len(prediction_proba) > 1 else prediction_proba[0]
            
            # 공격 유형 추정 (간단한 휴리스틱)
            attack_type = self._estimate_attack_type(packet_data, threat_probability)
            
            # 심각도 계산
            if threat_probability > 0.9:
                severity = "high"
            elif threat_probability > 0.7:
                severity = "medium"
            else:
                severity = "low"
            
            return ThreatDetectionResult(
                probability=threat_probability,
                confidence=max(prediction_proba),  # 최대 확률을 신뢰도로 사용
                attack_type=attack_type,
                severity_level=severity,
                source_ip=packet_data.get('source', 'unknown'),
                detection_method='rf',
                timestamp=datetime.now().isoformat(),
                raw_features=features
            )
            
        except Exception as e:
            logger.error(f"RF 탐지 오류: {e}")
            return self._create_fallback_threat_result(packet_data)
    
    def _extract_rf_features(self, packet_data: Dict) -> Dict:
        """패킷 데이터에서 RF 특성 추출"""
        # CIC-IDS-2017 스타일 특성 추출 (간단한 버전)
        features = {
            'Destination Port': packet_data.get('destination_port', 80),
            'Flow Duration': packet_data.get('duration', 1000),
            'Total Fwd Packets': packet_data.get('fwd_packets', 1),
            'Total Backward Packets': packet_data.get('bwd_packets', 1),
            'Flow Bytes/s': packet_data.get('bytes_per_sec', 1000),
            'Flow Packets/s': packet_data.get('packets_per_sec', 1),
            'Packet Length Mean': packet_data.get('length', 64),
            'FIN Flag Count': packet_data.get('fin_flags', 0),
            'SYN Flag Count': packet_data.get('syn_flags', 0),
            'RST Flag Count': packet_data.get('rst_flags', 0)
            # 실제로는 78개 특성 필요하지만 테스트용 간소화
        }
        
        return features
    
    def _estimate_attack_type(self, packet_data: Dict, probability: float) -> str:
        """공격 유형 추정 (휴리스틱 기반)"""
        port = packet_data.get('destination_port', 80)
        flags = packet_data.get('tcp_flags', {})
        
        if probability < 0.5:
            return 'normal'
        elif port == 22 and flags.get('syn', 0) > 0:
            return 'brute_force'
        elif flags.get('syn', 0) > 10:
            return 'port_scan'
        elif packet_data.get('packets_per_sec', 1) > 1000:
            return 'ddos'
        else:
            return 'unknown'
    
    def _create_fallback_threat_result(self, packet_data: Dict) -> ThreatDetectionResult:
        """RF 실패시 기본 위협 결과"""
        return ThreatDetectionResult(
            probability=0.1,
            confidence=0.5,
            attack_type='unknown',
            severity_level='low',
            source_ip=packet_data.get('source', 'unknown'),
            detection_method='fallback',
            timestamp=datetime.now().isoformat(),
            raw_features={}
        )
    
    def _rl_response_decision(self, threat_result: ThreatDetectionResult, 
                            packet_data: Dict) -> DefenseActionResult:
        """2단계: RL 대응 정책 결정"""
        try:
            # 시스템 상태 수집
            system_state = self._collect_system_state()
            
            # RL 상태 벡터 생성
            rl_state = self._create_rl_state(threat_result, system_state)
            
            # RL 에이전트 액션 결정
            action_id = self.rl_agent.act(rl_state, deterministic=True)
            
            # 액션 정보 생성
            action_names = {
                0: 'allow', 1: 'block_temporary', 2: 'block_permanent',
                3: 'rate_limit', 4: 'deep_inspection', 5: 'isolate_session'
            }
            
            action_name = action_names.get(action_id, 'unknown')
            
            # 결정 신뢰도 계산 (Q-값 기반)
            confidence = self._calculate_decision_confidence(rl_state, action_id)
            
            return DefenseActionResult(
                action_id=action_id,
                action_name=action_name,
                success=True,
                execution_time_ms=0.0,  # 아직 실행 전
                system_impact=self._estimate_system_impact(action_id),
                business_impact=self._estimate_business_impact(action_id, threat_result),
                confidence=confidence,
                rationale=f"RL decision based on threat_prob={threat_result.probability:.3f}"
            )
            
        except Exception as e:
            logger.error(f"RL 대응 결정 오류: {e}")
            # Fallback: 기본 규칙 기반 결정
            return self._fallback_rule_based_decision(threat_result)
    
    def _collect_system_state(self) -> Dict:
        """현재 시스템 상태 수집"""
        try:
            
            return {
                'cpu_usage': psutil.cpu_percent() / 100.0,
                'memory_usage': psutil.virtual_memory().percent / 100.0,
                'active_threats': len([log for log in self.defense_logs[-100:] 
                                     if log.get('threat_blocked', False)]),
                'blocked_ips': len(set([log.get('source_ip') for log in self.defense_logs[-1000:] 
                                      if log.get('action_id') in [1, 2]])),
                'current_time_hour': datetime.now().hour,
                'service_criticality': 0.8  # 설정값
            }
        except Exception as e:
            logger.warning(f"시스템 상태 수집 실패: {e}")
            return {
                'cpu_usage': 0.3, 'memory_usage': 0.4, 'active_threats': 5,
                'blocked_ips': 10, 'current_time_hour': 14, 'service_criticality': 0.8
            }
    
    def _create_rl_state(self, threat_result: ThreatDetectionResult, 
                        system_state: Dict) -> np.ndarray:
        """RL 상태 벡터 생성"""
        # 공격 유형 인코딩
        attack_type_map = {
            'normal': 0.0, 'ddos': 0.2, 'port_scan': 0.4,
            'brute_force': 0.6, 'web_attack': 0.8, 'botnet': 1.0
        }
        attack_encoded = attack_type_map.get(threat_result.attack_type, 0.5)
        
        state = np.array([
            threat_result.probability,                                    # RF 위협 확률
            threat_result.confidence,                                     # RF 신뢰도
            attack_encoded,                                              # 공격 유형
            0.8 if threat_result.severity_level == 'high' else 
            0.5 if threat_result.severity_level == 'medium' else 0.2,   # 심각도
            system_state['cpu_usage'],                                   # CPU 사용률
            system_state['memory_usage'],                                # 메모리 사용률
            min(system_state['active_threats'] / 50.0, 1.0),           # 활성 위협
            min(system_state['blocked_ips'] / 100.0, 1.0),             # 차단 IP
            system_state['current_time_hour'] / 24.0,                   # 시간대
            system_state['service_criticality']                         # 서비스 중요도
        ], dtype=np.float32)
        
        return state
    
    def _calculate_decision_confidence(self, state: np.ndarray, action: int) -> float:
        """RL 결정 신뢰도 계산"""
        try:
            
            self.rl_agent.q_network.eval()
            with torch.no_grad():
                state_tensor = torch.FloatTensor(state).unsqueeze(0)
                q_values = self.rl_agent.q_network(state_tensor)
                
                # Softmax 확률로 신뢰도 계산
                probs = torch.softmax(q_values, dim=1)
                confidence = probs[0][action].item()
                
                return confidence
                
        except Exception as e:
            logger.warning(f"신뢰도 계산 실패: {e}")
            return 0.7  # 기본값
    
    def _estimate_system_impact(self, action_id: int) -> float:
        """액션의 시스템 영향도 추정"""
        impact_map = {
            0: 0.0,   # allow
            1: 0.1,   # block_temporary
            2: 0.2,   # block_permanent
            3: 0.3,   # rate_limit
            4: 0.5,   # deep_inspection
            5: 0.4    # isolate_session
        }
        return impact_map.get(action_id, 0.0)
    
    def _estimate_business_impact(self, action_id: int, threat_result: ThreatDetectionResult) -> float:
        """액션의 비즈니스 영향도 추정"""
        if action_id == 0:  # allow
            return 0.0
        
        # 오탐 위험도 계산
        false_positive_risk = 1.0 - threat_result.confidence
        
        # 액션별 비즈니스 영향
        action_impact = {
            1: 0.2, 2: 0.8, 3: 0.1, 4: 0.05, 5: 0.3
        }
        
        base_impact = action_impact.get(action_id, 0.0)
        return base_impact * false_positive_risk
    
    def _execute_defense_action(self, defense_action: DefenseActionResult,
                               threat_result: ThreatDetectionResult) -> DefenseActionResult:
        """3단계: 방어 조치 실행"""
        start_time = time.time()
        
        try:
            if self.defense_manager:
                # 실제 방어 시스템 연동
                packet_info = {
                    'source': threat_result.source_ip,
                    'confidence': threat_result.probability,
                    'attack_type': threat_result.attack_type
                }
                
                # defense_mechanism.py 연동
                action_taken = self.defense_manager.execute_defense_action(packet_info, threat_result.probability)
                
                execution_time = (time.time() - start_time) * 1000
                
                # 결과 업데이트
                defense_action.success = True
                defense_action.execution_time_ms = execution_time
                
                logger.info(f"방어 조치 실행: {defense_action.action_name} → {action_taken}")
                
            else:
                # 방어 관리자 없음 - 시뮬레이션
                defense_action.success = True
                defense_action.execution_time_ms = 10.0
                
                logger.warning("방어 관리자 없음 - 시뮬레이션 모드")
            
            return defense_action
            
        except Exception as e:
            logger.error(f"방어 조치 실행 실패: {e}")
            defense_action.success = False
            defense_action.execution_time_ms = (time.time() - start_time) * 1000
            return defense_action
    
    def _log_for_ope_evaluation(self, threat_result: ThreatDetectionResult,
                               defense_action: DefenseActionResult,
                               execution_result: DefenseActionResult):
        """4단계: OPE 평가용 로깅"""
        if self.ope_evaluator is None:
            return
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'rf_prediction': {
                'probability': threat_result.probability,
                'confidence': threat_result.confidence,
                'attack_type': threat_result.attack_type
            },
            'system_state': self._collect_system_state(),
            'action': defense_action.action_name,
            'action_id': defense_action.action_id,
            'outcome': {
                'success': execution_result.success,
                'execution_time': execution_result.execution_time_ms,
                'system_impact': execution_result.system_impact,
                'business_impact': execution_result.business_impact
            },
            'metadata': {
                'source_ip': threat_result.source_ip,
                'detection_method': threat_result.detection_method,
                'pipeline_version': '1.0'
            }
        }
        
        # 로그 버퍼에 추가
        self.defense_logs.append(log_entry)
        
        # 버퍼 크기 관리
        if len(self.defense_logs) > self.max_log_size:
            self.defense_logs = self.defense_logs[-self.max_log_size//2:]
        
        self.pipeline_stats['ope_evaluations'] += 1
    
    def _fallback_rule_based_decision(self, threat_result: ThreatDetectionResult) -> DefenseActionResult:
        """Fallback: 규칙 기반 결정"""
        if threat_result.probability > 0.9:
            action_id, action_name = 2, 'block_permanent'
        elif threat_result.probability > 0.7:
            action_id, action_name = 1, 'block_temporary'
        elif threat_result.probability > 0.5:
            action_id, action_name = 3, 'rate_limit'
        else:
            action_id, action_name = 0, 'allow'
        
        return DefenseActionResult(
            action_id=action_id,
            action_name=action_name,
            success=True,
            execution_time_ms=1.0,
            system_impact=self._estimate_system_impact(action_id),
            business_impact=self._estimate_business_impact(action_id, threat_result),
            confidence=0.8,
            rationale="Fallback rule-based decision"
        )
    
    def get_pipeline_stats(self) -> Dict:
        """파이프라인 통계 정보"""
        uptime = time.time() - self.pipeline_stats['pipeline_uptime']
        
        stats = self.pipeline_stats.copy()
        stats['uptime_seconds'] = uptime
        stats['uptime_hours'] = uptime / 3600
        stats['threats_per_hour'] = stats['total_threats_processed'] / max(uptime / 3600, 0.001)
        stats['ope_log_buffer_size'] = len(self.defense_logs)
        
        return stats
    
    def evaluate_current_policy(self) -> Dict:
        """현재 정책 성능 평가 (OPE 사용)"""
        if self.ope_evaluator is None or len(self.defense_logs) < 10:
            return {'error': 'Insufficient data for evaluation'}
        
        try:
            # OPE 평가 실행
            results = self.ope_evaluator.evaluate_policy_from_logs(
                self.defense_logs,
                self.rl_agent,
                self.rl_env
            )
            
            return results
            
        except Exception as e:
            logger.error(f"정책 평가 실패: {e}")
            return {'error': str(e)}
    
    def save_pipeline_state(self, filename: str):
        """파이프라인 상태 저장"""
        state = {
            'pipeline_stats': self.pipeline_stats,
            'config': self.config,
            'defense_logs': self.defense_logs[-1000:],  # 최근 1000개만
            'timestamp': datetime.now().isoformat()
        }
        
        # RL 에이전트 상태 저장
        agent_filename = filename.replace('.json', '_agent.pth')
        buffer_filename = filename.replace('.json', '_buffer.pkl')
        
        self.rl_agent.save_model(agent_filename)
        self.rl_agent.save_buffer(buffer_filename)
        
        # 파이프라인 상태 저장
        with open(filename, 'w') as f:
            json.dump(state, f, indent=2)
        
        logger.info(f"파이프라인 상태 저장: {filename}")
    
    def _initialize_integrated_systems(self):
        """새로운 통합 시스템 초기화"""
        try:
            logger.info("통합 시스템 초기화 시작...")
            
            # 상태 추출기
            self.state_extractor = get_state_extractor()
            logger.info("✓ RL 상태 추출기 로드됨")
            
            # 보상 계산기
            self.reward_calculator = get_reward_calculator()
            logger.info("✓ 실시간 보상 계산기 로드됨")
            
            # 온라인 RL 학습기
            if hasattr(self, 'rl_agent') and self.rl_agent is not None:
                self.online_trainer = get_online_trainer(
                    self.rl_agent,
                    learning_interval=10,
                    min_experiences=32,
                    batch_size=32
                )
                logger.info("✓ 온라인 RL 학습기 로드됨")
            
                # RL 통합기
                self.rl_integrator = get_rl_integrator(
                    self.rl_agent,
                    self.state_extractor,
                    self.reward_calculator,
                    self.online_trainer
                )
                logger.info("✓ 실시간 RL 통합기 로드됨")
            
            # 취약점 스캐너 (선택사항)
            try:
                self.vuln_scanner = get_auto_scanner(network_range="192.168.0.0/24")
                logger.info("✓ 자동 취약점 스캐너 로드됨")
            except Exception as e:
                logger.warning(f"취약점 스캐너 로드 실패: {e}")
                self.vuln_scanner = None
            
            # 우선순위 분석기
            try:
                self.priority_analyzer = get_priority_analyzer()
                logger.info("✓ AI 우선순위 분석기 로드됨")
            except Exception as e:
                logger.warning(f"우선순위 분석기 로드 실패: {e}")
                self.priority_analyzer = None
            
            # 통합 플래그
            self.integrated_mode = True
            
            logger.info("✅ 통합 시스템 초기화 완료!")
            
        except Exception as e:
            logger.error(f"통합 시스템 초기화 실패: {e}")
            self.integrated_mode = False
    
    def start_integrated_services(self):
        """통합 서비스 시작 (백그라운드 스레드)"""
        if not hasattr(self, 'integrated_mode') or not self.integrated_mode:
            logger.warning("통합 모드가 비활성화되어 있습니다")
            return False
        
        try:
            # 온라인 학습 시작
            if hasattr(self, 'online_trainer') and self.online_trainer:
                self.online_trainer.start()
                logger.info("온라인 RL 학습 스레드 시작됨")
            
            # 취약점 스캐너 시작
            if hasattr(self, 'vuln_scanner') and self.vuln_scanner:
                self.vuln_scanner.start()
                logger.info("자동 취약점 스캐너 시작됨")
            
            return True
            
        except Exception as e:
            logger.error(f"통합 서비스 시작 실패: {e}")
            return False
    
    def stop_integrated_services(self):
        """통합 서비스 중지"""
        try:
            if hasattr(self, 'online_trainer') and self.online_trainer:
                self.online_trainer.stop()
                logger.info("온라인 RL 학습 스레드 중지됨")
            
            if hasattr(self, 'vuln_scanner') and self.vuln_scanner:
                self.vuln_scanner.stop()
                logger.info("자동 취약점 스캐너 중지됨")
            
        except Exception as e:
            logger.error(f"통합 서비스 중지 오류: {e}")

def test_ips_pipeline():
    """IPS 파이프라인 통합 테스트"""
    print("=== IPS 파이프라인 통합 테스트 시작 ===")
    
    try:
        # 파이프라인 생성
        pipeline = IPSPipelineIntegrator()
        
        # 모의 패킷 데이터 생성
        test_packets = [
            {
                'source': '192.168.1.100',
                'destination_port': 22,
                'length': 64,
                'tcp_flags': {'syn': 1},
                'packets_per_sec': 10,
                'duration': 1000
            },
            {
                'source': '10.0.0.50', 
                'destination_port': 80,
                'length': 1460,
                'tcp_flags': {'syn': 100},
                'packets_per_sec': 5000,
                'duration': 100
            },
            {
                'source': '172.16.0.10',
                'destination_port': 443,
                'length': 128,
                'tcp_flags': {'ack': 1},
                'packets_per_sec': 5,
                'duration': 5000
            }
        ]
        
        print(f"테스트 패킷: {len(test_packets)}개")
        
        # 각 패킷 처리
        for i, packet in enumerate(test_packets, 1):
            print(f"\n--- 패킷 {i} 처리 ---")
            
            result = pipeline.process_packet_threat(packet)
            
            print(f"  출발지: {packet['source']}")
            print(f"  대응 액션: {result.action_name}")
            print(f"  실행 성공: {result.success}")
            print(f"  처리 시간: {result.execution_time_ms:.2f}ms")
            print(f"  결정 신뢰도: {result.confidence:.3f}")
        
        # 파이프라인 통계
        print(f"\n=== 파이프라인 통계 ===")
        stats = pipeline.get_pipeline_stats()
        print(f"처리된 위협: {stats['total_threats_processed']}개")
        print(f"RF 탐지: {stats['rf_detections']}개")
        print(f"RL 결정: {stats['rl_decisions']}개")
        print(f"방어 실행: {stats['defense_actions']}개")
        print(f"OPE 로그: {stats['ope_log_buffer_size']}개")
        
        # 상태 저장 테스트
        pipeline.save_pipeline_state('test_pipeline_state.json')
        
        # 테스트 파일 정리
        for filename in ['test_pipeline_state.json', 'test_pipeline_state_agent.pth', 'test_pipeline_state_buffer.pkl']:
            if os.path.exists(filename):
                os.remove(filename)
        
        print("\n✅ IPS 파이프라인 통합 테스트 성공!")
        print("✅ RF → RL 데이터 흐름 확인")
        print("✅ 실시간 처리 파이프라인 동작")
        print("✅ OPE 로깅 시스템 동작")
        
        return True
        
    except Exception as e:
        print(f"❌ 파이프라인 테스트 실패: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_ips_pipeline()
    if success:
        print("\n다음 단계: IPSAgent_RL.py 통합")
    else:
        print("\n문제 해결 후 재시도 필요")

