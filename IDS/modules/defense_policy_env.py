#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPS 대응정책 강화학습 환경
RF 탐지 결과 기반 최적 방어 조치 학습을 위한 환경
"""

import gym
from gym import spaces
import numpy as np
import pandas as pd
import joblib
import json
import time
import random
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import logging

# 로깅 설정
logger = logging.getLogger('DefensePolicyEnv')

class DefensePolicyEnv(gym.Env):
    """IPS 대응정책 학습 환경
    
    RF 모델의 위협 탐지 결과를 받아서 최적의 방어 조치를 학습하는 환경
    기존 NetworkEnv와 완전히 분리된 독립적 환경
    """
    
    def __init__(self, rf_model_path="ips_random_forest_model.pkl", config_path="defense_config.json"):
        """환경 초기화
        
        Args:
            rf_model_path (str): "../ips_random_forest_model.pkl"
            config_path (str): "../defense_config.json"
        """
        super(DefensePolicyEnv, self).__init__()
        
        # 액션 스페이스: 6개 대응 수준
        self.action_space = spaces.Discrete(6)
        self.action_names = {
            0: 'allow',           # 허용 (정상 처리)
            1: 'block_temporary', # 임시 차단 (30분)
            2: 'block_permanent', # 영구 차단
            3: 'rate_limit',      # 레이트 제한
            4: 'deep_inspection', # 추가 검사
            5: 'isolate_session'  # 세션 격리
        }
        
        # 상태 스페이스: 10차원 (RF 결과 + 시스템 상태 + 컨텍스트)
        self.observation_space = spaces.Box(
            low=0.0, high=1.0,
            shape=(10,),
            dtype=np.float32
        )
        
        # RF 모델 로드
        try:
            self.rf_model = joblib.load(rf_model_path)
            logger.info(f"RF 모델 로드 성공: {rf_model_path}")
        except Exception as e:
            logger.error(f"RF 모델 로드 실패: {e}")
            self.rf_model = None
        
        # 설정 로드
        self.config = self._load_config(config_path)
        
        # 환경 상태
        self.current_step = 0
        self.max_steps = 1000
        self.episode_rewards = []
        self.total_reward = 0
        
        # 시스템 상태 시뮬레이터
        self.system_state = {
            'cpu_usage': 0.3,
            'memory_usage': 0.4,
            'active_threats': 5,
            'blocked_ips': 10,
            'current_time_hour': 14,
            'service_criticality': 0.8,
            'network_load': 0.5
        }
        
        # 비용 매개변수 (조직 정책에 따라 조정)
        self.costs = {
            'attack_prevention_value': 100.0,   # 공격 차단 가치
            'false_positive_cost': 20.0,        # 오탐 비용
            'system_impact_penalty': 10.0,      # 시스템 영향 페널티
            'latency_penalty': 5.0,             # 지연 페널티
            'service_disruption_cost': 50.0     # 서비스 중단 비용
        }
        
        # 위협 시나리오 생성기
        self.threat_scenarios = self._initialize_threat_scenarios()
        self.current_threat = None
        
        logger.info("DefensePolicyEnv 초기화 완료")
    
    def _load_config(self, config_path):
        """설정 파일 로드"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            return config
        except Exception as e:
            logger.warning(f"설정 파일 로드 실패: {e}, 기본 설정 사용")
            return {
                "defense": {
                    "high_threat_threshold": 0.9,
                    "medium_threat_threshold": 0.7,
                    "low_threat_threshold": 0.5
                }
            }
    
    def _initialize_threat_scenarios(self):
        """위협 시나리오 초기화"""
        # CIC-IDS-2017 기반 위협 시나리오 생성
        scenarios = [
            {
                'threat_type': 'ddos',
                'probability': 0.95,
                'confidence': 0.92,
                'severity': 'high',
                'system_impact': 0.8,
                'business_impact': 0.9,
                'expected_action': 2  # block_permanent
            },
            {
                'threat_type': 'port_scan',
                'probability': 0.85,
                'confidence': 0.78,
                'severity': 'medium',
                'system_impact': 0.3,
                'business_impact': 0.2,
                'expected_action': 3  # rate_limit
            },
            {
                'threat_type': 'brute_force',
                'probability': 0.88,
                'confidence': 0.82,
                'severity': 'medium',
                'system_impact': 0.4,
                'business_impact': 0.5,
                'expected_action': 1  # block_temporary
            },
            {
                'threat_type': 'web_attack',
                'probability': 0.75,
                'confidence': 0.68,
                'severity': 'medium',
                'system_impact': 0.2,
                'business_impact': 0.6,
                'expected_action': 4  # deep_inspection
            },
            {
                'threat_type': 'botnet',
                'probability': 0.92,
                'confidence': 0.89,
                'severity': 'high',
                'system_impact': 0.7,
                'business_impact': 0.8,
                'expected_action': 2  # block_permanent
            },
            {
                'threat_type': 'normal',
                'probability': 0.05,
                'confidence': 0.95,
                'severity': 'low',
                'system_impact': 0.0,
                'business_impact': 0.0,
                'expected_action': 0  # allow
            }
        ]
        
        return scenarios
    
    def reset(self):
        """환경 리셋 - 새로운 위협 시나리오 생성"""
        self.current_step = 0
        self.total_reward = 0
        
        # 새로운 위협 시나리오 선택
        self.current_threat = random.choice(self.threat_scenarios).copy()
        
        # 시스템 상태 업데이트 (시뮬레이션)
        self._update_system_state()
        
        # 상태 벡터 생성
        state = self._create_state_vector()
        
        logger.debug(f"환경 리셋: {self.current_threat['threat_type']} 위협 시나리오")
        
        return state
    
    def step(self, action):
        """액션 실행 및 환경 업데이트"""
        self.current_step += 1
        
        # 액션 실행 시뮬레이션
        action_result = self._execute_action_simulation(action)
        
        # 보상 계산
        reward = self._calculate_reward(action, action_result)
        self.total_reward += reward
        
        # 시스템 상태 업데이트
        self._update_system_state_after_action(action, action_result)
        
        # 다음 상태 생성
        next_state = self._create_state_vector()
        
        # 종료 조건 확인
        done = self.current_step >= self.max_steps
        
        # 정보 딕셔너리
        info = {
            'action_name': self.action_names[action],
            'action_result': action_result,
            'threat_info': self.current_threat,
            'system_state': self.system_state.copy(),
            'reward_breakdown': self._get_reward_breakdown(action, action_result)
        }
        
        logger.debug(f"액션 {action}({self.action_names[action]}) 실행, 보상: {reward:.2f}")
        
        return next_state, reward, done, info
    
    def _create_state_vector(self):
        """현재 상태를 10차원 벡터로 변환"""
        if self.current_threat is None:
            return np.zeros(10, dtype=np.float32)
        
        # 공격 유형 인코딩
        attack_type_map = {
            'normal': 0.0, 'ddos': 0.2, 'port_scan': 0.4, 
            'brute_force': 0.6, 'web_attack': 0.8, 'botnet': 1.0
        }
        attack_type_encoded = attack_type_map.get(self.current_threat['threat_type'], 0.5)
        
        state = np.array([
            # RF 탐지 결과 (4차원)
            self.current_threat['probability'],      # 위협 확률
            self.current_threat['confidence'],       # 탐지 신뢰도
            attack_type_encoded,                     # 공격 유형
            self.current_threat['system_impact'],    # 시스템 영향도
            
            # 시스템 상태 (4차원)
            self.system_state['cpu_usage'],          # CPU 사용률
            self.system_state['memory_usage'],       # 메모리 사용률
            min(self.system_state['active_threats'] / 50.0, 1.0),  # 활성 위협 비율
            min(self.system_state['blocked_ips'] / 100.0, 1.0),    # 차단 IP 비율
            
            # 컨텍스트 (2차원)
            self.system_state['current_time_hour'] / 24.0,         # 시간대
            self.system_state['service_criticality']               # 서비스 중요도
        ], dtype=np.float32)
        
        return state
    
    def _execute_action_simulation(self, action):
        """대응 액션 실행 시뮬레이션"""
        action_name = self.action_names[action]
        threat = self.current_threat
        
        # 액션별 효과 시뮬레이션
        if action == 0:  # allow
            success_rate = 1.0 - threat['probability']
            system_impact = 0.0
            service_disruption = False
            
        elif action == 1:  # block_temporary
            success_rate = 0.95 if threat['probability'] > 0.7 else 0.8
            system_impact = 0.1
            service_disruption = threat['probability'] < 0.5  # 오탐시 서비스 영향
            
        elif action == 2:  # block_permanent
            success_rate = 0.98 if threat['probability'] > 0.8 else 0.7
            system_impact = 0.2
            service_disruption = threat['probability'] < 0.7
            
        elif action == 3:  # rate_limit
            success_rate = 0.7 if threat['probability'] > 0.5 else 0.9
            system_impact = 0.3
            service_disruption = False
            
        elif action == 4:  # deep_inspection
            success_rate = 0.85
            system_impact = 0.5
            service_disruption = False
            
        else:  # isolate_session
            success_rate = 0.9
            system_impact = 0.4
            service_disruption = threat['probability'] < 0.6
        
        # 결과 계산
        is_successful = random.random() < success_rate
        response_time = random.uniform(50, 500)  # ms
        
        return {
            'action': action,
            'action_name': action_name,
            'success': is_successful,
            'system_impact': system_impact,
            'service_disruption': service_disruption,
            'response_time_ms': response_time,
            'threat_blocked': is_successful and threat['probability'] > 0.5
        }
    
    def _calculate_reward(self, action, action_result):
        """대응 정책 보상 계산"""
        threat = self.current_threat
        result = action_result
        
        base_reward = 0.0
        
        # 1. 대응 효과성 보상
        if result['threat_blocked'] and threat['probability'] > 0.7:
            # 실제 위협을 성공적으로 차단
            base_reward += self.costs['attack_prevention_value'] * threat['probability']
        elif result['service_disruption'] and threat['probability'] < 0.5:
            # 정상 트래픽을 잘못 차단 (오탐)
            base_reward -= self.costs['false_positive_cost']
        
        # 2. 대응 적절성 보상
        threat_level = threat['probability']
        if threat_level > 0.9:  # 확실한 공격
            if action in [1, 2]:  # 강한 대응
                base_reward += 15.0
            elif action in [3, 4]:  # 중간 대응
                base_reward += 8.0
            else:  # 약한 대응
                base_reward -= 10.0
                
        elif threat_level > 0.7:  # 의심스러운
            if action in [1, 3, 4]:  # 적절한 대응
                base_reward += 10.0
            elif action == 2:  # 과도한 대응
                base_reward -= 5.0
            else:
                base_reward += 3.0
                
        elif threat_level > 0.5:  # 낮은 위험
            if action in [0, 3, 4]:  # 관찰적 대응
                base_reward += 5.0
            else:  # 과도한 대응
                base_reward -= 8.0
                
        else:  # 정상 트래픽
            if action == 0:  # 허용
                base_reward += 8.0
            else:  # 불필요한 대응
                base_reward -= 15.0
        
        # 3. 시스템 부하 페널티
        if result['system_impact'] > 0.5:
            base_reward -= self.costs['system_impact_penalty'] * result['system_impact']
        
        # 4. 응답 시간 페널티
        if result['response_time_ms'] > 1000:  # 1초 초과
            base_reward -= self.costs['latency_penalty'] * (result['response_time_ms'] / 1000.0)
        
        # 5. 서비스 중단 페널티
        if result['service_disruption']:
            base_reward -= self.costs['service_disruption_cost'] * threat['business_impact']
        
        return base_reward
    
    def _update_system_state(self):
        """시스템 상태 업데이트 (시뮬레이션)"""
        # 시간 진행
        self.system_state['current_time_hour'] = (self.system_state['current_time_hour'] + 0.1) % 24
        
        # 시스템 부하 변동 (랜덤)
        self.system_state['cpu_usage'] = max(0.1, min(0.9, 
            self.system_state['cpu_usage'] + random.uniform(-0.1, 0.1)))
        self.system_state['memory_usage'] = max(0.2, min(0.9,
            self.system_state['memory_usage'] + random.uniform(-0.05, 0.05)))
        
        # 활성 위협 수 변동
        self.system_state['active_threats'] = max(0, 
            self.system_state['active_threats'] + random.randint(-2, 3))
        
        # 네트워크 부하 변동
        hour = self.system_state['current_time_hour']
        if 9 <= hour <= 18:  # 업무시간
            self.system_state['network_load'] = random.uniform(0.5, 0.9)
        else:  # 야간
            self.system_state['network_load'] = random.uniform(0.1, 0.4)
    
    def _update_system_state_after_action(self, action, action_result):
        """액션 실행 후 시스템 상태 업데이트"""
        # 차단 조치 후 차단 IP 수 증가
        if action in [1, 2] and action_result['success']:
            self.system_state['blocked_ips'] += 1
        
        # 시스템 부하 증가 (액션에 따라)
        impact = action_result['system_impact']
        self.system_state['cpu_usage'] = min(0.95, 
            self.system_state['cpu_usage'] + impact * 0.1)
        
        # 위협 수 감소 (성공적 차단시)
        if action_result['threat_blocked']:
            self.system_state['active_threats'] = max(0, 
                self.system_state['active_threats'] - 1)
    
    def _get_reward_breakdown(self, action, action_result):
        """보상 구성 요소 분석 (디버깅용)"""
        threat = self.current_threat
        
        return {
            'threat_level': threat['probability'],
            'action_taken': self.action_names[action],
            'success': action_result['success'],
            'appropriateness': self._calculate_action_appropriateness(action, threat),
            'system_cost': action_result['system_impact'],
            'business_cost': action_result['service_disruption'],
            'response_time': action_result['response_time_ms']
        }
    
    def _calculate_action_appropriateness(self, action, threat):
        """액션 적절성 평가 (0.0-1.0)"""
        threat_level = threat['probability']
        
        # 위협 수준별 적절한 액션 정의
        if threat_level > 0.9:
            appropriate_actions = [1, 2]  # 강한 대응
        elif threat_level > 0.7:
            appropriate_actions = [1, 3, 4]  # 중간 대응
        elif threat_level > 0.5:
            appropriate_actions = [0, 3, 4]  # 관찰적 대응
        else:
            appropriate_actions = [0]  # 허용
        
        if action in appropriate_actions:
            return 1.0
        else:
            return 0.0
    
    def render(self, mode='human'):
        """환경 상태 시각화"""
        if mode == 'human':
            print(f"\n=== DefensePolicyEnv 상태 ===")
            print(f"스텝: {self.current_step}/{self.max_steps}")
            print(f"총 보상: {self.total_reward:.2f}")
            
            if self.current_threat:
                print(f"현재 위협:")
                print(f"  유형: {self.current_threat['threat_type']}")
                print(f"  확률: {self.current_threat['probability']:.3f}")
                print(f"  신뢰도: {self.current_threat['confidence']:.3f}")
            
            print(f"시스템 상태:")
            print(f"  CPU: {self.system_state['cpu_usage']:.2f}")
            print(f"  Memory: {self.system_state['memory_usage']:.2f}")
            print(f"  활성 위협: {self.system_state['active_threats']}")
            print(f"  차단 IP: {self.system_state['blocked_ips']}")
    
    def close(self):
        """환경 정리"""
        logger.info("DefensePolicyEnv 종료")

# 환경 테스트 함수
def test_defense_policy_env():
    """DefensePolicyEnv 환경 테스트"""
    print("=== DefensePolicyEnv 테스트 시작 ===")
    
    try:
        env = DefensePolicyEnv()
        
        # 환경 정보 출력
        print(f"액션 스페이스: {env.action_space}")
        print(f"상태 스페이스: {env.observation_space}")
        print(f"액션 이름: {env.action_names}")
        
        # 간단한 에피소드 실행
        state = env.reset()
        print(f"초기 상태: {state}")
        
        for step in range(5):
            action = env.action_space.sample()  # 랜덤 액션
            next_state, reward, done, info = env.step(action)
            
            print(f"\n스텝 {step+1}:")
            print(f"  액션: {action} ({info['action_name']})")
            print(f"  보상: {reward:.2f}")
            print(f"  성공: {info['action_result']['success']}")
            
            if done:
                break
        
        env.close()
        print("\n✅ DefensePolicyEnv 테스트 완료")
        
    except Exception as e:
        print(f"❌ 테스트 실패: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_defense_policy_env()
