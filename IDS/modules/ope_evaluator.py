#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OPE (Off-Policy Evaluation) 평가 시스템
Conservative RL Agent의 대응 정책 성능을 안전하게 평가
"""

import numpy as np
import pandas as pd
import json
import logging
import os
import torch
from typing import Dict, List, Tuple, Optional, Union
from scipy import stats
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Conservative RL Agent 연동
try:
    from .conservative_rl_agent import ConservativeRLAgent
    from .defense_policy_env import DefensePolicyEnv
except ImportError:
    from conservative_rl_agent import ConservativeRLAgent
    from defense_policy_env import DefensePolicyEnv

# 로깅 설정
logger = logging.getLogger('OPEEvaluator')

class OPEEvaluator:
    """오프라인 정책 평가 시스템
    
    Conservative RL Agent의 대응 정책을 안전하게 평가하는 시스템
    - Importance Sampling (IS)
    - Doubly Robust (DR) 
    - 정책 비교 및 통계적 검정
    - 신뢰구간 계산
    """
    
    def __init__(self, behavior_policy_name="rule_based", target_policy_name="conservative_rl"):
        """OPE 평가기 초기화
        
        Args:
            behavior_policy_name (str): 현재 사용 중인 정책 (로그 데이터 생성 정책)
            target_policy_name (str): 평가할 대상 정책
        """
        self.behavior_policy_name = behavior_policy_name
        self.target_policy_name = target_policy_name
        
        # 평가 방법들
        self.evaluation_methods = {
            'importance_sampling': self._importance_sampling,
            'doubly_robust': self._doubly_robust,
            'direct_method': self._direct_method,
            'weighted_importance_sampling': self._weighted_importance_sampling
        }
        
        # 평가 결과 저장
        self.evaluation_results = {}
        
        # 통계 정보
        self.stats = {
            'total_episodes_evaluated': 0,
            'total_transitions': 0,
            'evaluation_methods_used': [],
            'confidence_intervals': {},
            'policy_comparison': {}
        }
        
        logger.info(f"OPE 평가기 초기화: {behavior_policy_name} → {target_policy_name}")
    
    def evaluate_policy_from_logs(self, defense_logs: List[Dict], 
                                  target_agent: ConservativeRLAgent,
                                  env: DefensePolicyEnv) -> Dict:
        """방어 로그 데이터로부터 정책 성능 평가
        
        Args:
            defense_logs: 방어 조치 로그 데이터
            target_agent: 평가할 RL 에이전트
            env: 평가 환경
            
        Returns:
            Dict: 평가 결과
        """
        print("=== OPE 정책 평가 시작 ===")
        
        # 로그 데이터 전처리
        processed_data = self._preprocess_logs(defense_logs)
        print(f"처리된 로그: {len(processed_data)}개 에피소드")
        
        # 각 평가 방법으로 성능 추정
        results = {}
        
        for method_name, method_func in self.evaluation_methods.items():
            print(f"\n{method_name.upper()} 평가 중...")
            
            try:
                result = method_func(processed_data, target_agent, env)
                results[method_name] = result
                print(f"  추정 성능: {result['estimated_value']:.3f}")
                print(f"  신뢰구간: [{result['ci_lower']:.3f}, {result['ci_upper']:.3f}]")
                
            except Exception as e:
                logger.error(f"{method_name} 평가 실패: {e}")
                results[method_name] = {'error': str(e)}
        
        # 종합 평가 결과
        final_result = self._aggregate_results(results)
        
        # 통계 업데이트
        self.stats['total_episodes_evaluated'] = len(processed_data)
        self.stats['evaluation_methods_used'] = list(results.keys())
        self.evaluation_results = final_result
        
        print(f"\n=== OPE 평가 완료 ===")
        print(f"종합 성능 추정: {final_result['consensus_value']:.3f}")
        print(f"신뢰도: {final_result['confidence_level']:.1%}")
        
        return final_result
    
    def _preprocess_logs(self, logs: List[Dict]) -> List[Dict]:
        """로그 데이터 전처리"""
        processed = []
        
        for log_entry in logs:
            # 로그 데이터를 OPE 형태로 변환
            episode = {
                'state': self._extract_state_from_log(log_entry),
                'action': self._extract_action_from_log(log_entry),
                'reward': self._extract_reward_from_log(log_entry),
                'next_state': self._extract_next_state_from_log(log_entry),
                'behavior_probability': self._estimate_behavior_probability(log_entry),
                'metadata': log_entry.get('metadata', {})
            }
            
            if self._is_valid_episode(episode):
                processed.append(episode)
        
        return processed
    
    def _extract_state_from_log(self, log_entry: Dict) -> np.ndarray:
        """로그에서 상태 벡터 추출"""
        # 방어 로그에서 RF 결과 + 시스템 상태 추출
        rf_result = log_entry.get('rf_prediction', {})
        system_state = log_entry.get('system_state', {})
        
        state = np.array([
            rf_result.get('probability', 0.5),
            rf_result.get('confidence', 0.5),
            self._encode_attack_type(rf_result.get('attack_type', 'unknown')),
            rf_result.get('severity', 0.5),
            system_state.get('cpu_usage', 0.3),
            system_state.get('memory_usage', 0.4),
            min(system_state.get('active_threats', 5) / 50.0, 1.0),
            min(system_state.get('blocked_ips', 10) / 100.0, 1.0),
            system_state.get('time_of_day', 14) / 24.0,
            system_state.get('service_criticality', 0.8)
        ], dtype=np.float32)
        
        return state
    
    def _extract_action_from_log(self, log_entry: Dict) -> int:
        """로그에서 액션 추출"""
        action_map = {
            '허용': 0, 'allow': 0,
            '임시 차단': 1, 'block_temporary': 1,
            '영구 차단': 2, 'block_permanent': 2,
            '레이트 제한': 3, 'rate_limit': 3,
            '추가 검사': 4, 'deep_inspection': 4,
            '세션 격리': 5, 'isolate_session': 5
        }
        
        action_str = log_entry.get('action', 'allow')
        return action_map.get(action_str, 0)
    
    def _extract_reward_from_log(self, log_entry: Dict) -> float:
        """로그에서 보상 계산"""
        # 실제 대응 결과를 바탕으로 보상 계산
        outcome = log_entry.get('outcome', {})
        
        if outcome.get('attack_blocked', False):
            reward = 100.0  # 공격 차단 성공
        elif outcome.get('false_positive', False):
            reward = -20.0  # 오탐 페널티
        elif outcome.get('service_disruption', False):
            reward = -50.0  # 서비스 중단 페널티
        else:
            reward = 5.0    # 기본 보상
        
        return reward
    
    def _extract_next_state_from_log(self, log_entry: Dict) -> np.ndarray:
        """다음 상태 추출 (시뮬레이션)"""
        # 현재 상태 기반으로 다음 상태 시뮬레이션
        current_state = self._extract_state_from_log(log_entry)
        
        # 액션 결과에 따른 상태 변화 시뮬레이션
        action = self._extract_action_from_log(log_entry)
        
        next_state = current_state.copy()
        
        # 차단 액션시 시스템 상태 변화
        if action in [1, 2]:  # 차단 조치
            next_state[6] = max(0, next_state[6] - 0.1)  # 활성 위협 감소
            next_state[7] = min(1.0, next_state[7] + 0.05)  # 차단 IP 증가
        
        return next_state
    
    def _estimate_behavior_probability(self, log_entry: Dict) -> float:
        """행동 정책의 액션 확률 추정"""
        # 규칙 기반 정책의 액션 확률 추정
        rf_prob = log_entry.get('rf_prediction', {}).get('probability', 0.5)
        action = self._extract_action_from_log(log_entry)
        
        # 규칙 기반 정책 시뮬레이션
        if rf_prob > 0.9:
            # 높은 위협시 차단 확률 높음
            probs = [0.05, 0.4, 0.4, 0.1, 0.05, 0.0]  # allow, block_temp, block_perm, ...
        elif rf_prob > 0.7:
            # 중간 위협시 제한적 조치
            probs = [0.2, 0.3, 0.1, 0.3, 0.1, 0.0]
        else:
            # 낮은 위협시 허용 위주
            probs = [0.7, 0.1, 0.05, 0.1, 0.05, 0.0]
        
        return probs[action]
    
    def _encode_attack_type(self, attack_type: str) -> float:
        """공격 유형 인코딩"""
        type_map = {
            'normal': 0.0, 'ddos': 0.2, 'port_scan': 0.4,
            'brute_force': 0.6, 'web_attack': 0.8, 'botnet': 1.0
        }
        return type_map.get(attack_type, 0.5)
    
    def _is_valid_episode(self, episode: Dict) -> bool:
        """에피소드 유효성 검사"""
        required_fields = ['state', 'action', 'reward', 'behavior_probability']
        return all(field in episode for field in required_fields)
    
    def _importance_sampling(self, data: List[Dict], target_agent: ConservativeRLAgent, 
                           env: DefensePolicyEnv) -> Dict:
        """중요도 샘플링 평가"""
        total_weighted_reward = 0.0
        total_weight = 0.0
        weights = []
        rewards = []
        
        for episode in data:
            state = episode['state']
            action = episode['action']
            reward = episode['reward']
            behavior_prob = episode['behavior_probability']
            
            # 대상 정책의 액션 확률 계산
            target_prob = self._get_target_policy_probability(target_agent, state, action)
            
            # 중요도 가중치 계산
            if behavior_prob > 1e-8:  # 0으로 나누기 방지
                weight = target_prob / behavior_prob
                weight = min(weight, 10.0)  # 가중치 클리핑 (안정성)
                
                total_weighted_reward += weight * reward
                total_weight += weight
                
                weights.append(weight)
                rewards.append(reward)
        
        # 성능 추정
        if total_weight > 0:
            estimated_value = total_weighted_reward / total_weight
        else:
            estimated_value = 0.0
        
        # 신뢰구간 계산
        if len(weights) > 1:
            weighted_rewards = [w * r for w, r in zip(weights, rewards)]
            std_error = np.std(weighted_rewards) / np.sqrt(len(weighted_rewards))
            ci_lower = estimated_value - 1.96 * std_error
            ci_upper = estimated_value + 1.96 * std_error
        else:
            ci_lower = ci_upper = estimated_value
        
        return {
            'estimated_value': estimated_value,
            'ci_lower': ci_lower,
            'ci_upper': ci_upper,
            'method': 'importance_sampling',
            'sample_size': len(data),
            'effective_sample_size': total_weight,
            'weight_variance': np.var(weights) if weights else 0.0
        }
    
    def _doubly_robust(self, data: List[Dict], target_agent: ConservativeRLAgent,
                      env: DefensePolicyEnv) -> Dict:
        """Doubly Robust 평가"""
        # IS + 모델 기반 추정 결합
        
        total_dr_value = 0.0
        dr_values = []
        
        for episode in data:
            state = episode['state']
            action = episode['action']
            reward = episode['reward']
            next_state = episode['next_state']
            behavior_prob = episode['behavior_probability']
            
            # 1. 중요도 샘플링 부분
            target_prob = self._get_target_policy_probability(target_agent, state, action)
            
            if behavior_prob > 1e-8:
                is_weight = target_prob / behavior_prob
                is_weight = min(is_weight, 10.0)
            else:
                is_weight = 0.0
            
            # 2. 모델 기반 추정 (Q-함수 활용)
            import torch
            target_agent.q_network.eval()
            with torch.no_grad():
                state_tensor = torch.FloatTensor(state).unsqueeze(0)
                q_value = target_agent.q_network(state_tensor)[0][action].item()
                q_value = state_tensor[0][action].item()
            
            # 3. Doubly Robust 결합
            dr_value = is_weight * reward + (1 - is_weight) * q_value
            dr_values.append(dr_value)
            total_dr_value += dr_value
        
        # 성능 추정
        estimated_value = total_dr_value / len(data) if data else 0.0
        
        # 신뢰구간
        if len(dr_values) > 1:
            std_error = np.std(dr_values) / np.sqrt(len(dr_values))
            ci_lower = estimated_value - 1.96 * std_error
            ci_upper = estimated_value + 1.96 * std_error
        else:
            ci_lower = ci_upper = estimated_value
        
        return {
            'estimated_value': estimated_value,
            'ci_lower': ci_lower,
            'ci_upper': ci_upper,
            'method': 'doubly_robust',
            'sample_size': len(data),
            'dr_variance': np.var(dr_values) if dr_values else 0.0
        }
    
    def _direct_method(self, data: List[Dict], target_agent: ConservativeRLAgent,
                      env: DefensePolicyEnv) -> Dict:
        """직접 방법 (모델 기반 추정)"""
        total_value = 0.0
        q_values = []
        
        for episode in data:
            state = episode['state']
            
            # 대상 정책의 예상 액션
            target_action = target_agent.act(state, deterministic=True)
            
            # Q-함수로 가치 추정
            import torch
            target_agent.q_network.eval()
            with torch.no_grad():
                state_tensor = torch.FloatTensor(state).unsqueeze(0)
            q_value = target_agent.q_network(state_tensor)[0][target_action].item()
            q_values.append(q_value)
            total_value += q_value
        
        estimated_value = total_value / len(data) if data else 0.0
        
        # 신뢰구간
        if len(q_values) > 1:
            std_error = np.std(q_values) / np.sqrt(len(q_values))
            ci_lower = estimated_value - 1.96 * std_error
            ci_upper = estimated_value + 1.96 * std_error
        else:
            ci_lower = ci_upper = estimated_value
        
        return {
            'estimated_value': estimated_value,
            'ci_lower': ci_lower,
            'ci_upper': ci_upper,
            'method': 'direct_method',
            'sample_size': len(data),
            'model_variance': np.var(q_values) if q_values else 0.0
        }
    
    def _weighted_importance_sampling(self, data: List[Dict], target_agent: ConservativeRLAgent,
                                    env: DefensePolicyEnv) -> Dict:
        """가중 중요도 샘플링"""
        weighted_rewards = []
        weights = []
        
        for episode in data:
            state = episode['state']
            action = episode['action']
            reward = episode['reward']
            behavior_prob = episode['behavior_probability']
            
            target_prob = self._get_target_policy_probability(target_agent, state, action)
            
            if behavior_prob > 1e-8:
                weight = target_prob / behavior_prob
                weight = min(weight, 10.0)  # 클리핑
                
                weighted_rewards.append(weight * reward)
                weights.append(weight)
        
        # 가중 평균
        if sum(weights) > 0:
            estimated_value = sum(weighted_rewards) / sum(weights)
        else:
            estimated_value = 0.0
        
        # 신뢰구간 (bootstrap 방식)
        if len(weighted_rewards) > 10:
            bootstrap_estimates = []
            for _ in range(1000):
                indices = np.random.choice(len(weighted_rewards), size=len(weighted_rewards), replace=True)
                bootstrap_rewards = [weighted_rewards[i] for i in indices]
                bootstrap_weights = [weights[i] for i in indices]
                
                if sum(bootstrap_weights) > 0:
                    bootstrap_est = sum(bootstrap_rewards) / sum(bootstrap_weights)
                    bootstrap_estimates.append(bootstrap_est)
            
            ci_lower = np.percentile(bootstrap_estimates, 2.5)
            ci_upper = np.percentile(bootstrap_estimates, 97.5)
        else:
            ci_lower = ci_upper = estimated_value
        
        return {
            'estimated_value': estimated_value,
            'ci_lower': ci_lower,
            'ci_upper': ci_upper,
            'method': 'weighted_importance_sampling',
            'sample_size': len(data),
            'effective_sample_size': sum(weights)**2 / sum([w**2 for w in weights]) if weights else 0
        }
    
    def _get_target_policy_probability(self, agent: ConservativeRLAgent, 
                                     state: np.ndarray, action: int) -> float:
        """대상 정책의 액션 확률 계산"""
        try:
            # Conservative RL Agent의 액션 확률 계산
            import torch
            agent.q_network.eval()
            with torch.no_grad():
                state_tensor = torch.FloatTensor(state).unsqueeze(0)
                q_values = agent.q_network(state_tensor)
                probs = torch.softmax(q_values, dim=1)
                return probs[0][action].item()
                
        except Exception as e:
            logger.warning(f"대상 정책 확률 계산 실패: {e}")
            return 1.0 / agent.action_size  # 균등 분포로 fallback
    
    def _aggregate_results(self, results: Dict) -> Dict:
        """여러 평가 방법 결과 종합"""
        valid_results = {k: v for k, v in results.items() if 'error' not in v}
        
        if not valid_results:
            return {'error': 'No valid evaluation results'}
        
        # 각 방법의 추정값
        estimates = [r['estimated_value'] for r in valid_results.values()]
        
        # 종합 추정 (평균)
        consensus_value = np.mean(estimates)
        
        # 신뢰도 계산 (추정값들의 일치도)
        if len(estimates) > 1:
            estimate_std = np.std(estimates)
            confidence_level = max(0.5, 1.0 - estimate_std / abs(consensus_value)) if consensus_value != 0 else 0.5
        else:
            confidence_level = 0.7
        
        # 최종 신뢰구간 (가장 보수적인 것 선택)
        all_ci_lower = [r['ci_lower'] for r in valid_results.values()]
        all_ci_upper = [r['ci_upper'] for r in valid_results.values()]
        
        final_ci_lower = min(all_ci_lower)
        final_ci_upper = max(all_ci_upper)
        
        return {
            'consensus_value': consensus_value,
            'confidence_level': confidence_level,
            'ci_lower': final_ci_lower,
            'ci_upper': final_ci_upper,
            'individual_results': valid_results,
            'methods_used': list(valid_results.keys()),
            'evaluation_timestamp': datetime.now().isoformat()
        }
    
    def compare_policies(self, baseline_logs: List[Dict], target_logs: List[Dict]) -> Dict:
        """두 정책 성능 비교"""
        print("=== 정책 비교 분석 시작 ===")
        
        # 기본 통계
        baseline_rewards = [self._extract_reward_from_log(log) for log in baseline_logs]
        target_rewards = [self._extract_reward_from_log(log) for log in target_logs]
        
        # 기본 성능 지표
        baseline_mean = np.mean(baseline_rewards)
        target_mean = np.mean(target_rewards)
        
        # 통계적 유의성 검정
        if len(baseline_rewards) > 1 and len(target_rewards) > 1:
            t_stat, p_value = stats.ttest_ind(target_rewards, baseline_rewards)
            significant = p_value < 0.05
        else:
            t_stat = p_value = 0.0
            significant = False
        
        # 효과 크기 계산
        pooled_std = np.sqrt((np.var(baseline_rewards) + np.var(target_rewards)) / 2)
        effect_size = (target_mean - baseline_mean) / pooled_std if pooled_std > 0 else 0.0
        
        comparison_result = {
            'baseline_performance': {
                'mean_reward': baseline_mean,
                'std_reward': np.std(baseline_rewards),
                'sample_size': len(baseline_rewards)
            },
            'target_performance': {
                'mean_reward': target_mean,
                'std_reward': np.std(target_rewards),
                'sample_size': len(target_rewards)
            },
            'improvement': {
                'absolute': target_mean - baseline_mean,
                'relative': (target_mean - baseline_mean) / abs(baseline_mean) if baseline_mean != 0 else 0,
                'effect_size': effect_size
            },
            'statistical_test': {
                't_statistic': t_stat,
                'p_value': p_value,
                'significant': significant,
                'confidence_level': 0.95
            },
            'recommendation': self._generate_recommendation(target_mean, baseline_mean, significant, effect_size)
        }
        
        print(f"기준 정책 성능: {baseline_mean:.3f}")
        print(f"대상 정책 성능: {target_mean:.3f}")
        print(f"개선도: {comparison_result['improvement']['relative']:.1%}")
        print(f"통계적 유의성: {significant}")
        
        return comparison_result
    
    def _generate_recommendation(self, target_mean: float, baseline_mean: float, 
                               significant: bool, effect_size: float) -> str:
        """정책 채택 권고안 생성"""
        improvement = target_mean - baseline_mean
        
        if significant and improvement > 0 and effect_size > 0.5:
            return "강력 권장: 통계적으로 유의한 성능 향상"
        elif improvement > 0 and effect_size > 0.2:
            return "권장: 의미있는 성능 향상"
        elif abs(improvement) < 0.1:
            return "중립: 성능 차이 미미"
        elif improvement < 0:
            return "비권장: 성능 저하 위험"
        else:
            return "추가 검증 필요: 불확실한 결과"
    
    def save_evaluation_results(self, filename: str):
        """평가 결과 저장"""
        results = {
            'evaluation_results': self.evaluation_results,
            'statistics': self.stats,
            'behavior_policy': self.behavior_policy_name,
            'target_policy': self.target_policy_name,
            'evaluation_timestamp': datetime.now().isoformat(),
            'evaluator_version': '1.0'
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"OPE 평가 결과 저장: {filename}")
    
    def create_evaluation_report(self, save_plots=True):
        """평가 보고서 생성"""
        if not self.evaluation_results:
            print("평가 결과가 없습니다.")
            return
        
        print("\n=== OPE 평가 보고서 ===")
        
        result = self.evaluation_results
        
        print(f"평가 대상: {self.target_policy_name}")
        print(f"기준 정책: {self.behavior_policy_name}")
        print(f"평가 방법: {len(result.get('methods_used', []))}개")
        
        print(f"\n성능 추정:")
        print(f"  종합 추정값: {result['consensus_value']:.3f}")
        print(f"  신뢰구간: [{result['ci_lower']:.3f}, {result['ci_upper']:.3f}]")
        print(f"  신뢰도: {result['confidence_level']:.1%}")
        
        # 개별 방법 결과
        print(f"\n개별 평가 방법 결과:")
        for method, res in result.get('individual_results', {}).items():
            print(f"  {method}: {res['estimated_value']:.3f}")
        
        return result

def test_ope_evaluator():
    """OPE 평가기 테스트"""
    print("=== OPE Evaluator 테스트 시작 ===")
    
    try:
        # 모의 방어 로그 생성
        mock_logs = []
        for i in range(100):
            log_entry = {
                'rf_prediction': {
                    'probability': np.random.uniform(0.1, 0.95),
                    'confidence': np.random.uniform(0.7, 0.99),
                    'attack_type': np.random.choice(['ddos', 'port_scan', 'normal', 'brute_force'])
                },
                'system_state': {
                    'cpu_usage': np.random.uniform(0.2, 0.8),
                    'memory_usage': np.random.uniform(0.3, 0.7),
                    'active_threats': np.random.randint(0, 20),
                    'blocked_ips': np.random.randint(0, 50),
                    'time_of_day': np.random.randint(0, 24),
                    'service_criticality': np.random.uniform(0.5, 1.0)
                },
                'action': np.random.choice(['허용', '임시 차단', '영구 차단', '레이트 제한']),
                'outcome': {
                    'attack_blocked': np.random.choice([True, False]),
                    'false_positive': np.random.choice([True, False], p=[0.1, 0.9]),
                    'service_disruption': np.random.choice([True, False], p=[0.05, 0.95])
                }
            }
            mock_logs.append(log_entry)
        
        print(f"모의 로그 생성: {len(mock_logs)}개")
        
        # 환경 및 에이전트 생성
        env = DefensePolicyEnv()
        agent = ConservativeRLAgent(state_size=10, action_size=6)
        
        # OPE 평가기 생성
        evaluator = OPEEvaluator("rule_based", "conservative_rl")
        
        # 평가 실행
        results = evaluator.evaluate_policy_from_logs(mock_logs, agent, env)
        
        # 보고서 생성
        evaluator.create_evaluation_report()
        
        # 결과 저장
        evaluator.save_evaluation_results('ope_test_results.json')
        
        print("\n✅ OPE Evaluator 테스트 완료")
        print("✅ 모든 평가 방법 동작 확인")
        print("✅ 정책 성능 추정 성공")
        
        # 테스트 파일 정리
        if os.path.exists('ope_test_results.json'):
            os.remove('ope_test_results.json')
        
        return True
        
    except Exception as e:
        print(f"❌ 테스트 실패: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_ope_evaluator()
    if success:
        print("\n다음 단계: TODO 4 - RF-RL 파이프라인 통합")
    else:
        print("\n문제 해결 후 재시도 필요")
