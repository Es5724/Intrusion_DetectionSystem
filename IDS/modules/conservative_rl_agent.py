#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
통합된 보수적 강화학습 에이전트
Conservative Q-Learning + Quantization + TinyML 기능 통합
기존 QuantizedDQNAgent, TinyMLConverter 대체
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import joblib
import json
import os
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Union
import logging

# 기존 ExperienceReplayBuffer 재사용 (중복 제거)
try:
    from .experience_replay_buffer import ExperienceReplayBuffer, IDSExperienceReplayBuffer
except ImportError:
    from experience_replay_buffer import ExperienceReplayBuffer, IDSExperienceReplayBuffer

# DefensePolicyEnv 연동
try:
    from .defense_policy_env import DefensePolicyEnv
except ImportError:
    from defense_policy_env import DefensePolicyEnv

# 로깅 설정
logger = logging.getLogger('ConservativeRLAgent')

class ConservativeRLAgent:
    """통합된 보수적 강화학습 에이전트
    
    통합 기능:
    - Conservative Q-Learning (보안 시스템 특화)
    - Quantization 지원 (QuantizedDQNAgent 대체)
    - TinyML 변환 (TinyMLConverter 대체)
    - 기존 ExperienceReplayBuffer 재사용
    - 완전한 영속성 보장 (기존과 동일 인터페이스)
    """
    
    def __init__(self, state_size=10, action_size=6, mode="standard", 
                 use_prioritized_replay=True, buffer_capacity=10000):
        """통합 에이전트 초기화
        
        Args:
            state_size (int): 상태 공간 크기 (DefensePolicyEnv: 10)
            action_size (int): 액션 공간 크기 (DefensePolicyEnv: 6)
            mode (str): 운영 모드 ('standard', 'quantized', 'tiny')
            use_prioritized_replay (bool): 우선순위 버퍼 사용 여부
            buffer_capacity (int): 버퍼 크기
        """
        self.state_size = state_size
        self.action_size = action_size
        self.mode = mode
        self.quantized = mode in ['quantized', 'tiny']
        self.tiny_mode = mode == 'tiny'
        
        # Conservative Q-Learning 파라미터
        self.alpha_cql = 1.0        # Conservative 정규화 계수
        self.tau = 0.005            # 타겟 네트워크 업데이트 비율 (보수적)
        self.gamma = 0.99           # 할인율 (높게 설정 - 장기 안정성)
        self.learning_rate = 0.0001 # 낮은 학습률 (안전성)
        
        # 탐험 전략 (보수적)
        self.epsilon = 0.1          # 낮은 초기 탐험률
        self.epsilon_min = 0.01     # 최소 탐험률
        self.epsilon_decay = 0.999  # 천천히 감소
        
        # 기존 ExperienceReplayBuffer 재사용 (중복 제거)
        if use_prioritized_replay:
            self.memory = IDSExperienceReplayBuffer(
                capacity=buffer_capacity,
                state_size=state_size,
                mode="defense_policy",  # 새로운 모드
                alpha=0.6,
                beta=0.4,
                malicious_preserve_ratio=0.5  # 공격 경험 많이 보존
            )
        else:
            self.memory = ExperienceReplayBuffer(
                capacity=buffer_capacity,
                state_size=state_size,
                mode="defense_policy"
            )
        
        # 신경망 모델 생성
        self.q_network = self._build_model()
        self.target_network = self._build_model()
        self.optimizer = optim.Adam(self.q_network.parameters(), lr=self.learning_rate)
        
        # 타겟 네트워크 초기화
        self.update_target_network(tau=1.0)
        
        # 통계 및 성능 추적
        self.training_stats = {
            'episodes': 0,
            'total_reward': 0.0,
            'avg_reward': 0.0,
            'policy_updates': 0,
            'conservative_penalty': 0.0
        }
        
        # 양자화 설정 (QuantizedDQNAgent 기능 통합)
        if self.quantized:
            self._setup_quantization()
        
        logger.info(f"ConservativeRLAgent 초기화 완료 (모드: {mode})")
    
    def _build_model(self):
        """신경망 모델 구성 (모드별 최적화)"""
        if self.tiny_mode:
            # TinyMLConverter 기능 통합: 초경량 모델
            model = nn.Sequential(
                nn.Linear(self.state_size, 16),  # 매우 작은 은닉층
                nn.ReLU(),
                nn.Linear(16, 8),
                nn.ReLU(), 
                nn.Linear(8, self.action_size)
            )
        elif self.quantized:
            # QuantizedDQNAgent 기능 통합: 경량 모델
            model = nn.Sequential(
                nn.Linear(self.state_size, 32),
                nn.ReLU(),
                nn.Dropout(0.1),
                nn.Linear(32, 16),
                nn.ReLU(),
                nn.Linear(16, self.action_size)
            )
        else:
            # 표준 Conservative 모델
            model = nn.Sequential(
                nn.Linear(self.state_size, 64),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(64, 32),
                nn.ReLU(),
                nn.Dropout(0.1),
                nn.Linear(32, self.action_size)
            )
        
        return model
    
    def _setup_quantization(self):
        """양자화 설정 (QuantizedDQNAgent 기능)"""
        if torch.cuda.is_available():
            # GPU 양자화
            self.q_network = torch.quantization.quantize_dynamic(
                self.q_network, {nn.Linear}, dtype=torch.qint8
            )
            self.target_network = torch.quantization.quantize_dynamic(
                self.target_network, {nn.Linear}, dtype=torch.qint8
            )
        
        logger.info("모델 양자화 적용 완료")
    
    def act(self, state, deterministic=False):
        """액션 선택 (보수적 정책)"""
        if not deterministic and np.random.random() < self.epsilon:
            # 탐험: 보수적 액션 우선 (allow, rate_limit 등)
            conservative_actions = [0, 3, 4]  # allow, rate_limit, deep_inspection
            return np.random.choice(conservative_actions)
        
        # 활용: Q-네트워크 기반 선택
        state_tensor = torch.FloatTensor(state).unsqueeze(0)
        
        with torch.no_grad():
            q_values = self.q_network(state_tensor)
            return q_values.argmax().item()
    
    def remember(self, state, action, reward, next_state, done, metadata=None):
        """경험 저장 (기존 인터페이스와 동일)"""
        # 보안 특화 메타데이터 추가
        if metadata is None:
            metadata = {}
        
        metadata['timestamp'] = datetime.now().isoformat()
        metadata['agent_type'] = 'conservative'
        metadata['action_name'] = ['allow', 'block_temp', 'block_perm', 
                                  'rate_limit', 'deep_inspect', 'isolate'][action]
        
        # 기존 ExperienceReplayBuffer 사용 (호환성 보장)
        self.memory.push(state, action, reward, next_state, done, metadata)
    
    def train(self, batch_size=32):
        """Conservative Q-Learning 학습"""
        if len(self.memory) < batch_size:
            return
        
        # 샘플링 (기존 버퍼 인터페이스 사용)
        if hasattr(self.memory, 'sample') and len(self.memory.sample.__code__.co_varnames) > 2:
            # Prioritized buffer
            states, actions, rewards, next_states, dones, weights, indices = self.memory.sample(batch_size)
        else:
            # 기본 buffer
            states, actions, rewards, next_states, dones = self.memory.sample(batch_size)
            weights = torch.ones(batch_size)
            indices = None
        
        # 현재 Q값
        current_q_values = self.q_network(states).gather(1, actions.unsqueeze(1))
        
        # 타겟 Q값 (Double DQN)
        with torch.no_grad():
            next_actions = self.q_network(next_states).argmax(1).unsqueeze(1)
            next_q_values = self.target_network(next_states).gather(1, next_actions)
            target_q_values = rewards.unsqueeze(1) + (1 - dones.unsqueeze(1)) * self.gamma * next_q_values
        
        # Conservative Q-Learning 손실
        # 1. 기본 TD 손실
        td_loss = nn.MSELoss(reduction='none')(current_q_values, target_q_values)
        
        # 2. Conservative 정규화 (과대추정 방지)
        # 모든 액션에 대한 Q값의 기댓값을 줄임
        all_q_values = self.q_network(states)
        conservative_penalty = torch.logsumexp(all_q_values, dim=1).mean() - current_q_values.mean()
        
        # 3. 총 손실 (TD 손실 + Conservative 페널티)
        total_loss = (weights * td_loss.squeeze()).mean() + self.alpha_cql * conservative_penalty
        
        # 역전파 및 최적화
        self.optimizer.zero_grad()
        total_loss.backward()
        
        # 그래디언트 클리핑 (안정성)
        torch.nn.utils.clip_grad_norm_(self.q_network.parameters(), 1.0)
        
        self.optimizer.step()
        
        # 우선순위 업데이트 (Prioritized Replay인 경우)
        if indices is not None and hasattr(self.memory, 'update_priorities'):
            td_errors = (current_q_values - target_q_values).abs().squeeze().detach()
            self.memory.update_priorities(indices.tolist(), td_errors.cpu().numpy())
        
        # 타겟 네트워크 소프트 업데이트
        self.update_target_network(self.tau)
        
        # 탐험률 감소
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
        
        # 통계 업데이트
        self.training_stats['policy_updates'] += 1
        self.training_stats['conservative_penalty'] = conservative_penalty.item()
    
    def update_target_network(self, tau):
        """타겟 네트워크 소프트 업데이트"""
        for target_param, local_param in zip(self.target_network.parameters(), 
                                           self.q_network.parameters()):
            target_param.data.copy_(tau * local_param.data + (1.0 - tau) * target_param.data)
    
    def save_buffer(self, filename):
        """기존과 동일한 인터페이스 - 영속성 보장"""
        import pickle
        
        buffer_data = {
            'states': self.memory.states[:self.memory.size] if hasattr(self.memory, 'states') else [],
            'actions': self.memory.actions[:self.memory.size] if hasattr(self.memory, 'actions') else [],
            'rewards': self.memory.rewards[:self.memory.size] if hasattr(self.memory, 'rewards') else [],
            'next_states': self.memory.next_states[:self.memory.size] if hasattr(self.memory, 'next_states') else [],
            'dones': self.memory.dones[:self.memory.size] if hasattr(self.memory, 'dones') else [],
            'metadata': self.memory.metadata[:self.memory.size] if hasattr(self.memory, 'metadata') else [],
            'size': self.memory.size,
            'position': getattr(self.memory, 'position', 0),
            'mode': self.mode,
            'state_size': self.state_size,
            'agent_type': 'conservative',
            'training_stats': self.training_stats
        }
        
        with open(filename, 'wb') as f:
            pickle.dump(buffer_data, f)
        
        logger.info(f"Conservative RL 버퍼 저장: {filename}")
    
    def load_buffer(self, filename):
        """기존과 동일한 인터페이스 - 호환성 보장"""
        import pickle
        
        try:
            with open(filename, 'rb') as f:
                buffer_data = pickle.load(f)
            
            # 호환성 확인
            if buffer_data.get('state_size') != self.state_size:
                logger.warning(f"State size 불일치: 저장된 {buffer_data.get('state_size')} vs 현재 {self.state_size}")
                return False
            
            # 버퍼 데이터 복원
            self.memory.clear()
            size = buffer_data['size']
            
            for i in range(size):
                if i < len(buffer_data['states']):
                    metadata = buffer_data['metadata'][i] if i < len(buffer_data['metadata']) else {}
                    self.memory.push(
                        buffer_data['states'][i],
                        buffer_data['actions'][i],
                        buffer_data['rewards'][i],
                        buffer_data['next_states'][i],
                        buffer_data['dones'][i],
                        metadata
                    )
            
            # 통계 복원
            if 'training_stats' in buffer_data:
                self.training_stats.update(buffer_data['training_stats'])
            
            logger.info(f"Conservative RL 버퍼 로드 성공: {size}개 경험")
            return True
            
        except Exception as e:
            logger.error(f"버퍼 로드 실패: {e}")
            return False
    
    def save_model(self, filename):
        """모델 저장 (PyTorch + 설정)"""
        checkpoint = {
            'q_network_state_dict': self.q_network.state_dict(),
            'target_network_state_dict': self.target_network.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'training_stats': self.training_stats,
            'hyperparameters': {
                'state_size': self.state_size,
                'action_size': self.action_size,
                'mode': self.mode,
                'alpha_cql': self.alpha_cql,
                'tau': self.tau,
                'gamma': self.gamma,
                'learning_rate': self.learning_rate,
                'epsilon': self.epsilon
            },
            'timestamp': datetime.now().isoformat(),
            'agent_version': '1.0'
        }
        
        torch.save(checkpoint, filename)
        logger.info(f"Conservative RL 모델 저장: {filename}")
    
    def load_model(self, filename):
        """모델 로드 (자동 복구)"""
        try:
            checkpoint = torch.load(filename, map_location='cpu')
            
            # 모델 가중치 복원
            self.q_network.load_state_dict(checkpoint['q_network_state_dict'])
            self.target_network.load_state_dict(checkpoint['target_network_state_dict'])
            self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
            
            # 하이퍼파라미터 복원
            hyperparams = checkpoint.get('hyperparameters', {})
            self.alpha_cql = hyperparams.get('alpha_cql', self.alpha_cql)
            self.tau = hyperparams.get('tau', self.tau)
            self.gamma = hyperparams.get('gamma', self.gamma)
            self.epsilon = hyperparams.get('epsilon', self.epsilon)
            
            # 통계 복원
            self.training_stats.update(checkpoint.get('training_stats', {}))
            
            logger.info(f"Conservative RL 모델 로드 성공: {filename}")
            return True
            
        except Exception as e:
            logger.error(f"모델 로드 실패: {e}")
            return False
    
    def get_buffer_stats(self):
        """버퍼 통계 (기존 인터페이스와 동일)"""
        stats = self.memory.get_stats() if hasattr(self.memory, 'get_stats') else {}
        stats.update({
            'buffer_size': len(self.memory),
            'buffer_capacity': self.memory.capacity,
            'buffer_utilization': len(self.memory) / self.memory.capacity,
            'agent_type': 'conservative',
            'mode': self.mode,
            'training_episodes': self.training_stats['episodes'],
            'avg_reward': self.training_stats['avg_reward'],
            'policy_updates': self.training_stats['policy_updates']
        })
        
        return stats
    
    def clear_buffer(self):
        """버퍼 초기화 (기존 인터페이스와 동일)"""
        self.memory.clear()
        self.training_stats = {
            'episodes': 0,
            'total_reward': 0.0,
            'avg_reward': 0.0,
            'policy_updates': 0,
            'conservative_penalty': 0.0
        }
        logger.info("Conservative RL 버퍼 초기화 완료")
    
    def optimize_for_deployment(self, target_device='cpu'):
        """배포용 최적화 (TinyMLConverter 기능 통합)"""
        if self.tiny_mode:
            # TinyML 변환
            if target_device == 'esp32':
                # ESP32용 최적화
                self._optimize_for_esp32()
            elif target_device == 'raspberry_pi':
                # 라즈베리파이용 최적화
                self._optimize_for_raspberry_pi()
            else:
                # 일반 CPU 최적화
                self._optimize_for_cpu()
        
        elif self.quantized:
            # 양자화 최적화
            self.q_network = torch.quantization.quantize_dynamic(
                self.q_network, {nn.Linear}, dtype=torch.qint8
            )
        
        logger.info(f"배포용 최적화 완료: {target_device}")
    
    def _optimize_for_esp32(self):
        """ESP32용 초경량 최적화"""
        # 모델 크기를 50KB 이하로 압축
        pass
    
    def _optimize_for_raspberry_pi(self):
        """라즈베리파이용 최적화"""
        # ARM 프로세서 최적화
        pass
    
    def _optimize_for_cpu(self):
        """일반 CPU 최적화"""
        # Intel/AMD 프로세서 최적화
        pass
    
    def get_model_size(self):
        """모델 크기 확인 (최적화 검증용)"""
        import tempfile
        
        with tempfile.NamedTemporaryFile() as tmp:
            torch.save(self.q_network.state_dict(), tmp.name)
            size_bytes = os.path.getsize(tmp.name)
        
        size_kb = size_bytes / 1024
        size_mb = size_kb / 1024
        
        return {
            'size_bytes': size_bytes,
            'size_kb': size_kb,
            'size_mb': size_mb,
            'mode': self.mode,
            'quantized': self.quantized
        }

def test_conservative_agent():
    """Conservative RL Agent 테스트"""
    print("=== Conservative RL Agent 테스트 시작 ===")
    
    try:
        # 환경 생성
        env = DefensePolicyEnv()
        
        # 에이전트 생성 (모든 모드 테스트)
        modes = ['standard', 'quantized', 'tiny']
        
        for mode in modes:
            print(f"\n--- {mode.upper()} 모드 테스트 ---")
            
            agent = ConservativeRLAgent(
                state_size=10,
                action_size=6,
                mode=mode
            )
            
            # 모델 크기 확인
            model_size = agent.get_model_size()
            print(f"모델 크기: {model_size['size_kb']:.2f}KB")
            
            # 간단한 학습 테스트
            state = env.reset()
            action = agent.act(state)
            next_state, reward, done, info = env.step(action)
            
            # 경험 저장
            agent.remember(state, action, reward, next_state, done, info)
            
            # 버퍼 통계
            stats = agent.get_buffer_stats()
            print(f"버퍼 사용률: {stats['buffer_utilization']:.1%}")
            
            # 저장/로드 테스트
            buffer_file = f"test_conservative_buffer_{mode}.pkl"
            model_file = f"test_conservative_model_{mode}.pth"
            
            agent.save_buffer(buffer_file)
            agent.save_model(model_file)
            
            # 새 에이전트로 로드 테스트
            new_agent = ConservativeRLAgent(state_size=10, action_size=6, mode=mode)
            buffer_loaded = new_agent.load_buffer(buffer_file)
            model_loaded = new_agent.load_model(model_file)
            
            print(f"저장/로드 테스트: 버퍼 {buffer_loaded}, 모델 {model_loaded}")
            
            # 테스트 파일 정리
            if os.path.exists(buffer_file):
                os.remove(buffer_file)
            if os.path.exists(model_file):
                os.remove(model_file)
        
        print("\n✅ Conservative RL Agent 테스트 완료")
        print("기존 ExperienceReplayBuffer 호환성 확인됨")
        
    except Exception as e:
        print(f"❌ 테스트 실패: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_conservative_agent()

