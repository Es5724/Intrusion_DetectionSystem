"""
Experience Replay Buffer for IDS Reinforcement Learning

이 모듈은 침입 탐지 시스템(IDS)의 강화학습을 위한 고급 Experience Replay Buffer를 구현합니다.
주요 기능:
- Prioritized Experience Replay (중요도 기반 샘플링)
- 메모리 효율적인 저장 (numpy arrays)
- IDS 특화 기능 (악성 패킷 우선순위)
- 통계 및 모니터링
"""

import numpy as np
import random
from collections import namedtuple
import torch
import logging
from typing import Tuple, List, Optional, Dict
import heapq

# Experience 튜플 정의
Experience = namedtuple('Experience', ['state', 'action', 'reward', 'next_state', 'done', 'metadata'])

class ExperienceReplayBuffer:
    """기본 Experience Replay Buffer"""
    
    def __init__(self, capacity: int, state_size: int, mode: str = "lightweight"):
        """
        Args:
            capacity: 버퍼의 최대 크기
            state_size: 상태 벡터의 크기 (lightweight: 7, performance: 12)
            mode: 운영 모드 ('lightweight' 또는 'performance')
        """
        self.capacity = capacity
        self.state_size = state_size
        self.mode = mode
        self.position = 0
        self.size = 0
        
        # 메모리 효율성을 위한 numpy 배열 사용
        self.states = np.zeros((capacity, state_size), dtype=np.float32)
        self.actions = np.zeros(capacity, dtype=np.int32)
        self.rewards = np.zeros(capacity, dtype=np.float32)
        self.next_states = np.zeros((capacity, state_size), dtype=np.float32)
        self.dones = np.zeros(capacity, dtype=np.bool_)
        
        # IDS 특화 메타데이터 저장
        self.metadata = [{} for _ in range(capacity)]
        
        # 통계 정보
        self.stats = {
            'total_experiences': 0,
            'malicious_experiences': 0,
            'benign_experiences': 0,
            'avg_reward': 0.0,
            'max_reward': float('-inf'),
            'min_reward': float('inf')
        }
        
        self.logger = logging.getLogger('ExperienceReplayBuffer')
        
    def push(self, state: np.ndarray, action: int, reward: float, 
             next_state: np.ndarray, done: bool, metadata: Optional[Dict] = None):
        """경험을 버퍼에 추가"""
        
        # 상태 크기 검증
        if len(state) != self.state_size or len(next_state) != self.state_size:
            raise ValueError(f"State size mismatch. Expected {self.state_size}, "
                           f"got {len(state)} and {len(next_state)}")
        
        # 데이터 저장
        self.states[self.position] = state
        self.actions[self.position] = action
        self.rewards[self.position] = reward
        self.next_states[self.position] = next_state
        self.dones[self.position] = done
        self.metadata[self.position] = metadata or {}
        
        # 통계 업데이트
        self._update_stats(reward, metadata)
        
        # 포인터 업데이트
        self.position = (self.position + 1) % self.capacity
        self.size = min(self.size + 1, self.capacity)
        
    def sample(self, batch_size: int) -> Tuple[torch.Tensor, ...]:
        """랜덤하게 배치 샘플링"""
        if self.size < batch_size:
            raise ValueError(f"Not enough experiences. Required: {batch_size}, Available: {self.size}")
        
        indices = np.random.choice(self.size, batch_size, replace=False)
        
        states = torch.FloatTensor(self.states[indices])
        actions = torch.LongTensor(self.actions[indices])
        rewards = torch.FloatTensor(self.rewards[indices])
        next_states = torch.FloatTensor(self.next_states[indices])
        dones = torch.FloatTensor(self.dones[indices])
        
        return states, actions, rewards, next_states, dones
    
    def _update_stats(self, reward: float, metadata: Optional[Dict]):
        """통계 정보 업데이트"""
        self.stats['total_experiences'] += 1
        
        # IDS 특화 통계
        if metadata and metadata.get('is_malicious', False):
            self.stats['malicious_experiences'] += 1
        else:
            self.stats['benign_experiences'] += 1
        
        # 보상 통계
        self.stats['max_reward'] = max(self.stats['max_reward'], reward)
        self.stats['min_reward'] = min(self.stats['min_reward'], reward)
        
        # 이동 평균 계산
        alpha = 0.01
        self.stats['avg_reward'] = (1 - alpha) * self.stats['avg_reward'] + alpha * reward
    
    def get_stats(self) -> Dict:
        """통계 정보 반환"""
        return self.stats.copy()
    
    def __len__(self) -> int:
        return self.size
    
    def clear(self):
        """버퍼 초기화"""
        self.position = 0
        self.size = 0
        self.stats = {
            'total_experiences': 0,
            'malicious_experiences': 0,
            'benign_experiences': 0,
            'avg_reward': 0.0,
            'max_reward': float('-inf'),
            'min_reward': float('inf')
        }


class PrioritizedExperienceReplayBuffer(ExperienceReplayBuffer):
    """우선순위 기반 Experience Replay Buffer
    
    TD 오차나 IDS 특화 중요도를 기반으로 샘플링 확률을 조정합니다.
    """
    
    def __init__(self, capacity: int, state_size: int, mode: str = "lightweight",
                 alpha: float = 0.6, beta: float = 0.4, beta_increment: float = 0.001):
        """
        Args:
            capacity: 버퍼의 최대 크기
            state_size: 상태 벡터의 크기
            mode: 운영 모드
            alpha: 우선순위의 중요도 (0: uniform, 1: full prioritization)
            beta: importance sampling의 보정 정도
            beta_increment: 에피소드마다 beta 증가량
        """
        super().__init__(capacity, state_size, mode)
        
        self.alpha = alpha
        self.beta = beta
        self.beta_increment = beta_increment
        self.epsilon = 1e-6  # 우선순위 최소값
        
        # 우선순위 저장
        self.priorities = np.zeros(capacity, dtype=np.float32)
        self.max_priority = 1.0
        
        # Sum tree for efficient sampling
        self.sum_tree = SumTree(capacity)
        
    def push(self, state: np.ndarray, action: int, reward: float,
             next_state: np.ndarray, done: bool, metadata: Optional[Dict] = None):
        """우선순위와 함께 경험 추가"""
        
        # IDS 특화 우선순위 계산
        priority = self._calculate_priority(reward, metadata)
        
        # 기본 push 실행
        super().push(state, action, reward, next_state, done, metadata)
        
        # 우선순위 저장
        self.priorities[self.position - 1] = priority
        self.sum_tree.update(self.position - 1, priority ** self.alpha)
        
    def _calculate_priority(self, reward: float, metadata: Optional[Dict]) -> float:
        """IDS 특화 우선순위 계산"""
        base_priority = self.max_priority
        
        if metadata:
            # 악성 패킷에 높은 우선순위
            if metadata.get('is_malicious', False):
                base_priority *= 2.0
            
            # 수리카타 경고가 있는 경우 추가 우선순위
            if self.mode == "performance" and metadata.get('suricata_alert', False):
                base_priority *= 1.5
            
            # 위협 레벨에 따른 가중치
            threat_level = metadata.get('threat_level', 0)
            base_priority *= (1 + threat_level * 0.5)
        
        # 보상 기반 조정
        if abs(reward) > 1.0:  # 큰 보상/페널티에 우선순위
            base_priority *= abs(reward)
        
        return max(base_priority, self.epsilon)
    
    def sample(self, batch_size: int) -> Tuple[torch.Tensor, ...]:
        """우선순위 기반 배치 샘플링"""
        if self.size < batch_size:
            raise ValueError(f"Not enough experiences. Required: {batch_size}, Available: {self.size}")
        
        indices = []
        priorities = []
        weights = []
        
        # 전체 우선순위 합을 배치 크기로 나눔
        segment = self.sum_tree.total() / batch_size
        
        # beta 업데이트
        self.beta = min(1.0, self.beta + self.beta_increment)
        
        for i in range(batch_size):
            a = segment * i
            b = segment * (i + 1)
            
            # 세그먼트에서 균등 샘플링
            value = random.uniform(a, b)
            idx, priority = self.sum_tree.get(value)
            
            indices.append(idx)
            priorities.append(priority)
        
        # Importance sampling weights 계산
        probs = np.array(priorities) / self.sum_tree.total()
        weights = (self.size * probs) ** (-self.beta)
        weights /= weights.max()  # 정규화
        
        # 텐서로 변환
        indices = np.array(indices)
        states = torch.FloatTensor(self.states[indices])
        actions = torch.LongTensor(self.actions[indices])
        rewards = torch.FloatTensor(self.rewards[indices])
        next_states = torch.FloatTensor(self.next_states[indices])
        dones = torch.FloatTensor(self.dones[indices])
        weights = torch.FloatTensor(weights)
        
        return states, actions, rewards, next_states, dones, weights, indices
    
    def update_priorities(self, indices: List[int], priorities: List[float]):
        """TD 오차 기반으로 우선순위 업데이트"""
        for idx, priority in zip(indices, priorities):
            priority = max(priority, self.epsilon)
            self.priorities[idx] = priority
            self.sum_tree.update(idx, priority ** self.alpha)
            self.max_priority = max(self.max_priority, priority)


class SumTree:
    """효율적인 우선순위 샘플링을 위한 Sum Tree 구조"""
    
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.tree = np.zeros(2 * capacity - 1, dtype=np.float32)
        
    def update(self, idx: int, priority: float):
        """리프 노드의 우선순위 업데이트"""
        tree_idx = idx + self.capacity - 1
        delta = priority - self.tree[tree_idx]
        self.tree[tree_idx] = priority
        
        # 부모 노드들 업데이트
        while tree_idx > 0:
            tree_idx = (tree_idx - 1) // 2
            self.tree[tree_idx] += delta
    
    def get(self, value: float) -> Tuple[int, float]:
        """값에 해당하는 리프 노드 찾기"""
        idx = 0
        
        while idx < self.capacity - 1:
            left = 2 * idx + 1
            right = left + 1
            
            if value <= self.tree[left]:
                idx = left
            else:
                value -= self.tree[left]
                idx = right
        
        data_idx = idx - self.capacity + 1
        return data_idx, self.tree[idx]
    
    def total(self) -> float:
        """전체 우선순위 합"""
        return self.tree[0]


class IDSExperienceReplayBuffer(PrioritizedExperienceReplayBuffer):
    """IDS 시스템에 특화된 Experience Replay Buffer
    
    네트워크 보안 특성을 고려한 추가 기능:
    - 패킷 시계열 패턴 저장
    - 공격 유형별 경험 분류
    - 희소 이벤트(악성 패킷) 보존
    """
    
    def __init__(self, capacity: int, state_size: int, mode: str = "lightweight",
                 alpha: float = 0.6, beta: float = 0.4, 
                 malicious_preserve_ratio: float = 0.3):
        """
        Args:
            malicious_preserve_ratio: 악성 패킷 경험의 최소 보존 비율
        """
        super().__init__(capacity, state_size, mode, alpha, beta)
        
        self.malicious_preserve_ratio = malicious_preserve_ratio
        self.malicious_indices = set()  # 악성 패킷 인덱스 추적
        
        # 공격 유형별 통계
        self.attack_type_stats = {}
        
        # 시계열 패턴 저장을 위한 순환 버퍼
        self.sequence_length = 10
        self.state_sequences = []
        
    def push(self, state: np.ndarray, action: int, reward: float,
             next_state: np.ndarray, done: bool, metadata: Optional[Dict] = None):
        """IDS 특화 경험 추가"""
        
        # 악성 패킷 보존 로직
        if metadata and metadata.get('is_malicious', False):
            # 버퍼가 가득 찬 경우, 정상 패킷을 우선 제거
            if self.size == self.capacity:
                self._make_space_for_malicious()
            
            # 악성 패킷 인덱스 추적
            self.malicious_indices.add(self.position)
            
            # 공격 유형 통계 업데이트
            attack_type = metadata.get('attack_type', 'unknown')
            self.attack_type_stats[attack_type] = self.attack_type_stats.get(attack_type, 0) + 1
        
        # 기본 push 실행
        super().push(state, action, reward, next_state, done, metadata)
        
        # 시계열 패턴 업데이트
        self._update_sequences(state)
    
    def _make_space_for_malicious(self):
        """악성 패킷을 위한 공간 확보"""
        # 현재 악성 패킷 비율 확인
        malicious_ratio = len(self.malicious_indices) / self.capacity
        
        if malicious_ratio < self.malicious_preserve_ratio:
            # 정상 패킷 중 우선순위가 낮은 것을 찾아 대체
            min_priority_idx = None
            min_priority = float('inf')
            
            for i in range(self.size):
                if i not in self.malicious_indices and self.priorities[i] < min_priority:
                    min_priority = self.priorities[i]
                    min_priority_idx = i
            
            if min_priority_idx is not None:
                self.position = min_priority_idx
                self.malicious_indices.discard(min_priority_idx)
    
    def _update_sequences(self, state: np.ndarray):
        """시계열 패턴 업데이트"""
        if len(self.state_sequences) >= self.sequence_length:
            self.state_sequences.pop(0)
        self.state_sequences.append(state.copy())
    
    def get_sequence_context(self) -> Optional[np.ndarray]:
        """현재 시계열 컨텍스트 반환"""
        if len(self.state_sequences) < self.sequence_length:
            return None
        return np.array(self.state_sequences)
    
    def get_attack_statistics(self) -> Dict:
        """공격 유형별 통계 반환"""
        total_attacks = sum(self.attack_type_stats.values())
        if total_attacks == 0:
            return {}
        
        stats = {
            'total_attacks': total_attacks,
            'attack_distribution': {
                attack_type: count / total_attacks 
                for attack_type, count in self.attack_type_stats.items()
            }
        }
        return stats
    
    def sample_by_attack_type(self, batch_size: int, attack_type: str) -> Tuple[torch.Tensor, ...]:
        """특정 공격 유형의 경험만 샘플링"""
        attack_indices = []
        
        for i in range(self.size):
            if (self.metadata[i].get('attack_type') == attack_type and 
                i in self.malicious_indices):
                attack_indices.append(i)
        
        if len(attack_indices) < batch_size:
            # 부족한 경우 일반 샘플링으로 보충
            return self.sample(batch_size)
        
        # 공격 유형별 샘플링
        indices = np.random.choice(attack_indices, batch_size, replace=False)
        
        states = torch.FloatTensor(self.states[indices])
        actions = torch.LongTensor(self.actions[indices])
        rewards = torch.FloatTensor(self.rewards[indices])
        next_states = torch.FloatTensor(self.next_states[indices])
        dones = torch.FloatTensor(self.dones[indices])
        
        return states, actions, rewards, next_states, dones 