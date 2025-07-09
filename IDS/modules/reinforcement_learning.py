import os
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
# gym 패키지 임포트 시도 - 없을 경우 자동 설치
try:
    import gym
    from gym import spaces
except ImportError:
    import subprocess
    import sys
    print("gym 모듈이 설치되어 있지 않습니다. 설치 중...")
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'gym'])
    import gym
    from gym import spaces
    print("gym 모듈 설치 완료!")

from collections import deque
import random
import joblib
import matplotlib.pyplot as plt
import ipaddress
try:
    from scapy.all import IP, TCP, sniff
except ImportError:
    import subprocess
    import sys
    print("scapy 모듈이 설치되어 있지 않습니다. 설치 중...")
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'scapy'])
    from scapy.all import IP, TCP, sniff
    print("scapy 모듈 설치 완료!")

# Experience Replay Buffer 임포트
try:
    from experience_replay_buffer import IDSExperienceReplayBuffer, ExperienceReplayBuffer
except ImportError:
    from .experience_replay_buffer import IDSExperienceReplayBuffer, ExperienceReplayBuffer

class NetworkEnv(gym.Env):
    def __init__(self, max_steps=1000, mode="lightweight"):
        super(NetworkEnv, self).__init__()
        
        # 운영 모드 설정
        self.mode = mode
        
        # 액션 스페이스 정의 (0: 허용, 1: 차단, 2: 모니터링)
        self.action_space = spaces.Discrete(3)
        
        # 관찰 스페이스 정의 (패킷 특성들)
        if self.mode == "performance":
            # 고성능 모드: 기본 7개 특성 + 수리카타 5개 특성 = 12개 특성
            self.observation_space = spaces.Box(
                low=-np.inf, 
                high=np.inf, 
                shape=(12,),  # 12개의 특성
                dtype=np.float32
            )
        else:
            # 경량 모드: 기본 7개의 특성
            self.observation_space = spaces.Box(
                low=-np.inf, 
                high=np.inf, 
                shape=(7,),  # 7개의 특성: [src_ip, dst_ip, protocol, length, ttl, flags, rf_prob]
                dtype=np.float32
            )
        
        self.max_steps = max_steps
        self.current_step = 0
        self.total_reward = 0
        self.episode_rewards = []
        self.packet_buffer = []
        self.rf_model = None
        
        # 랜덤포레스트 모델 로드
        try:
            if os.path.exists('random_forest_model.pkl'):
                self.rf_model = joblib.load('random_forest_model.pkl')
        except Exception as e:
            print(f"랜덤포레스트 모델 로드 실패: {e}")

    def set_mode(self, mode):
        """운영 모드 설정
        
        Args:
            mode (str): 'lightweight' 또는 'performance'
        """
        if mode not in ["lightweight", "performance"]:
            raise ValueError("모드는 'lightweight' 또는 'performance'여야 합니다.")
            
        # 모드가 변경되면 관찰 공간 업데이트
        if self.mode != mode:
            self.mode = mode
            
            # 관찰 공간 재정의
            if self.mode == "performance":
                self.observation_space = spaces.Box(
                    low=-np.inf, 
                    high=np.inf, 
                    shape=(12,),  # 12개의 특성
                    dtype=np.float32
                )
            else:
                self.observation_space = spaces.Box(
                    low=-np.inf, 
                    high=np.inf, 
                    shape=(7,),  # 7개의 특성
                    dtype=np.float32
                )
        
    def reset(self):
        self.current_step = 0
        self.total_reward = 0
        self.packet_buffer = []
        
        # 모드에 맞는 초기 상태 반환
        if self.mode == "performance":
            return np.zeros(12, dtype=np.float32)
        else:
            return np.zeros(7, dtype=np.float32)
    
    def _extract_packet_features(self, packet):
        """패킷에서 특성 추출 - 모드에 따라 다른 특성 세트 반환"""
        if self.mode == "performance":
            return self._extract_enhanced_features(packet)
        else:
            return self._extract_basic_features(packet)
    
    def _extract_basic_features(self, packet):
        """기본 특성 추출 (경량 모드)"""
        features = np.zeros(7, dtype=np.float32)
        
        if IP in packet:
            # IP 주소를 숫자로 변환
            src_ip = int(ipaddress.IPv4Address(packet[IP].src))
            dst_ip = int(ipaddress.IPv4Address(packet[IP].dst))
            
            features[0] = src_ip / 2**32  # 정규화
            features[1] = dst_ip / 2**32  # 정규화
            features[2] = packet[IP].proto
            features[3] = len(packet) / 1500  # 정규화 (MTU 기준)
            features[4] = packet[IP].ttl / 255  # 정규화
            
            # TCP 플래그 처리
            if TCP in packet:
                flags = packet[TCP].flags
                features[5] = flags / 63  # 정규화 (최대 플래그 값)
            
            # 랜덤포레스트 예측 확률
            if self.rf_model is not None:
                try:
                    packet_df = pd.DataFrame({
                        'source': [packet[IP].src],
                        'destination': [packet[IP].dst],
                        'protocol': [packet[IP].proto],
                        'length': [len(packet)]
                    })
                    prob = self.rf_model.predict_proba(packet_df)[0][1]
                    features[6] = prob
                except:
                    features[6] = 0.5  # 기본값
        
        return features
    
    def _extract_enhanced_features(self, packet):
        """고성능 모드용 확장 특성 추출 (기본 특성 + 수리카타 특성)"""
        # 먼저 기본 특성 추출
        basic_features = self._extract_basic_features(packet)
        
        # 고성능 모드 확장 특성 생성
        features = np.zeros(12, dtype=np.float32)
        
        # 기본 특성 복사
        features[:7] = basic_features
        
        # 수리카타 특성이 패킷에 있는 경우 추출
        if hasattr(packet, 'suricata_alert') and packet.suricata_alert:
            # 수리카타 경고 여부 (0/1)
            features[7] = 1.0
            
            # 시그니처 우선순위 (정규화: 1-4 -> 0-1)
            severity = getattr(packet, 'suricata_severity', 2)
            features[8] = (severity - 1) / 3.0 if 1 <= severity <= 4 else 0.5
            
            # 카테고리 인코딩 (임의의 간단한 인코딩)
            category = getattr(packet, 'suricata_category', 'unknown')
            category_code = self._encode_category(category)
            features[9] = category_code
            
            # 시그니처 ID (정규화)
            sig_id = getattr(packet, 'suricata_signature_id', 0)
            features[10] = min(sig_id / 10000.0, 1.0)  # 임의로 10000으로 나눔
            
            # 수리카타 신뢰도
            features[11] = getattr(packet, 'suricata_confidence', 0.8)
        else:
            # 수리카타 특성이 없는 경우 기본값 설정
            features[7] = 0.0  # 수리카타 경고 없음
            features[8:12] = 0.5  # 다른 특성들은 중간값
            
        return features
            
    def _encode_category(self, category):
        """수리카타 카테고리를 숫자로 인코딩"""
        categories = {
            "unknown": 0.1,
            "not-suspicious": 0.2,
            "bad-unknown": 0.3,
            "attempted-recon": 0.4,
            "successful-recon-limited": 0.5,
            "successful-recon-largescale": 0.6,
            "attempted-dos": 0.7,
            "successful-dos": 0.8,
            "attempted-user": 0.85,
            "unsuccessful-user": 0.86,
            "successful-user": 0.9,
            "attempted-admin": 0.95,
            "successful-admin": 1.0
        }
        return categories.get(category.lower(), 0.5)
    
    def step(self, action):
        self.current_step += 1
        
        # 패킷 캡처 및 특성 추출
        metadata = {}
        try:
            packet = sniff(count=1, timeout=1)[0]
            state = self._extract_packet_features(packet)
            
            # IDS 메타데이터 생성
            is_malicious = not self._is_safe_packet(packet)
            metadata['is_malicious'] = is_malicious
            
            # 수리카타 정보가 있는 경우
            if hasattr(packet, 'suricata_alert') and packet.suricata_alert:
                metadata['suricata_alert'] = True
                metadata['attack_type'] = getattr(packet, 'suricata_category', 'unknown')
                metadata['threat_level'] = getattr(packet, 'suricata_severity', 2) / 4.0
            else:
                metadata['suricata_alert'] = False
                metadata['attack_type'] = 'benign' if not is_malicious else 'unknown'
                metadata['threat_level'] = 0.0
                
            # 패킷 정보 추가
            if IP in packet:
                metadata['src_ip'] = packet[IP].src
                metadata['dst_ip'] = packet[IP].dst
                metadata['protocol'] = packet[IP].proto
                
        except:
            # 오류 시 빈 상태 반환 (모드에 맞게)
            if self.mode == "performance":
                state = np.zeros(12, dtype=np.float32)
            else:
                state = np.zeros(7, dtype=np.float32)
            packet = None
        
        # 보상 계산
        reward = self._calculate_reward(action, packet if 'packet' in locals() else None)
        self.total_reward += reward
        
        # 종료 조건 확인
        done = self.current_step >= self.max_steps
        
        # info 딕셔너리에 메타데이터 포함
        info = {'metadata': metadata}
        
        return state, reward, done, info
    
    def _calculate_reward(self, action, packet):
        """보상 계산 함수"""
        reward = 0
        
        if packet is None:
            return -0.1  # 패킷 캡처 실패 페널티
        
        # 수리카타 경고가 있는 패킷 처리 (고성능 모드)
        is_malicious = not self._is_safe_packet(packet)
        if self.mode == "performance" and hasattr(packet, 'suricata_alert') and packet.suricata_alert:
            # 수리카타 경고가 있으면 위험도 증가
            is_malicious = True
            
        # 기본 보상
        if action == 0:  # 허용
            if not is_malicious:
                reward += 1.0
            else:
                reward -= 2.0
        elif action == 1:  # 차단
            if is_malicious:
                reward += 2.0
            else:
                reward -= 1.0
        else:  # 모니터링
            reward += 0.5
        
        # 탐색 페널티
        if self.current_step < 100:
            reward *= 0.8  # 초기 탐색 단계
        elif self.current_step < 400:
            reward *= 0.9  # 중간 단계
        
        return reward
    
    def _is_safe_packet(self, packet):
        """패킷의 안전성 판단"""
        # 수리카타 경고가 있으면 안전하지 않음
        if self.mode == "performance" and hasattr(packet, 'suricata_alert') and packet.suricata_alert:
            return False
            
        # 랜덤포레스트 기반 판단
        if self.rf_model is not None:
            try:
                packet_df = pd.DataFrame({
                    'source': [packet[IP].src],
                    'destination': [packet[IP].dst],
                    'protocol': [packet[IP].proto],
                    'length': [len(packet)]
                })
                prediction = self.rf_model.predict(packet_df)[0]
                return prediction == 0  # 0이 정상 패킷
            except:
                return True  # 예측 실패 시 안전하다고 가정
        return True  # 모델이 없으면 안전하다고 가정

class DQNAgent:
    def __init__(self, state_size, action_size, mode="lightweight", 
                 use_prioritized_replay=True, replay_buffer_capacity=10000):
        self.state_size = state_size
        self.action_size = action_size
        self.mode = mode
        self.use_prioritized_replay = use_prioritized_replay
        
        # Experience Replay Buffer 초기화
        if use_prioritized_replay:
            self.memory = IDSExperienceReplayBuffer(
                capacity=replay_buffer_capacity,
                state_size=state_size,
                mode=mode,
                alpha=0.6,
                beta=0.4,
                malicious_preserve_ratio=0.3
            )
        else:
            self.memory = ExperienceReplayBuffer(
                capacity=replay_buffer_capacity,
                state_size=state_size,
                mode=mode
            )
        
        self.gamma = 0.95    # 할인율
        self.epsilon = 1.0   # 탐험률
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.995
        self.learning_rate = 0.001
        
        # 모드별 모델 구성
        if self.mode == "performance":
            self.model = self._build_performance_model()
            self.target_model = self._build_performance_model()
        else:
            self.model = self._build_lightweight_model()
            self.target_model = self._build_lightweight_model()
            
        self.update_target_model()
        
        # 옵티마이저 초기화
        self.optimizer = optim.Adam(self.model.parameters(), lr=self.learning_rate)
        
    def _build_lightweight_model(self):
        """경량 모드용 신경망 모델 (7개 특성 입력)"""
        model = nn.Sequential(
            nn.Linear(7, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, self.action_size)
        )
        return model
        
    def _build_performance_model(self):
        """고성능 모드용 신경망 모델 (12개 특성 입력)"""
        model = nn.Sequential(
            nn.Linear(12, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, self.action_size)
        )
        return model
    
    def _build_model(self):
        """현재 모드에 맞는 모델 생성"""
        if self.mode == "performance":
            return self._build_performance_model()
        else:
            return self._build_lightweight_model()
    
    def update_target_model(self):
        self.target_model.load_state_dict(self.model.state_dict())
    
    def switch_mode(self, new_mode):
        """모드 전환
        
        Args:
            new_mode (str): 'lightweight' 또는 'performance'
            
        Returns:
            bool: 성공 여부
        """
        if new_mode not in ["lightweight", "performance"]:
            print("모드는 'lightweight' 또는 'performance'여야 합니다.")
            return False
            
        if new_mode == self.mode:
            return True
            
        print(f"{self.mode} 모드에서 {new_mode} 모드로 전환 중...")
        
        # 현재 모델 저장
        self._save_current_model()
        
        # 현재 Experience Replay Buffer의 경험들을 임시 저장
        saved_experiences = []
        if len(self.memory) > 0:
            print("기존 경험 데이터를 보존합니다...")
            # 메모리의 모든 경험을 추출 (간단한 방법)
            for i in range(len(self.memory)):
                if i < self.memory.size:
                    saved_experiences.append({
                        'state': self.memory.states[i].copy(),
                        'action': self.memory.actions[i],
                        'reward': self.memory.rewards[i],
                        'next_state': self.memory.next_states[i].copy(),
                        'done': self.memory.dones[i],
                        'metadata': self.memory.metadata[i].copy() if hasattr(self.memory, 'metadata') else {}
                    })
        
        # 모드 전환
        self.mode = new_mode
        
        # 새 모드에 맞는 모델 생성
        if self.mode == "performance":
            self.state_size = 12
            self.model = self._build_performance_model()
            self.target_model = self._build_performance_model()
        else:
            self.state_size = 7
            self.model = self._build_lightweight_model()
            self.target_model = self._build_lightweight_model()
        
        # 옵티마이저 재초기화
        self.optimizer = optim.Adam(self.model.parameters(), lr=self.learning_rate)
        
        # Experience Replay Buffer 재초기화 (새로운 state_size로)
        capacity = self.memory.capacity
        if self.use_prioritized_replay:
            self.memory = IDSExperienceReplayBuffer(
                capacity=capacity,
                state_size=self.state_size,
                mode=self.mode,
                alpha=0.6,
                beta=0.4,
                malicious_preserve_ratio=0.3
            )
        else:
            self.memory = ExperienceReplayBuffer(
                capacity=capacity,
                state_size=self.state_size,
                mode=self.mode
            )
        
        # 저장된 경험들을 새로운 형식으로 변환하여 복원 (가능한 경우)
        # 모드 전환 시 상태 벡터 크기가 다르므로 경험을 직접 복원할 수 없음
        print(f"모드 전환으로 인해 {len(saved_experiences)}개의 기존 경험이 초기화됩니다.")
            
        # 저장된 모델이 있으면 로드
        self._load_mode_model()
        
        print(f"{new_mode} 모드로 전환 완료")
        return True
    
    def _save_current_model(self):
        """현재 모드의 모델 저장"""
        filename = f"dqn_model_{self.mode}.pth"
        torch.save(self.model.state_dict(), filename)
        print(f"모델이 {filename}에 저장되었습니다.")
    
    def _load_mode_model(self):
        """현재 모드에 맞는 모델 파일 로드"""
        filename = f"dqn_model_{self.mode}.pth"
        if os.path.exists(filename):
            self.model.load_state_dict(torch.load(filename))
            self.target_model.load_state_dict(self.model.state_dict())
            print(f"모델이 {filename}에서 로드되었습니다.")
            return True
        return False
    
    def remember(self, state, action, reward, next_state, done, metadata=None):
        """경험을 Experience Replay Buffer에 저장
        
        Args:
            state: 현재 상태
            action: 수행한 액션
            reward: 받은 보상
            next_state: 다음 상태
            done: 에피소드 종료 여부
            metadata: IDS 관련 메타데이터 (악성 여부, 공격 유형 등)
        """
        # numpy 배열로 변환
        if not isinstance(state, np.ndarray):
            state = np.array(state, dtype=np.float32)
        if not isinstance(next_state, np.ndarray):
            next_state = np.array(next_state, dtype=np.float32)
            
        self.memory.push(state, action, reward, next_state, done, metadata)
    
    def predict_threat(self, packet_features):
        """
        패킷 특성을 기반으로 위협 점수를 예측합니다.
        
        Args:
            packet_features (list): [length, source_len, destination_len] 형태의 특성
            
        Returns:
            float: 0.0~1.0 사이의 위협 점수
        """
        try:
            # 특성을 모델 입력 형태로 변환
            if self.mode == "performance":
                # 고성능 모드: 12개 특성 필요
                state = np.zeros(12, dtype=np.float32)
                # 기본 특성들 설정
                state[0] = min(packet_features[0] / 10000.0, 1.0)  # 패킷 길이 정규화
                state[1] = min(packet_features[1] / 100.0, 1.0)   # 소스 주소 길이
                state[2] = min(packet_features[2] / 100.0, 1.0)   # 목적지 주소 길이
                # 나머지는 기본값 0으로 설정 (실제로는 더 많은 특성을 추출해야 함)
            else:
                # 경량 모드: 7개 특성
                state = np.zeros(7, dtype=np.float32)
                state[0] = min(packet_features[0] / 10000.0, 1.0)  # 패킷 길이 정규화
                state[1] = min(packet_features[1] / 100.0, 1.0)   # 소스 주소 길이
                state[2] = min(packet_features[2] / 100.0, 1.0)   # 목적지 주소 길이
                # 나머지는 기본값 0으로 설정
                
            # 모델 예측 실행
            with torch.no_grad():
                state_tensor = torch.FloatTensor(state).unsqueeze(0)
                q_values = self.model(state_tensor)
                
                # Q값을 위협 점수로 변환 (소프트맥스 사용)
                probabilities = torch.softmax(q_values, dim=1)
                
                # 악성 행동 확률 계산 (action_size가 2라면: 0=정상, 1=악성)
                if self.action_size == 2:
                    threat_score = probabilities[0][1].item()  # 악성 클래스 확률
                else:
                    # 다중 클래스인 경우 최대값을 위협 점수로 사용
                    threat_score = torch.max(probabilities[0]).item()
                
                return min(max(threat_score, 0.0), 1.0)  # 0.0~1.0 범위로 제한
                
        except Exception as e:
            # 예측 실패 시 0.0 반환 (안전으로 간주)
            return 0.0

    def act(self, state):
        if np.random.rand() <= self.epsilon:
            return random.randrange(self.action_size)
        state = torch.FloatTensor(state).unsqueeze(0)
        act_values = self.model(state)
        return torch.argmax(act_values[0]).item()
    
    def replay(self, batch_size):
        """Experience Replay를 통한 학습"""
        if len(self.memory) < batch_size:
            return
        
        # 샘플링
        if self.use_prioritized_replay and isinstance(self.memory, IDSExperienceReplayBuffer):
            # Prioritized Experience Replay
            states, actions, rewards, next_states, dones, weights, indices = self.memory.sample(batch_size)
        else:
            # 일반 Experience Replay
            states, actions, rewards, next_states, dones = self.memory.sample(batch_size)
            weights = torch.ones(batch_size)
            indices = None
        
        # 현재 Q값 계산
        current_q_values = self.model(states).gather(1, actions.unsqueeze(1))
        
        # 타겟 Q값 계산 (Double DQN)
        with torch.no_grad():
            # 다음 상태에서 최적 액션 선택 (현재 모델 사용)
            next_actions = self.model(next_states).argmax(1).unsqueeze(1)
            # 타겟 모델로 Q값 계산
            next_q_values = self.target_model(next_states).gather(1, next_actions)
            target_q_values = rewards.unsqueeze(1) + (1 - dones.unsqueeze(1)) * self.gamma * next_q_values
        
        # TD 오차 계산
        td_errors = (current_q_values - target_q_values).abs().squeeze().detach()
        
        # 우선순위 업데이트 (Prioritized Replay인 경우)
        if indices is not None and hasattr(self.memory, 'update_priorities'):
            self.memory.update_priorities(indices.tolist(), td_errors.cpu().numpy())
        
        # 손실 계산 (importance sampling weights 적용)
        loss = (weights * nn.MSELoss(reduction='none')(current_q_values, target_q_values).squeeze()).mean()
        
        # 역전파 및 최적화
        self.optimizer.zero_grad()
        loss.backward()
        
        # 그래디언트 클리핑 (안정성을 위해)
        torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
        
        self.optimizer.step()
        
        # 엡실론 감소
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
    
    def get_buffer_stats(self):
        """Experience Replay Buffer의 통계 정보 반환"""
        stats = self.memory.get_stats()
        stats['buffer_size'] = len(self.memory)
        stats['buffer_capacity'] = self.memory.capacity
        stats['buffer_utilization'] = len(self.memory) / self.memory.capacity
        
        # IDS 특화 통계 추가
        if hasattr(self.memory, 'get_attack_statistics'):
            attack_stats = self.memory.get_attack_statistics()
            stats.update(attack_stats)
        
        return stats
    
    def clear_buffer(self):
        """Experience Replay Buffer 초기화"""
        self.memory.clear()
        print("Experience Replay Buffer가 초기화되었습니다.")
    
    def save_buffer(self, filename):
        """Experience Replay Buffer를 파일로 저장"""
        import pickle
        buffer_data = {
            'states': self.memory.states[:self.memory.size],
            'actions': self.memory.actions[:self.memory.size],
            'rewards': self.memory.rewards[:self.memory.size],
            'next_states': self.memory.next_states[:self.memory.size],
            'dones': self.memory.dones[:self.memory.size],
            'metadata': self.memory.metadata[:self.memory.size] if hasattr(self.memory, 'metadata') else [],
            'size': self.memory.size,
            'position': self.memory.position,
            'mode': self.mode,
            'state_size': self.state_size
        }
        
        with open(filename, 'wb') as f:
            pickle.dump(buffer_data, f)
        print(f"Experience Replay Buffer가 {filename}에 저장되었습니다.")
    
    def load_buffer(self, filename):
        """파일에서 Experience Replay Buffer 로드"""
        import pickle
        try:
            with open(filename, 'rb') as f:
                buffer_data = pickle.load(f)
            
            # 모드와 state_size 확인
            if buffer_data['mode'] != self.mode or buffer_data['state_size'] != self.state_size:
                print(f"경고: 저장된 버퍼의 모드({buffer_data['mode']}) 또는 state_size({buffer_data['state_size']})가 "
                      f"현재 설정(mode={self.mode}, state_size={self.state_size})과 다릅니다.")
                return False
            
            # 버퍼 데이터 복원
            size = buffer_data['size']
            self.memory.clear()
            
            for i in range(size):
                metadata = buffer_data['metadata'][i] if i < len(buffer_data['metadata']) else None
                self.memory.push(
                    buffer_data['states'][i],
                    buffer_data['actions'][i],
                    buffer_data['rewards'][i],
                    buffer_data['next_states'][i],
                    buffer_data['dones'][i],
                    metadata
                )
            
            print(f"{filename}에서 {size}개의 경험을 로드했습니다.")
            return True
            
        except Exception as e:
            import logging
            logging.getLogger('ReinforcementLearning').error(f"버퍼 로드 실패: {e}")
            return False

def train_rl_agent(env, agent, episodes=500, batch_size=32, 
                   save_buffer_interval=50, buffer_save_path="experience_buffer.pkl"):
    """강화학습 에이전트 훈련
    
    Args:
        env: 환경
        agent: DQN 에이전트
        episodes: 훈련 에피소드 수
        batch_size: 배치 크기
        save_buffer_interval: 버퍼 저장 주기
        buffer_save_path: 버퍼 저장 경로
    """
    rewards_history = []
    malicious_packet_counts = []
    buffer_stats_history = []
    
    for episode in range(episodes):
        state = env.reset()
        total_reward = 0
        episode_malicious_count = 0
        
        for step in range(env.max_steps):
            action = agent.act(state)
            next_state, reward, done, info = env.step(action)
            
            # 메타데이터 추출
            metadata = info.get('metadata', {})
            
            # 악성 패킷 카운트
            if metadata.get('is_malicious', False):
                episode_malicious_count += 1
            
            # Experience Replay Buffer에 저장
            agent.remember(state, action, reward, next_state, done, metadata)
            
            state = next_state
            total_reward += reward
            
            if done:
                break
            
            # 충분한 경험이 쌓이면 학습
            if len(agent.memory) >= batch_size:
                agent.replay(batch_size)
        
        # 에피소드마다 타겟 모델 업데이트
        if episode % 10 == 0:
            agent.update_target_model()
        
        # 통계 기록
        rewards_history.append(total_reward)
        malicious_packet_counts.append(episode_malicious_count)
        
        # 버퍼 통계 수집
        if episode % 10 == 0:
            buffer_stats = agent.get_buffer_stats()
            buffer_stats_history.append({
                'episode': episode,
                **buffer_stats
            })
        
        # 학습 진행 상황을 로그에만 기록 (화면 출력 안 함)
        if episode % 10 == 0:
            avg_reward = np.mean(rewards_history[-10:])
            avg_malicious = np.mean(malicious_packet_counts[-10:])
            buffer_stats = agent.get_buffer_stats()
            
            import logging
            logging.getLogger('ReinforcementLearning').info(f"에피소드: {episode}")
            logging.getLogger('ReinforcementLearning').info(f"  총 보상: {total_reward:.2f}, 평균 보상: {avg_reward:.2f}")
            logging.getLogger('ReinforcementLearning').info(f"  악성 패킷: {episode_malicious_count}, 평균: {avg_malicious:.1f}")
            logging.getLogger('ReinforcementLearning').info(f"  탐험률: {agent.epsilon:.3f}")
            logging.getLogger('ReinforcementLearning').info(f"  버퍼 사용률: {buffer_stats['buffer_utilization']:.1%}")
            logging.getLogger('ReinforcementLearning').info(f"  버퍼 내 악성 경험: {buffer_stats.get('malicious_experiences', 0)}")
            
            # 공격 유형 분포를 로그에만 기록 (있는 경우)
            if 'attack_distribution' in buffer_stats:
                logging.getLogger('ReinforcementLearning').info("  공격 유형 분포:")
                for attack_type, ratio in buffer_stats['attack_distribution'].items():
                    logging.getLogger('ReinforcementLearning').info(f"    - {attack_type}: {ratio:.1%}")
        
        # 주기적으로 버퍼 저장
        if episode > 0 and episode % save_buffer_interval == 0:
            agent.save_buffer(f"{buffer_save_path}.episode_{episode}")
            import logging
            logging.getLogger('ReinforcementLearning').info(f"  Experience Buffer 저장 완료: episode_{episode}")
    
    # 훈련 완료 후 최종 버퍼 저장
    agent.save_buffer(buffer_save_path)
    
    return rewards_history, malicious_packet_counts, buffer_stats_history

def plot_training_results(rewards, malicious_counts=None, buffer_stats=None):
    """훈련 결과 시각화
    
    Args:
        rewards: 에피소드별 보상 리스트
        malicious_counts: 에피소드별 악성 패킷 수 (선택사항)
        buffer_stats: 버퍼 통계 히스토리 (선택사항)
    """
    # 서브플롯 개수 결정
    num_plots = 1
    if malicious_counts is not None:
        num_plots += 1
    if buffer_stats is not None:
        num_plots += 1
    
    fig, axes = plt.subplots(num_plots, 1, figsize=(12, 4*num_plots))
    if num_plots == 1:
        axes = [axes]
    
    plot_idx = 0
    
    # 보상 플롯
    ax = axes[plot_idx]
    window_size = 10
    moving_avg = np.convolve(rewards, np.ones(window_size)/window_size, mode='valid')
    
    ax.plot(rewards, alpha=0.3, label='원본 보상', color='blue')
    ax.plot(range(window_size-1, len(rewards)), moving_avg, 
            label=f'{window_size}회 이동 평균', color='red', linewidth=2)
    ax.set_title('강화학습 훈련 결과 - 보상')
    ax.set_xlabel('에피소드')
    ax.set_ylabel('총 보상')
    ax.legend()
    ax.grid(True, alpha=0.3)
    plot_idx += 1
    
    # 악성 패킷 수 플롯
    if malicious_counts is not None:
        ax = axes[plot_idx]
        moving_avg_mal = np.convolve(malicious_counts, np.ones(window_size)/window_size, mode='valid')
        
        ax.plot(malicious_counts, alpha=0.3, label='악성 패킷 수', color='orange')
        ax.plot(range(window_size-1, len(malicious_counts)), moving_avg_mal,
                label=f'{window_size}회 이동 평균', color='darkred', linewidth=2)
        ax.set_title('에피소드별 악성 패킷 탐지')
        ax.set_xlabel('에피소드')
        ax.set_ylabel('악성 패킷 수')
        ax.legend()
        ax.grid(True, alpha=0.3)
        plot_idx += 1
    
    # 버퍼 통계 플롯
    if buffer_stats is not None and len(buffer_stats) > 0:
        ax = axes[plot_idx]
        
        episodes = [stat['episode'] for stat in buffer_stats]
        buffer_util = [stat['buffer_utilization'] * 100 for stat in buffer_stats]
        malicious_ratio = [stat.get('malicious_experiences', 0) / stat.get('total_experiences', 1) * 100 
                          for stat in buffer_stats]
        
        ax.plot(episodes, buffer_util, label='버퍼 사용률 (%)', marker='o')
        ax.plot(episodes, malicious_ratio, label='악성 경험 비율 (%)', marker='s')
        ax.set_title('Experience Replay Buffer 통계')
        ax.set_xlabel('에피소드')
        ax.set_ylabel('비율 (%)')
        ax.legend()
        ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.show()

def save_model(agent, filename=None):
    """강화학습 모델 저장"""
    if filename is None:
        filename = f"dqn_model_{agent.mode}.pth"
    torch.save(agent.model.state_dict(), filename)
    print(f"모델이 {filename}에 저장되었습니다.")
    
def load_model(agent, filename=None):
    """강화학습 모델 로드"""
    if filename is None:
        filename = f"dqn_model_{agent.mode}.pth"
    if os.path.exists(filename):
        agent.model.load_state_dict(torch.load(filename))
        agent.target_model.load_state_dict(agent.model.state_dict())
        print(f"모델이 {filename}에서 로드되었습니다.")
        return True
    return False 