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
        try:
            packet = sniff(count=1, timeout=1)[0]
            state = self._extract_packet_features(packet)
        except:
            # 오류 시 빈 상태 반환 (모드에 맞게)
            if self.mode == "performance":
                state = np.zeros(12, dtype=np.float32)
            else:
                state = np.zeros(7, dtype=np.float32)
        
        # 보상 계산
        reward = self._calculate_reward(action, packet if 'packet' in locals() else None)
        self.total_reward += reward
        
        # 종료 조건 확인
        done = self.current_step >= self.max_steps
        
        return state, reward, done, {}
    
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
    def __init__(self, state_size, action_size, mode="lightweight"):
        self.state_size = state_size
        self.action_size = action_size
        self.mode = mode
        self.memory = deque(maxlen=2000)
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
    
    def remember(self, state, action, reward, next_state, done):
        self.memory.append((state, action, reward, next_state, done))
    
    def act(self, state):
        if np.random.rand() <= self.epsilon:
            return random.randrange(self.action_size)
        state = torch.FloatTensor(state).unsqueeze(0)
        act_values = self.model(state)
        return torch.argmax(act_values[0]).item()
    
    def replay(self, batch_size):
        if len(self.memory) < batch_size:
            return
        
        minibatch = random.sample(self.memory, batch_size)
        for state, action, reward, next_state, done in minibatch:
            target = reward
            if not done:
                next_state = torch.FloatTensor(next_state).unsqueeze(0)
                target = reward + self.gamma * torch.max(self.target_model(next_state)[0]).item()
            
            state = torch.FloatTensor(state).unsqueeze(0)
            target_f = self.model(state)
            target_f[0][action] = target
            
            self.model.zero_grad()
            loss = nn.MSELoss()(self.model(state), target_f)
            loss.backward()
            optimizer = optim.Adam(self.model.parameters(), lr=self.learning_rate)
            optimizer.step()
        
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay

def train_rl_agent(env, agent, episodes=500, batch_size=32):
    rewards_history = []
    for episode in range(episodes):
        state = env.reset()
        total_reward = 0
        
        for step in range(env.max_steps):
            action = agent.act(state)
            next_state, reward, done, _ = env.step(action)
            
            agent.remember(state, action, reward, next_state, done)
            state = next_state
            total_reward += reward
            
            if done:
                break
                
            agent.replay(batch_size)
        
        # 에피소드마다 타겟 모델 업데이트
        if episode % 10 == 0:
            agent.update_target_model()
            
        # 에피소드 보상 기록
        rewards_history.append(total_reward)
        
        # 학습 진행 상황 출력
        if episode % 10 == 0:
            avg_reward = np.mean(rewards_history[-10:])
            print(f"에피소드: {episode}, 총 보상: {total_reward:.2f}, 평균 보상: {avg_reward:.2f}, 탐험률: {agent.epsilon:.2f}")
            
    return rewards_history

def plot_training_results(rewards):
    plt.figure(figsize=(12, 6))
    
    # 이동 평균 계산
    window_size = 10
    moving_avg = np.convolve(rewards, np.ones(window_size)/window_size, mode='valid')
    
    # 원본 보상과 이동 평균 플롯
    plt.plot(rewards, alpha=0.3, label='원본 보상')
    plt.plot(moving_avg, label=f'{window_size}회 이동 평균')
    
    plt.title('강화학습 훈련 결과')
    plt.xlabel('에피소드')
    plt.ylabel('총 보상')
    plt.legend()
    plt.grid(True)
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