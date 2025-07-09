"""
Experience Replay Buffer 테스트 스크립트

이 스크립트는 새로 구현한 Experience Replay Buffer의 기능을 테스트합니다.
"""

import sys
import os
import numpy as np

# 모듈 경로 추가
sys.path.append(os.path.join(os.path.dirname(__file__), 'modules'))

from experience_replay_buffer import ExperienceReplayBuffer, PrioritizedExperienceReplayBuffer, IDSExperienceReplayBuffer

def test_basic_buffer():
    """기본 Experience Replay Buffer 테스트"""
    print("=== 기본 Experience Replay Buffer 테스트 ===")
    
    # 버퍼 생성
    buffer = ExperienceReplayBuffer(capacity=100, state_size=7, mode="lightweight")
    
    # 경험 추가
    for i in range(50):
        state = np.random.rand(7).astype(np.float32)
        action = np.random.randint(0, 3)
        reward = np.random.randn()
        next_state = np.random.rand(7).astype(np.float32)
        done = i % 10 == 0
        
        metadata = {
            'is_malicious': np.random.rand() > 0.8,
            'attack_type': np.random.choice(['benign', 'dos', 'probe', 'r2l', 'u2r'])
        }
        
        buffer.push(state, action, reward, next_state, done, metadata)
    
    # 통계 출력
    stats = buffer.get_stats()
    print(f"버퍼 크기: {len(buffer)}")
    print(f"총 경험: {stats['total_experiences']}")
    print(f"악성 경험: {stats['malicious_experiences']}")
    print(f"정상 경험: {stats['benign_experiences']}")
    print(f"평균 보상: {stats['avg_reward']:.3f}")
    
    # 샘플링 테스트
    if len(buffer) >= 32:
        states, actions, rewards, next_states, dones = buffer.sample(32)
        print(f"\n샘플링 성공: {states.shape}")
    
    print("\n기본 버퍼 테스트 완료!\n")

def test_prioritized_buffer():
    """우선순위 기반 Experience Replay Buffer 테스트"""
    print("=== 우선순위 기반 Experience Replay Buffer 테스트 ===")
    
    # 버퍼 생성
    buffer = PrioritizedExperienceReplayBuffer(
        capacity=100, 
        state_size=12, 
        mode="performance",
        alpha=0.6,
        beta=0.4
    )
    
    # 다양한 우선순위의 경험 추가
    for i in range(50):
        state = np.random.rand(12).astype(np.float32)
        action = np.random.randint(0, 3)
        
        # 악성 패킷은 높은 보상/페널티
        is_malicious = np.random.rand() > 0.7
        if is_malicious:
            reward = np.random.choice([-2.0, -1.5, 2.0, 2.5])  # 큰 보상/페널티
        else:
            reward = np.random.choice([-0.5, 0.5, 1.0])  # 작은 보상
        
        next_state = np.random.rand(12).astype(np.float32)
        done = i % 10 == 0
        
        metadata = {
            'is_malicious': is_malicious,
            'suricata_alert': is_malicious and np.random.rand() > 0.5,
            'threat_level': np.random.rand() if is_malicious else 0.0,
            'attack_type': np.random.choice(['benign', 'dos', 'probe']) if is_malicious else 'benign'
        }
        
        buffer.push(state, action, reward, next_state, done, metadata)
    
    # 통계 출력
    stats = buffer.get_stats()
    print(f"버퍼 크기: {len(buffer)}")
    print(f"악성 경험: {stats['malicious_experiences']}")
    print(f"최대 우선순위: {buffer.max_priority:.3f}")
    
    # 우선순위 기반 샘플링
    if len(buffer) >= 16:
        states, actions, rewards, next_states, dones, weights, indices = buffer.sample(16)
        print(f"\n우선순위 샘플링 성공:")
        print(f"  - 상태 shape: {states.shape}")
        print(f"  - 가중치 범위: [{weights.min():.3f}, {weights.max():.3f}]")
        
        # TD 오차로 우선순위 업데이트
        td_errors = np.random.rand(16) * 2.0  # 임의의 TD 오차
        buffer.update_priorities(indices.tolist(), td_errors.tolist())
        print(f"  - 우선순위 업데이트 완료")
    
    print("\n우선순위 버퍼 테스트 완료!\n")

def test_ids_buffer():
    """IDS 특화 Experience Replay Buffer 테스트"""
    print("=== IDS 특화 Experience Replay Buffer 테스트 ===")
    
    # 버퍼 생성
    buffer = IDSExperienceReplayBuffer(
        capacity=100,
        state_size=7,
        mode="lightweight",
        alpha=0.6,
        beta=0.4,
        malicious_preserve_ratio=0.3
    )
    
    # 다양한 공격 유형의 경험 추가
    attack_types = ['benign', 'dos', 'probe', 'r2l', 'u2r', 'botnet', 'portscan']
    
    for i in range(150):  # 버퍼 용량보다 많이 추가
        state = np.random.rand(7).astype(np.float32)
        action = np.random.randint(0, 3)
        
        # 20% 확률로 악성
        is_malicious = np.random.rand() > 0.8
        attack_type = np.random.choice(attack_types[1:]) if is_malicious else 'benign'
        
        reward = -2.0 if is_malicious else 1.0
        next_state = np.random.rand(7).astype(np.float32)
        done = i % 20 == 0
        
        metadata = {
            'is_malicious': is_malicious,
            'attack_type': attack_type,
            'threat_level': np.random.rand() if is_malicious else 0.0,
            'src_ip': f"192.168.1.{np.random.randint(1, 255)}",
            'dst_ip': f"10.0.0.{np.random.randint(1, 255)}"
        }
        
        buffer.push(state, action, reward, next_state, done, metadata)
    
    # 통계 출력
    stats = buffer.get_stats()
    print(f"버퍼 크기: {len(buffer)}")
    print(f"악성 경험: {stats['malicious_experiences']}")
    print(f"악성 경험 비율: {stats['malicious_experiences'] / len(buffer) * 100:.1f}%")
    
    # 공격 유형별 통계
    attack_stats = buffer.get_attack_statistics()
    if attack_stats:
        print(f"\n공격 통계:")
        print(f"  - 총 공격: {attack_stats['total_attacks']}")
        print(f"  - 공격 유형 분포:")
        for attack_type, ratio in attack_stats['attack_distribution'].items():
            print(f"    * {attack_type}: {ratio:.1%}")
    
    # 특정 공격 유형 샘플링
    if len(buffer) >= 8:
        print(f"\n특정 공격 유형(dos) 샘플링 테스트:")
        states, actions, rewards, next_states, dones = buffer.sample_by_attack_type(8, 'dos')
        print(f"  - 샘플링 성공: {states.shape}")
    
    # 시계열 컨텍스트 테스트
    seq_context = buffer.get_sequence_context()
    if seq_context is not None:
        print(f"\n시계열 컨텍스트: {seq_context.shape}")
    
    print("\nIDS 버퍼 테스트 완료!\n")

def test_mode_compatibility():
    """모드 호환성 테스트"""
    print("=== 모드 호환성 테스트 ===")
    
    # Lightweight 모드
    buffer_light = IDSExperienceReplayBuffer(
        capacity=50,
        state_size=7,
        mode="lightweight"
    )
    
    # Performance 모드
    buffer_perf = IDSExperienceReplayBuffer(
        capacity=50,
        state_size=12,
        mode="performance"
    )
    
    # 각 모드에 맞는 데이터 추가
    for i in range(20):
        # Lightweight
        state_light = np.random.rand(7).astype(np.float32)
        buffer_light.push(state_light, 0, 1.0, state_light, False)
        
        # Performance
        state_perf = np.random.rand(12).astype(np.float32)
        buffer_perf.push(state_perf, 1, -1.0, state_perf, False)
    
    print(f"Lightweight 버퍼 크기: {len(buffer_light)}")
    print(f"Performance 버퍼 크기: {len(buffer_perf)}")
    print("\n모드 호환성 테스트 완료!\n")

if __name__ == "__main__":
    print("Experience Replay Buffer 테스트 시작\n")
    
    # 각 테스트 실행
    test_basic_buffer()
    test_prioritized_buffer()
    test_ids_buffer()
    test_mode_compatibility()
    
    print("모든 테스트 완료!") 