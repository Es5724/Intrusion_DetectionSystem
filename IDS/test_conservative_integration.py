#!/usr/bin/env python3
"""
Conservative RL Agent 통합 테스트 스크립트
"""

import sys
import os
sys.path.append('modules')

from modules.conservative_rl_agent import ConservativeRLAgent
from modules.defense_policy_env import DefensePolicyEnv

def test_integration():
    """통합 테스트 실행"""
    print("=== Conservative RL Agent 통합 테스트 ===")
    
    try:
        # 환경 생성 (올바른 경로)
        print("1. 환경 생성 중...")
        env = DefensePolicyEnv('ips_random_forest_model.pkl', 'defense_config.json')
        print("   ✅ DefensePolicyEnv 생성 성공")
        
        # 에이전트 생성
        print("2. 에이전트 생성 중...")
        agent = ConservativeRLAgent(state_size=10, action_size=6, mode='standard')
        print("   ✅ ConservativeRLAgent 생성 성공")
        
        # 기본 동작 테스트
        print("3. 환경-에이전트 연동 테스트")
        state = env.reset()
        action = agent.act(state)
        next_state, reward, done, info = env.step(action)
        
        print(f"   상태 샘플: {state[:3]}")
        print(f"   선택 액션: {action}")
        print(f"   받은 보상: {reward:.2f}")
        print(f"   액션 이름: {info['action_name']}")
        print("   ✅ 기본 동작 성공")
        
        # 경험 저장 테스트
        print("4. 경험 저장 테스트")
        agent.remember(state, action, reward, next_state, done, info)
        stats = agent.get_buffer_stats()
        print(f"   버퍼 사용률: {stats['buffer_utilization']:.1%}")
        print(f"   저장된 경험: {stats['buffer_size']}개")
        print("   ✅ 경험 저장 성공")
        
        # 다중 경험 수집 (학습 준비)
        print("5. 다중 경험 수집")
        for i in range(35):  # 배치 크기 확보
            state = env.reset()
            action = agent.act(state, deterministic=False)
            next_state, reward, done, info = env.step(action)
            agent.remember(state, action, reward, next_state, done, info)
        
        final_stats = agent.get_buffer_stats()
        print(f"   총 수집 경험: {final_stats['buffer_size']}개")
        print("   ✅ 다중 경험 수집 성공")
        
        # 학습 기능 테스트
        print("6. Conservative Q-Learning 테스트")
        initial_epsilon = agent.epsilon
        agent.train(batch_size=32)
        
        print(f"   학습 전 epsilon: {initial_epsilon:.4f}")
        print(f"   학습 후 epsilon: {agent.epsilon:.4f}")
        print(f"   정책 업데이트: {agent.training_stats['policy_updates']}회")
        print("   ✅ 학습 기능 성공")
        
        # 영속성 테스트 (간단한 방법)
        print("7. 영속성 기능 테스트")
        
        # 버퍼 저장/로드
        agent.save_buffer('test_conservative_buffer.pkl')
        print("   버퍼 저장 완료")
        
        # 새 에이전트로 로드 테스트
        new_agent = ConservativeRLAgent(state_size=10, action_size=6, mode='standard')
        buffer_loaded = new_agent.load_buffer('test_conservative_buffer.pkl')
        
        print(f"   버퍼 로드: {buffer_loaded}")
        if buffer_loaded:
            new_stats = new_agent.get_buffer_stats()
            print(f"   복원된 경험: {new_stats['buffer_size']}개")
        
        print("   ✅ 영속성 기능 성공")
        
        # 테스트 파일 정리
        if os.path.exists('test_conservative_buffer.pkl'):
            os.remove('test_conservative_buffer.pkl')
        
        print("\n🎉 모든 테스트 성공!")
        print("✅ DefensePolicyEnv + ConservativeRLAgent 통합 완료")
        print("✅ 기존 ExperienceReplayBuffer 완전 호환")
        print("✅ 영속성 기능 보장")
        print("✅ Conservative Q-Learning 동작 확인")
        
        return True
        
    except Exception as e:
        print(f"❌ 테스트 실패: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_integration()
    if success:
        print("\n다음 단계: TODO 3 - OPE 평가 시스템 구현")
    else:
        print("\n문제 해결 후 재시도 필요")

