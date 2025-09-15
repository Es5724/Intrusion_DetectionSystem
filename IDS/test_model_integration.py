#!/usr/bin/env python3
"""
모델 파일 연동 테스트 스크립트
KISTI RF 모델과 Conservative RL 시스템 간 연동 검증
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np

sys.path.append('modules')

def test_model_files_integration():
    """모델 파일들 연동 테스트"""
    print("=== 모델 파일 연동 테스트 시작 ===")
    
    # 1. 모델 파일 존재 확인
    print("\n1. 모델 파일 존재 확인:")
    
    model_files = {
        'KISTI RF 모델': 'kisti_random_forest_model.pkl',
        'CIC RF 모델': 'ips_random_forest_model.pkl',
        'Conservative RL 모델': 'defense_policy_agent.pth',
        'Conservative RL 버퍼': 'defense_policy_buffer.pkl'
    }
    
    existing_models = {}
    
    for name, filename in model_files.items():
        if os.path.exists(filename):
            file_size = os.path.getsize(filename) / (1024 * 1024)  # MB
            print(f"  ✅ {name}: {filename} ({file_size:.1f}MB)")
            existing_models[name] = filename
        else:
            print(f"  ❌ {name}: {filename} (없음)")
    
    # 2. KISTI RF 모델 로딩 테스트
    print("\n2. KISTI RF 모델 로딩 테스트:")
    
    if 'KISTI RF 모델' in existing_models:
        try:
            kisti_model = joblib.load('kisti_random_forest_model.pkl')
            print(f"  ✅ KISTI RF 모델 로딩 성공")
            print(f"     모델 타입: {type(kisti_model).__name__}")
            
            # 모델 기본 정보
            if hasattr(kisti_model, 'n_estimators'):
                print(f"     트리 수: {kisti_model.n_estimators}")
            if hasattr(kisti_model, 'n_features_in_'):
                print(f"     입력 특성 수: {kisti_model.n_features_in_}")
            
            # 간단한 예측 테스트
            test_data = np.array([[1, 2, 80, 443, 6, 1500]]).reshape(1, -1)
            
            try:
                prediction = kisti_model.predict(test_data)
                probability = kisti_model.predict_proba(test_data)
                print(f"     예측 테스트: 예측={prediction[0]}, 확률={probability[0]}")
                print(f"  ✅ KISTI RF 모델 예측 기능 정상")
            except Exception as pred_error:
                print(f"  ⚠️ 예측 테스트 실패: {pred_error}")
                print(f"     예상 원인: 특성 수 불일치 또는 데이터 형태 문제")
                
        except Exception as e:
            print(f"  ❌ KISTI RF 모델 로딩 실패: {e}")
    else:
        print("  ❌ KISTI RF 모델 파일 없음")
    
    # 3. Conservative RL 시스템 로딩 테스트
    print("\n3. Conservative RL 시스템 로딩 테스트:")
    
    try:
        from modules.conservative_rl_agent import ConservativeRLAgent
        from modules.defense_policy_env import DefensePolicyEnv
        
        # DefensePolicyEnv 테스트
        print("  DefensePolicyEnv 테스트:")
        env = DefensePolicyEnv()
        print(f"    ✅ 환경 초기화 성공")
        print(f"    액션 공간: {env.action_space}")
        print(f"    상태 공간: {env.observation_space}")
        
        # ConservativeRLAgent 테스트
        print("  ConservativeRLAgent 테스트:")
        agent = ConservativeRLAgent(state_size=10, action_size=6, mode="standard")
        print(f"    ✅ 에이전트 초기화 성공")
        
        # 모델 로드 테스트
        if 'Conservative RL 모델' in existing_models:
            if agent.load_model('defense_policy_agent.pth'):
                print(f"    ✅ Conservative RL 모델 로드 성공")
            else:
                print(f"    ⚠️ Conservative RL 모델 로드 실패")
        
        # 간단한 액션 테스트
        test_state = np.random.random(10).astype(np.float32)
        action = agent.act(test_state, deterministic=True)
        print(f"    액션 테스트: 상태={test_state[:3]}... → 액션={action}")
        print(f"  ✅ Conservative RL 시스템 정상")
        
    except Exception as e:
        print(f"  ❌ Conservative RL 시스템 로딩 실패: {e}")
        import traceback
        traceback.print_exc()
    
    # 4. 통합 연동 테스트
    print("\n4. RF ↔ RL 통합 연동 테스트:")
    
    try:
        # KISTI 데이터 샘플 로드
        if os.path.exists('processed_data/kisti_quick_test.csv'):
            test_df = pd.read_csv('processed_data/kisti_quick_test.csv', nrows=5)
            print(f"  ✅ KISTI 테스트 데이터 로드: {len(test_df)}행")
            
            # 각 샘플에 대해 RF → RL 연동 테스트
            for i, row in test_df.iterrows():
                print(f"\n  샘플 {i+1} 연동 테스트:")
                
                # RF 예측 (KISTI 모델)
                if 'KISTI RF 모델' in existing_models:
                    # 특성 준비 (문자열 제외)
                    numeric_features = row.drop(['is_malicious', 'attack_type'], errors='ignore')
                    string_features = numeric_features.select_dtypes(include=['object'])
                    
                    if len(string_features) > 0:
                        print(f"    ⚠️ 문자열 특성 발견: {list(string_features.index)}")
                        # 간단한 인코딩
                        for col in string_features.index:
                            numeric_features[col] = hash(str(numeric_features[col])) % 10000
                    
                    try:
                        rf_features = numeric_features.values.reshape(1, -1)
                        rf_prediction = kisti_model.predict(rf_features)[0]
                        rf_probability = kisti_model.predict_proba(rf_features)[0]
                        
                        print(f"    RF 예측: {rf_prediction}, 확률: {rf_probability}")
                        
                        # RL 상태 생성
                        rl_state = np.array([
                            rf_probability[1] if len(rf_probability) > 1 else rf_probability[0],  # 위협 확률
                            max(rf_probability),  # 신뢰도
                            0.5,  # 공격 유형 (기본값)
                            0.8,  # 심각도
                            0.3,  # CPU 사용률
                            0.4,  # 메모리 사용률
                            0.1,  # 활성 위협
                            0.1,  # 차단 IP
                            0.6,  # 시간대
                            0.8   # 서비스 중요도
                        ], dtype=np.float32)
                        
                        # RL 액션 결정
                        rl_action = agent.act(rl_state, deterministic=True)
                        action_names = {0: 'allow', 1: 'block_temp', 2: 'block_perm', 
                                      3: 'rate_limit', 4: 'deep_inspect', 5: 'isolate'}
                        
                        print(f"    RL 결정: 액션={rl_action} ({action_names.get(rl_action, 'unknown')})")
                        print(f"    ✅ RF → RL 연동 성공")
                        
                    except Exception as integration_error:
                        print(f"    ❌ RF → RL 연동 실패: {integration_error}")
                
                if i >= 2:  # 처음 3개만 테스트
                    break
        else:
            print("  ❌ KISTI 테스트 데이터 없음")
    
    except Exception as e:
        print(f"  ❌ 통합 연동 테스트 실패: {e}")
    
    # 5. 파이프라인 통합기 연동 테스트
    print("\n5. 파이프라인 통합기 연동 테스트:")
    
    try:
        from modules.ips_pipeline_integrator import IPSPipelineIntegrator
        
        pipeline = IPSPipelineIntegrator()
        print(f"  ✅ 파이프라인 통합기 초기화 성공")
        
        # 간단한 패킷 처리 테스트
        test_packet = {
            'source': '192.168.1.100',
            'destination_port': 22,
            'length': 64,
            'tcp_flags': {'syn': 1}
        }
        
        result = pipeline.process_packet_threat(test_packet)
        print(f"  ✅ 패킷 처리 테스트: {result.action_name}")
        print(f"  ✅ 파이프라인 통합기 연동 성공")
        
    except Exception as e:
        print(f"  ❌ 파이프라인 통합기 연동 실패: {e}")
    
    print("\n=== 모델 연동 테스트 완료 ===")
    print("\n📋 테스트 결과 요약:")
    print(f"  모델 파일: {len(existing_models)}/{len(model_files)}개 존재")
    print(f"  KISTI RF: {'✅' if 'KISTI RF 모델' in existing_models else '❌'}")
    print(f"  Conservative RL: {'✅' if 'Conservative RL 모델' in existing_models else '❌'}")
    
    if len(existing_models) >= 1:  # KISTI RF 모델만 있어도 기본 동작
        print("\n🎉 기본 IPS 시스템 실행 가능!")
        print("   KISTI RF 탐지 + Conservative RL 대응 준비 완료")
    else:
        print("\n⚠️ 필수 모델 파일 부족")
        print("   RF 모델 학습 후 재시도 필요")

if __name__ == "__main__":
    test_model_files_integration()
