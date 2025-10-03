# -*- coding: utf-8 -*-

"""
반응형 AI 시스템 통합 테스트

전체 시스템의 통합 및 각 모듈 간 연동을 검증합니다.
"""

import sys
import os
import time
import numpy as np
from datetime import datetime

# 모듈 경로 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_dir, 'modules'))

print("=" * 80)
print("     반응형 AI 에이전트 취약점 자동진단 시스템 통합 테스트")
print("=" * 80)
print()


def test_rl_state_extractor():
    """RL 상태 추출기 테스트"""
    print("[ 1/7 ] RL 상태 추출기 테스트")
    print("-" * 60)
    
    try:
        from modules.rl_state_extractor import get_state_extractor
        
        extractor = get_state_extractor()
        
        # 테스트 패킷 데이터
        test_packet = {
            'source': '192.168.1.100:54321',
            'destination': '10.0.0.50:80',
            'protocol': 'TCP',
            'length': 1460,
            'flags': 'SYN',
            'info': 'TCP connection',
            'timestamp': time.time()
        }
        
        # RF 위협 확률 시뮬레이션
        test_context = {
            'threat_probability': 0.85,
            'connection_frequency': 0.5,
            'historical_threat': 0.6
        }
        
        # 상태 추출
        state_vector = extractor.extract_state(test_packet, test_context)
        
        print(f"  입력 패킷: {test_packet['source']} → {test_packet['destination']}")
        print(f"  RF 위협 확률: {test_context['threat_probability']:.2f}")
        print(f"  출력 상태 벡터: {state_vector.shape}")
        print(f"  상태 값: {state_vector}")
        
        # 검증
        assert state_vector.shape == (10,), "상태 벡터 크기 오류"
        assert np.all((state_vector >= 0) & (state_vector <= 1)), "상태 값 범위 오류"
        
        print("  ✅ RL 상태 추출기 테스트 성공!")
        return True
        
    except Exception as e:
        print(f"  ❌ 테스트 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_reward_calculator():
    """실시간 보상 계산기 테스트"""
    print("\n[ 2/7 ] 실시간 보상 계산기 테스트")
    print("-" * 60)
    
    try:
        from modules.realtime_reward_calculator import get_reward_calculator
        
        calculator = get_reward_calculator()
        
        # 테스트 시나리오 1: True Positive (위협 정확 차단)
        reward1, details1 = calculator.calculate_reward(
            threat_probability=0.95,
            action_taken=2,  # 영구 차단
            actual_threat=True,
            system_load=0.3,
            response_time=0.5
        )
        
        print(f"  시나리오 1 - TP (위협 정확 차단):")
        print(f"    보상: {reward1:.2f}, 분류: {details1['classification']}")
        
        # 테스트 시나리오 2: False Positive (정상 오차단)
        reward2, details2 = calculator.calculate_reward(
            threat_probability=0.85,
            action_taken=2,  # 영구 차단
            actual_threat=False,  # 실제로는 정상
            system_load=0.5,
            response_time=0.3
        )
        
        print(f"  시나리오 2 - FP (정상 오차단):")
        print(f"    보상: {reward2:.2f}, 분류: {details2['classification']}")
        
        # 통계 확인
        stats = calculator.get_statistics()
        print(f"  통계: TP={stats['tp_count']}, FP={stats['fp_count']}, "
              f"평균보상={stats['avg_reward']:.2f}")
        
        # 검증
        assert reward1 > 0, "TP 보상이 양수여야 함"
        assert reward2 < 0, "FP 보상이 음수여야 함"
        
        print("  ✅ 실시간 보상 계산기 테스트 성공!")
        return True
        
    except Exception as e:
        print(f"  ❌ 테스트 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_online_rl_trainer():
    """온라인 RL 학습기 테스트"""
    print("\n[ 3/7 ] 온라인 RL 학습기 테스트")
    print("-" * 60)
    
    try:
        from modules.conservative_rl_agent import ConservativeRLAgent
        from modules.online_rl_trainer import OnlineRLTrainer
        
        # RL 에이전트 생성
        agent = ConservativeRLAgent(
            state_size=10,
            action_size=6,
            mode="standard",
            use_prioritized_replay=True,
            buffer_capacity=100
        )
        
        # 온라인 학습기 생성
        trainer = OnlineRLTrainer(
            agent,
            learning_interval=1,  # 테스트용 1초
            min_experiences=5,
            batch_size=5
        )
        
        # 경험 추가
        print("  경험 추가 중...")
        for i in range(10):
            state = np.random.rand(10)
            action = np.random.randint(0, 6)
            reward = np.random.randn()
            next_state = np.random.rand(10)
            done = False
            
            trainer.add_experience(state, action, reward, next_state, done)
        
        print(f"  경험 추가 완료: 10개")
        
        # 학습 시작 (짧은 시간만)
        print("  온라인 학습 시작 (3초 실행)...")
        trainer.start()
        time.sleep(3)
        trainer.stop()
        
        # 통계 확인
        stats = trainer.get_statistics()
        print(f"  학습 사이클: {stats['total_learning_cycles']}회")
        print(f"  평균 Loss: {stats['avg_loss']:.4f}")
        print(f"  학습된 경험: {stats['total_experiences_learned']}개")
        
        print("  ✅ 온라인 RL 학습기 테스트 성공!")
        return True
        
    except Exception as e:
        print(f"  ❌ 테스트 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_vulnerability_auto_scanner():
    """자동 취약점 스캐너 테스트"""
    print("\n[ 4/7 ] 자동 취약점 스캐너 테스트")
    print("-" * 60)
    
    try:
        from modules.vulnerability_auto_scanner import VulnerabilityAutoScanner
        
        # 테스트용 로컬 네트워크만 스캔
        scanner = VulnerabilityAutoScanner(
            network_range="127.0.0.1/32",  # 로컬호스트만
            full_scan_interval=3600,
            quick_scan_interval=600,
            output_dir="test_scan_results"
        )
        
        print(f"  네트워크 범위: {scanner.network_range}")
        print(f"  전체 스캔 주기: {scanner.full_scan_interval}초")
        print(f"  빠른 스캔 주기: {scanner.quick_scan_interval}초")
        
        # 통계 확인
        stats = scanner.get_statistics()
        print(f"  총 스캔: {stats['total_scans']}회")
        print(f"  의심 호스트: {stats['suspicious_hosts']}개")
        
        # 정리
        import shutil
        if os.path.exists("test_scan_results"):
            shutil.rmtree("test_scan_results")
        
        print("  ✅ 자동 취약점 스캐너 테스트 성공!")
        return True
        
    except Exception as e:
        print(f"  ❌ 테스트 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_vulnerability_priority_analyzer():
    """AI 기반 취약점 우선순위 분석기 테스트"""
    print("\n[ 5/7 ] AI 우선순위 분석기 테스트")
    print("-" * 60)
    
    try:
        from modules.vulnerability_priority_analyzer import get_priority_analyzer
        
        analyzer = get_priority_analyzer()
        
        # 테스트 취약점 데이터
        test_vulnerabilities = [
            {
                'host_ip': '192.168.1.100',
                'port': 3389,  # RDP (BlueKeep)
                'service': 'RDP',
                'risk_level': 'high'
            },
            {
                'host_ip': '192.168.1.101',
                'port': 445,  # SMB (EternalBlue)
                'service': 'SMB',
                'risk_level': 'critical'
            },
            {
                'host_ip': '192.168.1.102',
                'port': 80,  # HTTP
                'service': 'HTTP',
                'risk_level': 'low'
            }
        ]
        
        # 일괄 분석
        print(f"  취약점 분석 중: {len(test_vulnerabilities)}개")
        
        rf_probabilities = [0.85, 0.92, 0.35]
        results = analyzer.analyze_multiple_vulnerabilities(
            test_vulnerabilities,
            rf_probabilities
        )
        
        print(f"\n  우선순위 분석 결과:")
        for i, result in enumerate(results, 1):
            print(f"    {i}. {result['priority_level']} - {result['host_ip']}:{result['port']} "
                  f"(점수: {result['priority_score']:.1f})")
            print(f"       {result['action_urgency']}")
        
        # 보고서 생성
        report = analyzer.generate_priority_report(results)
        print(f"\n  보고서 생성됨 ({len(report)}자)")
        
        print("  ✅ AI 우선순위 분석기 테스트 성공!")
        return True
        
    except Exception as e:
        print(f"  ❌ 테스트 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_rl_integrator():
    """실시간 RL 통합기 테스트"""
    print("\n[ 6/7 ] 실시간 RL 통합기 테스트")
    print("-" * 60)
    
    try:
        from modules.conservative_rl_agent import ConservativeRLAgent
        from modules.rl_state_extractor import get_state_extractor
        from modules.realtime_reward_calculator import get_reward_calculator
        from modules.online_rl_trainer import get_online_trainer, get_rl_integrator
        
        # 컴포넌트 초기화
        agent = ConservativeRLAgent(state_size=10, action_size=6, mode="standard")
        state_extractor = get_state_extractor()
        reward_calculator = get_reward_calculator()
        online_trainer = get_online_trainer(agent, learning_interval=1)
        
        # 통합기 생성
        integrator = get_rl_integrator(
            agent, state_extractor, reward_calculator, online_trainer
        )
        
        print("  통합기 생성 완료")
        
        # 테스트 패킷 처리
        test_packet = {
            'source': '10.0.0.50:12345',
            'destination': '192.168.1.1:80',
            'protocol': 'TCP',
            'length': 1460,
            'timestamp': time.time()
        }
        
        rf_probability = 0.75
        action, details = integrator.process_packet_with_rl(test_packet, rf_probability)
        
        print(f"  패킷 처리 결과:")
        print(f"    RF 확률: {rf_probability}")
        print(f"    RL 액션: {action}")
        print(f"    상태 벡터: {details.get('state', 'N/A')}")
        
        # 통계 확인
        stats = integrator.get_statistics()
        print(f"  대기 중인 결정: {stats['pending_decisions']}개")
        
        print("  ✅ 실시간 RL 통합기 테스트 성공!")
        return True
        
    except Exception as e:
        print(f"  ❌ 테스트 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_module_imports():
    """모듈 임포트 테스트"""
    print("\n[ 7/7 ] 모듈 임포트 테스트")
    print("-" * 60)
    
    modules_to_test = [
        ('rl_state_extractor', 'RLStateExtractor'),
        ('realtime_reward_calculator', 'RealtimeRewardCalculator'),
        ('online_rl_trainer', 'OnlineRLTrainer'),
        ('rl_defense_wrapper', 'RLDefenseWrapper'),
        ('vulnerability_auto_scanner', 'VulnerabilityAutoScanner'),
        ('vulnerability_priority_analyzer', 'VulnerabilityPriorityAnalyzer'),
    ]
    
    success_count = 0
    total_count = len(modules_to_test)
    
    for module_name, class_name in modules_to_test:
        try:
            module = __import__(f'modules.{module_name}', fromlist=[class_name])
            cls = getattr(module, class_name)
            print(f"  ✓ {module_name}.{class_name}")
            success_count += 1
        except Exception as e:
            print(f"  ✗ {module_name}.{class_name} - {e}")
    
    print(f"\n  임포트 성공: {success_count}/{total_count}")
    
    if success_count == total_count:
        print("  ✅ 모듈 임포트 테스트 성공!")
        return True
    else:
        print(f"  ⚠️  {total_count - success_count}개 모듈 임포트 실패")
        return False


def run_all_tests():
    """전체 테스트 실행"""
    print("\n" + "=" * 80)
    print("                         테스트 시작")
    print("=" * 80)
    print()
    
    test_results = []
    
    # 각 테스트 실행
    test_results.append(("RL 상태 추출기", test_rl_state_extractor()))
    test_results.append(("실시간 보상 계산기", test_reward_calculator()))
    test_results.append(("온라인 RL 학습기", test_online_rl_trainer()))
    test_results.append(("자동 취약점 스캐너", test_vulnerability_auto_scanner()))
    test_results.append(("AI 우선순위 분석기", test_vulnerability_priority_analyzer()))
    test_results.append(("실시간 RL 통합기", test_rl_integrator()))
    test_results.append(("모듈 임포트", test_module_imports()))
    
    # 결과 요약
    print("\n" + "=" * 80)
    print("                         테스트 결과 요약")
    print("=" * 80)
    
    success_count = sum(1 for _, result in test_results if result)
    total_count = len(test_results)
    
    for name, result in test_results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status}  {name}")
    
    print()
    print(f"  성공: {success_count}/{total_count} ({success_count/total_count*100:.1f}%)")
    
    if success_count == total_count:
        print("\n  🎉 모든 테스트 통과! 시스템이 정상적으로 작동합니다.")
        return 0
    else:
        print(f"\n  ⚠️  {total_count - success_count}개 테스트 실패")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)

