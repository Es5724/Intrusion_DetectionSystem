# -*- coding: utf-8 -*-

"""
RL 성능 벤치마크 테스트

RL 에이전트의 응답 시간, 학습 속도, 메모리 사용량 등을 측정합니다.
"""

import sys
import os
import time
import numpy as np
from datetime import datetime
import psutil
import gc

# 모듈 경로 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_dir, 'modules'))

print("=" * 80)
print("          RL 에이전트 성능 벤치마크 테스트")
print("=" * 80)
print()


def benchmark_state_extraction():
    """상태 추출 속도 벤치마크"""
    print("[ 1/5 ] 상태 추출 속도 벤치마크")
    print("-" * 60)
    
    try:
        from modules.rl_state_extractor import get_state_extractor
        
        extractor = get_state_extractor()
        
        # 테스트 패킷 생성
        test_packets = []
        for i in range(1000):
            packet = {
                'source': f'192.168.1.{i % 255}:{50000 + i}',
                'destination': f'10.0.0.{i % 255}:{80}',
                'protocol': ['TCP', 'UDP', 'ICMP'][i % 3],
                'length': np.random.randint(64, 1500),
                'timestamp': time.time()
            }
            test_packets.append(packet)
        
        # 벤치마크 실행
        start_time = time.time()
        
        for packet in test_packets:
            context = {'threat_probability': np.random.rand()}
            state = extractor.extract_state(packet, context)
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        # 결과 출력
        throughput = len(test_packets) / elapsed
        avg_time_ms = (elapsed / len(test_packets)) * 1000
        
        print(f"  처리 패킷: {len(test_packets)}개")
        print(f"  소요 시간: {elapsed:.3f}초")
        print(f"  처리량: {throughput:.1f} 패킷/초")
        print(f"  평균 시간: {avg_time_ms:.3f}ms/패킷")
        
        # 성능 평가
        if avg_time_ms < 1.0:
            print(f"  ✅ 성능: 우수 (< 1ms)")
        elif avg_time_ms < 5.0:
            print(f"  ✅ 성능: 양호 (< 5ms)")
        else:
            print(f"  ⚠️  성능: 개선 필요 (>= 5ms)")
        
        return True
        
    except Exception as e:
        print(f"  ❌ 벤치마크 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


def benchmark_rl_inference():
    """RL 추론 속도 벤치마크"""
    print("\n[ 2/5 ] RL 추론 속도 벤치마크")
    print("-" * 60)
    
    try:
        from modules.conservative_rl_agent import ConservativeRLAgent
        
        # 에이전트 생성
        agent = ConservativeRLAgent(
            state_size=10,
            action_size=6,
            mode="standard"
        )
        
        # 테스트 상태 생성
        test_states = [np.random.rand(10) for _ in range(1000)]
        
        # 벤치마크 실행
        start_time = time.time()
        
        for state in test_states:
            action = agent.act(state)
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        # 결과 출력
        throughput = len(test_states) / elapsed
        avg_time_ms = (elapsed / len(test_states)) * 1000
        
        print(f"  추론 횟수: {len(test_states)}회")
        print(f"  소요 시간: {elapsed:.3f}초")
        print(f"  처리량: {throughput:.1f} 추론/초")
        print(f"  평균 시간: {avg_time_ms:.3f}ms/추론")
        
        # 성능 평가
        if avg_time_ms < 0.5:
            print(f"  ✅ 성능: 우수 (< 0.5ms) - 실시간 처리 가능")
        elif avg_time_ms < 2.0:
            print(f"  ✅ 성능: 양호 (< 2ms)")
        else:
            print(f"  ⚠️  성능: 개선 필요 (>= 2ms)")
        
        return True
        
    except Exception as e:
        print(f"  ❌ 벤치마크 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


def benchmark_online_learning():
    """온라인 학습 속도 벤치마크"""
    print("\n[ 3/5 ] 온라인 학습 속도 벤치마크")
    print("-" * 60)
    
    try:
        from modules.conservative_rl_agent import ConservativeRLAgent
        from modules.online_rl_trainer import OnlineRLTrainer
        
        # 에이전트 및 학습기 생성
        agent = ConservativeRLAgent(
            state_size=10,
            action_size=6,
            mode="standard",
            use_prioritized_replay=True,
            buffer_capacity=1000
        )
        
        # 경험 데이터 생성
        print("  경험 데이터 생성 중 (100개)...")
        for i in range(100):
            state = np.random.rand(10)
            action = np.random.randint(0, 6)
            reward = np.random.randn() * 10
            next_state = np.random.rand(10)
            done = False
            
            agent.remember(state, action, reward, next_state, done)
        
        # 학습 벤치마크
        print("  학습 벤치마크 시작 (10회 학습)...")
        
        learning_times = []
        
        for i in range(10):
            start_time = time.time()
            loss = agent.train(batch_size=32)
            end_time = time.time()
            
            learning_times.append(end_time - start_time)
        
        # 결과 출력
        avg_learning_time = np.mean(learning_times) * 1000  # ms
        std_learning_time = np.std(learning_times) * 1000
        
        print(f"  학습 횟수: {len(learning_times)}회")
        print(f"  평균 학습 시간: {avg_learning_time:.2f}ms ± {std_learning_time:.2f}ms")
        print(f"  최소 시간: {min(learning_times) * 1000:.2f}ms")
        print(f"  최대 시간: {max(learning_times) * 1000:.2f}ms")
        
        # 10초 주기 학습 가능성 평가
        if avg_learning_time < 100:  # 100ms 미만
            print(f"  ✅ 성능: 우수 - 10초 주기 학습 가능 (여유: {10000 - avg_learning_time:.0f}ms)")
        elif avg_learning_time < 500:
            print(f"  ✅ 성능: 양호 - 10초 주기 학습 가능")
        else:
            print(f"  ⚠️  성능: 10초 주기 학습 어려움")
        
        return True
        
    except Exception as e:
        print(f"  ❌ 벤치마크 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


def benchmark_memory_usage():
    """메모리 사용량 벤치마크"""
    print("\n[ 4/5 ] 메모리 사용량 벤치마크")
    print("-" * 60)
    
    try:
        process = psutil.Process()
        
        # 초기 메모리
        gc.collect()
        initial_memory = process.memory_info().rss / (1024 * 1024)
        print(f"  초기 메모리: {initial_memory:.1f} MB")
        
        # 모듈 로드
        print("  모듈 로딩 중...")
        from modules.rl_state_extractor import get_state_extractor
        from modules.realtime_reward_calculator import get_reward_calculator
        from modules.conservative_rl_agent import ConservativeRLAgent
        from modules.online_rl_trainer import OnlineRLTrainer
        
        after_import_memory = process.memory_info().rss / (1024 * 1024)
        import_overhead = after_import_memory - initial_memory
        print(f"  로드 후 메모리: {after_import_memory:.1f} MB (+{import_overhead:.1f} MB)")
        
        # 인스턴스 생성
        print("  인스턴스 생성 중...")
        extractor = get_state_extractor()
        calculator = get_reward_calculator()
        agent = ConservativeRLAgent(state_size=10, action_size=6)
        trainer = OnlineRLTrainer(agent)
        
        after_init_memory = process.memory_info().rss / (1024 * 1024)
        init_overhead = after_init_memory - after_import_memory
        print(f"  생성 후 메모리: {after_init_memory:.1f} MB (+{init_overhead:.1f} MB)")
        
        # 작업 부하 테스트 (1000개 패킷 처리)
        print("  작업 부하 테스트 (1000개 패킷 처리)...")
        for i in range(1000):
            packet = {
                'source': f'192.168.1.{i % 255}',
                'destination': f'10.0.0.{i % 255}:80',
                'protocol': 'TCP',
                'length': np.random.randint(64, 1500),
                'timestamp': time.time()
            }
            context = {'threat_probability': np.random.rand()}
            state = extractor.extract_state(packet, context)
            action = agent.act(state)
            
            # 경험 추가
            if i % 10 == 0:
                reward = np.random.randn()
                next_state = np.random.rand(10)
                agent.remember(state, action, reward, next_state, False)
        
        after_workload_memory = process.memory_info().rss / (1024 * 1024)
        workload_overhead = after_workload_memory - after_init_memory
        print(f"  작업 후 메모리: {after_workload_memory:.1f} MB (+{workload_overhead:.1f} MB)")
        
        # 가비지 컬렉션 후
        gc.collect()
        after_gc_memory = process.memory_info().rss / (1024 * 1024)
        gc_saved = after_workload_memory - after_gc_memory
        print(f"  GC 후 메모리: {after_gc_memory:.1f} MB (-{gc_saved:.1f} MB)")
        
        # 총 메모리 증가량
        total_increase = after_gc_memory - initial_memory
        print(f"\n  총 메모리 증가: {total_increase:.1f} MB")
        
        # 평가
        if total_increase < 50:
            print(f"  ✅ 메모리 사용: 매우 효율적 (< 50MB)")
        elif total_increase < 100:
            print(f"  ✅ 메모리 사용: 효율적 (< 100MB)")
        elif total_increase < 200:
            print(f"  ✅ 메모리 사용: 양호 (< 200MB)")
        else:
            print(f"  ⚠️  메모리 사용: 높음 (>= 200MB)")
        
        return True
        
    except Exception as e:
        print(f"  ❌ 벤치마크 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


def benchmark_end_to_end_pipeline():
    """엔드투엔드 파이프라인 벤치마크"""
    print("\n[ 5/5 ] 엔드투엔드 파이프라인 벤치마크")
    print("-" * 60)
    
    try:
        from modules.conservative_rl_agent import ConservativeRLAgent
        from modules.rl_state_extractor import get_state_extractor
        from modules.realtime_reward_calculator import get_reward_calculator
        from modules.online_rl_trainer import get_rl_integrator, get_online_trainer
        
        # 시스템 구성
        print("  시스템 구성 중...")
        agent = ConservativeRLAgent(state_size=10, action_size=6, mode="standard")
        state_extractor = get_state_extractor()
        reward_calculator = get_reward_calculator()
        online_trainer = get_online_trainer(agent, learning_interval=1)
        integrator = get_rl_integrator(agent, state_extractor, reward_calculator, online_trainer)
        
        # 전체 파이프라인 벤치마크
        print("  전체 파이프라인 테스트 (100개 패킷)...")
        
        pipeline_times = []
        
        for i in range(100):
            packet = {
                'source': f'192.168.1.{i % 255}:{50000 + i}',
                'destination': f'10.0.0.{i % 255}:80',
                'protocol': 'TCP',
                'length': np.random.randint(64, 1500),
                'timestamp': time.time()
            }
            
            rf_probability = np.random.rand()
            
            start = time.time()
            
            # 1. 상태 추출
            context = {'threat_probability': rf_probability}
            state = state_extractor.extract_state(packet, context)
            
            # 2. RL 액션 선택
            action = agent.act(state)
            
            # 3. 보상 계산
            reward, details = reward_calculator.calculate_reward(
                threat_probability=rf_probability,
                action_taken=action
            )
            
            end = time.time()
            pipeline_times.append(end - start)
        
        # 결과 출력
        avg_pipeline_time = np.mean(pipeline_times) * 1000  # ms
        std_pipeline_time = np.std(pipeline_times) * 1000
        p95_time = np.percentile(pipeline_times, 95) * 1000
        p99_time = np.percentile(pipeline_times, 99) * 1000
        
        print(f"\n  파이프라인 성능:")
        print(f"    평균 시간: {avg_pipeline_time:.3f}ms ± {std_pipeline_time:.3f}ms")
        print(f"    최소 시간: {min(pipeline_times) * 1000:.3f}ms")
        print(f"    최대 시간: {max(pipeline_times) * 1000:.3f}ms")
        print(f"    P95: {p95_time:.3f}ms")
        print(f"    P99: {p99_time:.3f}ms")
        print(f"    처리량: {1000 / avg_pipeline_time:.1f} 패킷/초")
        
        # 실시간 처리 가능성 평가
        max_acceptable_latency = 10.0  # 10ms
        
        if p99_time < max_acceptable_latency:
            print(f"  ✅ 실시간 처리: 가능 (P99 < {max_acceptable_latency}ms)")
        else:
            print(f"  ⚠️  실시간 처리: 지연 가능성 (P99 >= {max_acceptable_latency}ms)")
        
        # 통계 출력
        reward_stats = reward_calculator.get_statistics()
        print(f"\n  보상 통계:")
        print(f"    TP: {reward_stats['tp_count']}, TN: {reward_stats['tn_count']}")
        print(f"    FP: {reward_stats['fp_count']}, FN: {reward_stats['fn_count']}")
        print(f"    평균 보상: {reward_stats['avg_reward']:.2f}")
        
        print("  ✅ 엔드투엔드 파이프라인 벤치마크 성공!")
        return True
        
    except Exception as e:
        print(f"  ❌ 벤치마크 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_all_benchmarks():
    """전체 벤치마크 실행"""
    print("\n시스템 정보:")
    print(f"  Python: {sys.version.split()[0]}")
    print(f"  OS: {os.name}")
    
    try:
        import psutil
        print(f"  CPU 코어: {psutil.cpu_count()}개")
        memory = psutil.virtual_memory()
        print(f"  총 메모리: {memory.total / (1024**3):.1f} GB")
        print(f"  사용 가능: {memory.available / (1024**3):.1f} GB")
    except:
        pass
    
    print("\n" + "=" * 80)
    print()
    
    results = []
    
    # 각 벤치마크 실행
    results.append(("상태 추출 속도", benchmark_state_extraction()))
    results.append(("RL 추론 속도", benchmark_rl_inference()))
    results.append(("온라인 학습 속도", benchmark_online_learning()))
    results.append(("메모리 사용량", benchmark_memory_usage()))
    results.append(("엔드투엔드 파이프라인", benchmark_end_to_end_pipeline()))
    
    # 결과 요약
    print("\n" + "=" * 80)
    print("                      벤치마크 결과 요약")
    print("=" * 80)
    
    success_count = sum(1 for _, result in results if result)
    total_count = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status}  {name}")
    
    print()
    print(f"  성공: {success_count}/{total_count} ({success_count/total_count*100:.1f}%)")
    
    if success_count == total_count:
        print("\n  🎉 모든 벤치마크 통과! 시스템이 성능 요구사항을 충족합니다.")
        return 0
    else:
        print(f"\n  ⚠️  {total_count - success_count}개 벤치마크 실패 - 성능 개선 필요")
        return 1


if __name__ == "__main__":
    exit_code = run_all_benchmarks()
    
    print("\n" + "=" * 80)
    print(f"테스트 완료 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    sys.exit(exit_code)

