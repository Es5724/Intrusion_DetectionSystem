# -*- coding: utf-8 -*-

"""
시스템 관리 모듈 테스트 (SystemState & ThreadManager)

P0 개선 작업의 검증을 위한 통합 테스트 스크립트입니다.
"""

import time
import threading
from modules.system_state import get_system_state, SystemState, ThreatStatistics
from modules.thread_manager import get_thread_manager, ThreadManager

def test_system_state():
    """SystemState 테스트"""
    print("=" * 60)
    print("📊 SystemState 테스트 시작")
    print("=" * 60)
    
    # 싱글톤 테스트
    state1 = get_system_state()
    state2 = get_system_state()
    assert state1 is state2, "싱글톤 패턴 실패"
    print("✅ 싱글톤 패턴: OK")
    
    # 통계 초기화
    state1.reset_all()
    
    # 위협 통계 테스트
    state1.increment_threat('high')
    state1.increment_threat('high')
    state1.increment_threat('medium')
    state1.increment_threat('low')
    state1.increment_threat('safe')
    
    threat_stats = state1.get_threat_stats()
    assert threat_stats['high'] == 2, f"high 카운트 오류: {threat_stats['high']}"
    assert threat_stats['medium'] == 1, f"medium 카운트 오류: {threat_stats['medium']}"
    assert threat_stats['low'] == 1, f"low 카운트 오류: {threat_stats['low']}"
    assert threat_stats['safe'] == 1, f"safe 카운트 오류: {threat_stats['safe']}"
    print(f"✅ 위협 통계: {threat_stats}")
    
    # 방어 통계 테스트
    state1.increment_defense('blocked')
    state1.increment_defense('blocked')
    state1.increment_defense('monitored')
    state1.increment_defense('alerts')
    
    defense_stats = state1.get_defense_stats()
    assert defense_stats['blocked'] == 2, f"blocked 카운트 오류: {defense_stats['blocked']}"
    assert defense_stats['monitored'] == 1, f"monitored 카운트 오류: {defense_stats['monitored']}"
    assert defense_stats['alerts'] == 1, f"alerts 카운트 오류: {defense_stats['alerts']}"
    print(f"✅ 방어 통계: {defense_stats}")
    
    # ML 통계 테스트
    state1.update_ml_training(0.95)
    ml_stats = state1.get_ml_stats()
    assert ml_stats['total_trained'] == 1, f"학습 카운트 오류: {ml_stats['total_trained']}"
    assert ml_stats['model_accuracy'] == 0.95, f"정확도 오류: {ml_stats['model_accuracy']}"
    print(f"✅ ML 통계: {ml_stats}")
    
    # 가동 시간 테스트
    uptime = state1.get_uptime()
    uptime_str = state1.get_uptime_str()
    assert uptime > 0, "가동 시간 오류"
    print(f"✅ 가동 시간: {uptime_str} ({uptime:.2f}초)")
    
    # 컴포넌트 등록 테스트
    state1.register_component('test_model', {'type': 'RandomForest'})
    state1.register_component('test_defense', {'type': 'DefenseManager'})
    components = state1.list_components()
    assert 'test_model' in components, "컴포넌트 등록 실패"
    assert 'test_defense' in components, "컴포넌트 등록 실패"
    print(f"✅ 컴포넌트 등록: {components}")
    
    # 설정 관리 테스트
    state1.set_config('mode', 'lightweight')
    state1.set_config('max_packets', 1000)
    mode = state1.get_config('mode')
    max_packets = state1.get_config('max_packets')
    assert mode == 'lightweight', f"설정 조회 오류: {mode}"
    assert max_packets == 1000, f"설정 조회 오류: {max_packets}"
    print(f"✅ 설정 관리: mode={mode}, max_packets={max_packets}")
    
    # 전체 요약 테스트
    summary = state1.get_summary()
    assert 'threat_stats' in summary, "요약 정보 누락"
    assert 'defense_stats' in summary, "요약 정보 누락"
    assert 'ml_stats' in summary, "요약 정보 누락"
    print(f"✅ 시스템 요약: {len(summary)} 항목")
    
    # 중지 요청 테스트
    state1.request_stop()
    assert state1.is_stop_requested(), "중지 요청 실패"
    state1.reset_stop_request()
    assert not state1.is_stop_requested(), "중지 요청 리셋 실패"
    print("✅ 중지 요청 메커니즘: OK")
    
    print("\n✅ SystemState 모든 테스트 통과!\n")


def test_thread_manager():
    """ThreadManager 테스트"""
    print("=" * 60)
    print("🧵 ThreadManager 테스트 시작")
    print("=" * 60)
    
    # 테스트 워커 함수
    def test_worker(stop_event, worker_id, results_list):
        """테스트용 워커 함수"""
        count = 0
        while not stop_event.is_set():
            count += 1
            time.sleep(0.1)
        results_list.append({'worker_id': worker_id, 'count': count})
    
    # ThreadManager 생성
    manager = ThreadManager()  # 새로운 인스턴스 (테스트용)
    
    # 스레드 등록
    results = []
    assert manager.register_thread("test_worker1", test_worker, args=(1, results)), "스레드 등록 실패"
    assert manager.register_thread("test_worker2", test_worker, args=(2, results)), "스레드 등록 실패"
    assert manager.register_thread("test_worker3", test_worker, args=(3, results)), "스레드 등록 실패"
    print("✅ 3개 스레드 등록 완료")
    
    # 중복 등록 방지 테스트
    assert not manager.register_thread("test_worker1", test_worker, args=(1, results)), "중복 등록이 허용됨"
    print("✅ 중복 등록 방지: OK")
    
    # 스레드 시작
    started = manager.start_all()
    assert started == 3, f"시작 실패: {started}/3"
    print(f"✅ {started}개 스레드 시작됨")
    
    # 상태 확인
    time.sleep(0.2)  # 스레드가 실행되도록 대기
    status = manager.get_all_status()
    assert status['test_worker1'] == 'running', "스레드 상태 오류"
    assert status['test_worker2'] == 'running', "스레드 상태 오류"
    assert status['test_worker3'] == 'running', "스레드 상태 오류"
    print(f"✅ 스레드 상태: {status}")
    
    # 통계 확인
    stats = manager.get_statistics()
    assert stats['total_threads'] == 3, f"총 스레드 수 오류: {stats['total_threads']}"
    assert stats['running'] == 3, f"실행 중 스레드 수 오류: {stats['running']}"
    print(f"✅ 스레드 통계: {stats}")
    
    # 스레드 정보 조회
    info = manager.get_thread_info('test_worker1')
    assert info is not None, "스레드 정보 조회 실패"
    assert info['status'] == 'running', f"스레드 상태 오류: {info['status']}"
    assert info['is_alive'], "스레드 살아있지 않음"
    print(f"✅ 스레드 정보: {info['name']} (uptime={info['uptime']:.2f}초)")
    
    # 1초 동안 실행
    print("⏳ 1초 동안 실행 중...")
    time.sleep(1.0)
    
    # Graceful shutdown 테스트
    print("🛑 Graceful shutdown 시작...")
    stop_results = manager.stop_all(timeout=2.0)
    assert all(stop_results.values()), f"일부 스레드 중지 실패: {stop_results}"
    print(f"✅ 모든 스레드 정상 종료: {stop_results}")
    
    # 스레드가 완전히 종료될 때까지 대기
    time.sleep(0.5)
    
    # 최종 상태 확인
    final_status = manager.get_all_status()
    # 스레드가 stopped 또는 stopping 상태면 정상
    for thread_name in ['test_worker1', 'test_worker2', 'test_worker3']:
        assert final_status[thread_name] in ['stopped', 'stopping'], f"스레드 상태 오류: {final_status[thread_name]}"
    print(f"✅ 최종 상태: {final_status}")
    
    # 워커 결과 확인
    assert len(results) == 3, f"결과 수 오류: {len(results)}/3"
    print(f"✅ 워커 결과: {results}")
    
    print("\n✅ ThreadManager 모든 테스트 통과!\n")


def test_thread_safe_concurrent_access():
    """멀티스레드 환경에서의 안전성 테스트"""
    print("=" * 60)
    print("🔒 스레드 안전성 테스트 시작")
    print("=" * 60)
    
    state = get_system_state()
    state.reset_all()
    
    def concurrent_incrementer(stop_event, stat_type, iterations):
        """동시에 통계를 증가시키는 함수"""
        for _ in range(iterations):
            if stop_event.is_set():
                break
            if stat_type == 'threat':
                state.increment_threat('high')
            elif stat_type == 'defense':
                state.increment_defense('blocked')
            time.sleep(0.001)  # 약간의 지연
    
    manager = ThreadManager()
    iterations = 100
    
    # 여러 스레드가 동시에 통계를 업데이트
    manager.register_thread("threat_inc1", concurrent_incrementer, args=('threat', iterations))
    manager.register_thread("threat_inc2", concurrent_incrementer, args=('threat', iterations))
    manager.register_thread("defense_inc1", concurrent_incrementer, args=('defense', iterations))
    manager.register_thread("defense_inc2", concurrent_incrementer, args=('defense', iterations))
    
    print(f"⏳ 4개 스레드로 각각 {iterations}회 업데이트 실행 중...")
    manager.start_all()
    
    # 모든 스레드가 완료될 때까지 대기
    time.sleep(2.0)
    manager.stop_all(timeout=2.0)
    
    # 결과 확인
    threat_stats = state.get_threat_stats()
    defense_stats = state.get_defense_stats()
    
    expected_threat = iterations * 2  # 2개 스레드
    expected_defense = iterations * 2  # 2개 스레드
    
    print(f"✅ 위협 통계 high: {threat_stats['high']} (예상: {expected_threat})")
    print(f"✅ 방어 통계 blocked: {defense_stats['blocked']} (예상: {expected_defense})")
    
    # 스레드 안전성 검증
    assert threat_stats['high'] == expected_threat, f"Race condition 발생! {threat_stats['high']} != {expected_threat}"
    assert defense_stats['blocked'] == expected_defense, f"Race condition 발생! {defense_stats['blocked']} != {expected_defense}"
    
    print("\n✅ 스레드 안전성 테스트 통과! (Race condition 없음)\n")


def main():
    """메인 테스트 실행"""
    print("\n" + "=" * 60)
    print("🚀 시스템 관리 모듈 통합 테스트")
    print("=" * 60 + "\n")
    
    try:
        # SystemState 테스트
        test_system_state()
        
        # ThreadManager 테스트
        test_thread_manager()
        
        # 스레드 안전성 테스트
        test_thread_safe_concurrent_access()
        
        print("=" * 60)
        print("🎉 모든 테스트 통과!")
        print("=" * 60)
        print("\n✅ P0 개선 작업 검증 완료:")
        print("   - SystemState 클래스: 전역 변수 대체 ✅")
        print("   - ThreadManager 클래스: Graceful shutdown ✅")
        print("   - 스레드 안전성: Race condition 방지 ✅")
        print("\n")
        
        return True
        
    except AssertionError as e:
        print(f"\n❌ 테스트 실패: {e}\n")
        return False
    except Exception as e:
        print(f"\n❌ 예외 발생: {e}\n")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)

