"""
객체 풀링 테스트 스크립트
메모리 사용량과 성능 개선 효과를 측정합니다.
"""

import sys
import os
import time
import gc
import psutil

# 모듈 경로 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_dir, 'modules'))

from memory_optimization import (PacketObjectPool, ProtocolStatsPool, DataFramePool, 
                                get_packet_pool, get_dataframe_pool, get_batch_processor)

def measure_memory():
    """현재 프로세스의 메모리 사용량 측정"""
    process = psutil.Process()
    return process.memory_info().rss / (1024 * 1024)  # MB

def test_without_pooling(iterations=10000):
    """객체 풀링 없이 테스트"""
    start_time = time.time()
    start_memory = measure_memory()
    
    packets = []
    for i in range(iterations):
        packet = {
            'source': f'192.168.1.{i % 255}',
            'destination': f'10.0.0.{i % 255}',
            'protocol': i % 3,
            'length': 1500 + i,
            'ttl': 64,
            'flags': 0,
            'info': f'Packet {i}',
            'timestamp': time.time()
        }
        packets.append(packet)
        
        # 처리 시뮬레이션
        if i % 1000 == 0:
            packets.clear()  # 주기적으로 비우기
    
    end_time = time.time()
    end_memory = measure_memory()
    
    return {
        'time': end_time - start_time,
        'memory_start': start_memory,
        'memory_end': end_memory,
        'memory_used': end_memory - start_memory
    }

def test_with_pooling(iterations=10000):
    """객체 풀링 사용하여 테스트"""
    pool = PacketObjectPool(initial_size=100, max_size=500)
    start_time = time.time()
    start_memory = measure_memory()
    
    packets = []
    for i in range(iterations):
        packet = pool.get()
        packet.update({
            'source': f'192.168.1.{i % 255}',
            'destination': f'10.0.0.{i % 255}',
            'protocol': i % 3,
            'length': 1500 + i,
            'ttl': 64,
            'flags': 0,
            'info': f'Packet {i}',
            'timestamp': time.time()
        })
        packets.append(packet)
        
        # 처리 시뮬레이션
        if i % 1000 == 0:
            # 사용한 패킷들을 풀에 반환
            for p in packets:
                pool.put(p)
            packets.clear()
    
    end_time = time.time()
    end_memory = measure_memory()
    
    stats = pool.get_stats()
    
    return {
        'time': end_time - start_time,
        'memory_start': start_memory,
        'memory_end': end_memory,
        'memory_used': end_memory - start_memory,
        'pool_stats': stats
    }

def test_dataframe_pooling(iterations=1000):
    """DataFrame 풀링 테스트"""
    import pandas as pd
    import numpy as np
    
    start_time = time.time()
    start_memory = measure_memory()
    
    dataframe_pool = DataFramePool(max_rows=50, pool_size=5)
    
    for i in range(iterations):
        # 풀에서 배열 가져오기
        rows = min(50, (i % 50) + 1)
        array, actual_rows, actual_cols = dataframe_pool.get_array(rows, 6)
        
        # 데이터 채우기 (안전한 크기 체크)
        for j in range(min(rows, array.shape[0])):
            if array.shape[1] > 0:
                array[j, 0] = f'192.168.1.{j}'
            if array.shape[1] > 1:
                array[j, 1] = f'10.0.0.{j}'
            if array.shape[1] > 2:
                array[j, 2] = j % 3
            if array.shape[1] > 3:
                array[j, 3] = 1500 + j
            if array.shape[1] > 4:
                array[j, 4] = 64
            if array.shape[1] > 5:
                array[j, 5] = 0
        
        # DataFrame 생성 (필요시에만)
        if i % 10 == 0 and array.shape[0] >= rows and array.shape[1] >= 6:
            df = pd.DataFrame({
                'source': array[:rows, 0],
                'destination': array[:rows, 1],
                'protocol': array[:rows, 2],
                'length': array[:rows, 3],
                'ttl': array[:rows, 4],
                'flags': array[:rows, 5]
            })
            del df
        
        # 배열 반환
        dataframe_pool.put_array(array)
    
    end_time = time.time()
    end_memory = measure_memory()
    
    return {
        'time': end_time - start_time,
        'memory_start': start_memory,
        'memory_end': end_memory,
        'memory_used': end_memory - start_memory,
        'pool_stats': dataframe_pool.get_stats()
    }

def test_dataframe_without_pooling(iterations=1000):
    """DataFrame 풀링 없이 테스트"""
    import pandas as pd
    import numpy as np
    
    start_time = time.time()
    start_memory = measure_memory()
    
    for i in range(iterations):
        rows = min(50, (i % 50) + 1)
        
        # 매번 새 배열 생성
        array = np.empty((rows, 6), dtype=object)
        
        # 데이터 채우기
        for j in range(rows):
            array[j, 0] = f'192.168.1.{j}'
            array[j, 1] = f'10.0.0.{j}'
            array[j, 2] = j % 3
            array[j, 3] = 1500 + j
            array[j, 4] = 64
            array[j, 5] = 0
        
        # DataFrame 생성 (필요시에만)
        if i % 10 == 0:
            df = pd.DataFrame({
                'source': array[:rows, 0],
                'destination': array[:rows, 1],
                'protocol': array[:rows, 2],
                'length': array[:rows, 3],
                'ttl': array[:rows, 4],
                'flags': array[:rows, 5]
            })
            del df
        
        del array
    
    end_time = time.time()
    end_memory = measure_memory()
    
    return {
        'time': end_time - start_time,
        'memory_start': start_memory,
        'memory_end': end_memory,
        'memory_used': end_memory - start_memory
    }

def main():
    print("=" * 80)
    print("🔍 개선된 객체 풀링 성능 테스트")
    print("=" * 80)
    
    # 패킷 객체 풀링 테스트
    packet_iterations = 10000
    print(f"\n📦 패킷 객체 풀링 테스트: {packet_iterations:,}개 패킷")
    print("-" * 50)
    
    # 가비지 컬렉션 강제 수행
    gc.collect()
    time.sleep(1)
    
    # 풀링 없이 테스트
    print("1. 패킷 풀링 없이 테스트...")
    result_packet_without = test_without_pooling(packet_iterations)
    
    # 가비지 컬렉션
    gc.collect()
    time.sleep(1)
    
    # 풀링 사용하여 테스트
    print("2. 패킷 풀링 사용하여 테스트...")
    result_packet_with = test_with_pooling(packet_iterations)
    
    # DataFrame 풀링 테스트
    dataframe_iterations = 1000
    print(f"\n🔢 DataFrame 풀링 테스트: {dataframe_iterations:,}개 배열")
    print("-" * 50)
    
    # 가비지 컬렉션
    gc.collect()
    time.sleep(1)
    
    # DataFrame 풀링 없이 테스트
    print("3. DataFrame 풀링 없이 테스트...")
    result_df_without = test_dataframe_without_pooling(dataframe_iterations)
    
    # 가비지 컬렉션
    gc.collect()
    time.sleep(1)
    
    # DataFrame 풀링 사용하여 테스트
    print("4. DataFrame 풀링 사용하여 테스트...")
    result_df_with = test_dataframe_pooling(dataframe_iterations)
    
    # 결과 출력
    print("\n" + "=" * 80)
    print("📊 테스트 결과 분석")
    print("=" * 80)
    
    # 패킷 풀링 결과
    print("\n🔸 패킷 객체 풀링 결과")
    print("-" * 40)
    print("│ 구분           │ 풀링 없음    │ 풀링 사용    │ 개선 효과     │")
    print("├" + "─" * 15 + "┼" + "─" * 13 + "┼" + "─" * 13 + "┼" + "─" * 14 + "┤")
    
    packet_time_improvement = (1 - result_packet_with['time'] / result_packet_without['time']) * 100
    packet_memory_improvement = (1 - result_packet_with['memory_used'] / max(0.1, result_packet_without['memory_used'])) * 100
    
    print(f"│ 실행 시간      │ {result_packet_without['time']:8.3f}초 │ {result_packet_with['time']:8.3f}초 │ {packet_time_improvement:6.1f}% 개선 │")
    print(f"│ 메모리 사용    │ {result_packet_without['memory_used']:8.1f}MB │ {result_packet_with['memory_used']:8.1f}MB │ {packet_memory_improvement:6.1f}% 절약 │")
    
    if 'pool_stats' in result_packet_with:
        stats = result_packet_with['pool_stats']
        print(f"│ 재사용률       │      -       │ {stats['reuse_rate']:8.1f}% │             │")
        print(f"│ 생성된 객체    │      -       │ {stats['total_created']:8,}개 │             │")
    
    # DataFrame 풀링 결과  
    print("\n🔸 DataFrame 풀링 결과")
    print("-" * 40)
    print("│ 구분           │ 풀링 없음    │ 풀링 사용    │ 개선 효과     │")
    print("├" + "─" * 15 + "┼" + "─" * 13 + "┼" + "─" * 13 + "┼" + "─" * 14 + "┤")
    
    df_time_improvement = (1 - result_df_with['time'] / result_df_without['time']) * 100
    df_memory_improvement = (1 - result_df_with['memory_used'] / max(0.1, result_df_without['memory_used'])) * 100
    
    print(f"│ 실행 시간      │ {result_df_without['time']:8.3f}초 │ {result_df_with['time']:8.3f}초 │ {df_time_improvement:6.1f}% 개선 │")
    print(f"│ 메모리 사용    │ {result_df_without['memory_used']:8.1f}MB │ {result_df_with['memory_used']:8.1f}MB │ {df_memory_improvement:6.1f}% 절약 │")
    
    if 'pool_stats' in result_df_with:
        df_stats = result_df_with['pool_stats']
        print(f"│ 재사용률       │      -       │ {df_stats['reuse_rate']:8.1f}% │             │")
        print(f"│ 생성된 배열    │      -       │ {df_stats['total_created']:8,}개 │             │")
    
    # 종합 분석
    print("\n🔸 종합 분석")
    print("-" * 40)
    
    total_packet_savings = result_packet_with['pool_stats']['total_reused'] * 0.001 if 'pool_stats' in result_packet_with else 0
    total_df_savings = result_df_with['pool_stats']['total_reused'] * 5 if 'pool_stats' in result_df_with else 0
    
    print(f"✅ 패킷 풀링 예상 절약: {total_packet_savings:.1f}MB")
    print(f"✅ DataFrame 풀링 예상 절약: {total_df_savings:.1f}MB")
    print(f"🎯 총 예상 절약: {total_packet_savings + total_df_savings:.1f}MB")
    
    # 권장사항
    print("\n🔸 권장사항")
    print("-" * 40)
    
    if packet_memory_improvement > 10:
        print("✅ 패킷 풀링: 효과적 - 계속 사용 권장")
    else:
        print("⚠️  패킷 풀링: 제한적 효과 - 다른 최적화 고려")
        
    if df_memory_improvement > 20:
        print("✅ DataFrame 풀링: 매우 효과적 - 필수 적용")
    elif df_memory_improvement > 10:
        print("✅ DataFrame 풀링: 효과적 - 사용 권장")
    else:
        print("⚠️  DataFrame 풀링: 제한적 효과 - 구현 검토 필요")
    
    # 전역 풀 테스트
    print("\n🔸 전역 풀 검증")
    print("-" * 40)
    
    global_pool = get_packet_pool()
    global_df_pool = get_dataframe_pool()
    
    # 간단한 동작 테스트
    for i in range(100):
        packet = global_pool.get()
        global_pool.put(packet)
        
        array, rows, cols = global_df_pool.get_array(10, 6)
        global_df_pool.put_array(array)
    
    global_packet_stats = global_pool.get_stats()
    global_df_stats = global_df_pool.get_stats()
    
    print(f"📦 전역 패킷 풀 재사용률: {global_packet_stats['reuse_rate']:.1f}%")
    print(f"🔢 전역 DataFrame 풀 재사용률: {global_df_stats['reuse_rate']:.1f}%")

if __name__ == "__main__":
    main() 