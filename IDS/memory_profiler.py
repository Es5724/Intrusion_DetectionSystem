#!/usr/bin/env python3
"""
IDS 메모리 누수 진단 프로파일러
실행 중인 IDSAgent_RL.py의 메모리 사용량을 상세하게 분석합니다.
"""

import psutil
import time
import gc
import sys
import threading
import tracemalloc

class MemoryProfiler:
    def __init__(self):
        self.start_time = time.time()
        self.memory_history = []
        self.gc_history = []
        self.is_running = False
        
    def start_monitoring(self, interval=5):
        """메모리 모니터링 시작"""
        self.is_running = True
        tracemalloc.start()  # 메모리 추적 시작
        
        print("🔍 메모리 누수 진단 프로파일러 시작...")
        print("="*80)
        print(f"{'시간':<8} {'메모리(MB)':<12} {'변화(MB)':<10} {'GC 객체':<10} {'가장 큰 누수':<20}")
        print("-"*80)
        
        monitor_thread = threading.Thread(target=self._monitor_loop, args=(interval,))
        monitor_thread.daemon = True
        monitor_thread.start()
        return monitor_thread
    
    def _monitor_loop(self, interval):
        """메모리 모니터링 루프"""
        last_memory = 0
        
        while self.is_running:
            try:
                # 현재 메모리 사용량
                process = psutil.Process()
                current_memory = process.memory_info().rss / (1024 * 1024)
                memory_change = current_memory - last_memory if last_memory > 0 else 0
                
                # 가비지 컬렉션 정보
                gc_objects = len(gc.get_objects())
                collected = gc.collect()
                
                # tracemalloc으로 가장 큰 메모리 할당 추적
                current, peak = tracemalloc.get_traced_memory()
                
                # 가장 큰 메모리 사용 위치 찾기
                top_stats = tracemalloc.take_snapshot().statistics('lineno')
                biggest_leak = "N/A"
                if top_stats:
                    stat = top_stats[0]
                    biggest_leak = f"{stat.traceback.format()[-1].split('/')[-1][:15]}"
                
                # 기록 저장
                elapsed = time.time() - self.start_time
                record = {
                    'time': elapsed,
                    'memory': current_memory,
                    'change': memory_change,
                    'gc_objects': gc_objects,
                    'collected': collected,
                    'biggest_leak': biggest_leak
                }
                self.memory_history.append(record)
                
                # 화면 출력
                print(f"{elapsed:6.0f}초 {current_memory:10.1f} {memory_change:+8.2f} {gc_objects:8d} {biggest_leak:<20}")
                
                # 메모리 누수 경고
                if memory_change > 5.0:  # 5MB 이상 증가
                    print(f"   ⚠️  급격한 메모리 증가 감지: +{memory_change:.1f}MB")
                    
                if current_memory > 200:  # 200MB 이상
                    print(f"   🚨 높은 메모리 사용량: {current_memory:.1f}MB")
                
                last_memory = current_memory
                time.sleep(interval)
                
            except Exception as e:
                print(f"모니터링 오류: {e}")
                break
    
    def stop_monitoring(self):
        """모니터링 중지 및 보고서 생성"""
        self.is_running = False
        tracemalloc.stop()
        
        if not self.memory_history:
            print("모니터링 데이터가 없습니다.")
            return
        
        print("\n" + "="*80)
        print("📊 메모리 누수 진단 보고서")
        print("="*80)
        
        # 기본 통계
        start_memory = self.memory_history[0]['memory']
        end_memory = self.memory_history[-1]['memory']
        total_change = end_memory - start_memory
        duration = self.memory_history[-1]['time']
        
        print(f"분석 기간: {duration:.0f}초")
        print(f"시작 메모리: {start_memory:.1f} MB")
        print(f"종료 메모리: {end_memory:.1f} MB")
        print(f"총 메모리 변화: {total_change:+.1f} MB")
        print(f"시간당 증가율: {(total_change/duration)*3600:+.1f} MB/hour")
        
        # 누수 여부 판정
        if total_change > 10:
            print(f"🚨 심각한 메모리 누수 감지!")
        elif total_change > 5:
            print(f"⚠️  메모리 누수 의심")
        elif total_change > 2:
            print(f"📈 미세한 메모리 증가")
        else:
            print(f"✅ 메모리 사용량 안정")
        
        # 가장 큰 증가 구간 찾기
        max_increase = 0
        max_period = None
        for i in range(1, len(self.memory_history)):
            change = self.memory_history[i]['change']
            if change > max_increase:
                max_increase = change
                max_period = i
        
        if max_period:
            print(f"\n가장 큰 메모리 증가:")
            print(f"  시점: {self.memory_history[max_period]['time']:.0f}초")
            print(f"  증가량: +{max_increase:.1f} MB")
        
        # 메모리 사용 패턴 분석
        increases = [r['change'] for r in self.memory_history if r['change'] > 0]
        if increases:
            avg_increase = sum(increases) / len(increases)
            print(f"\n평균 증가량: {avg_increase:.2f} MB/회")
            print(f"증가 횟수: {len(increases)}회")

def monitor_ids_memory():
    """IDS 메모리 모니터링 실행"""
    profiler = MemoryProfiler()
    
    try:
        monitor_thread = profiler.start_monitoring(interval=3)  # 3초마다
        
        print("\n메모리 모니터링 중... (Ctrl+C로 중지)")
        print("지금 다른 터미널에서 IDSAgent_RL.py를 실행하세요!")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n모니터링 중지 중...")
        profiler.stop_monitoring()
        monitor_thread.join(timeout=2)

if __name__ == "__main__":
    monitor_ids_memory() 