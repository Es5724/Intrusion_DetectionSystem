# -*- coding: utf-8 -*-

"""
스레드 관리 클래스

애플리케이션의 모든 스레드를 중앙집중식으로 관리하고,
graceful shutdown을 보장합니다.
"""

import threading
import logging
import time
from typing import Dict, Callable, Optional, Any, List
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger('ThreadManager')


class ThreadStatus(Enum):
    """스레드 상태"""
    PENDING = "pending"  # 시작 대기 중
    RUNNING = "running"  # 실행 중
    STOPPING = "stopping"  # 중지 중
    STOPPED = "stopped"  # 중지됨
    ERROR = "error"  # 오류 발생


@dataclass
class ManagedThread:
    """관리되는 스레드 정보"""
    name: str
    thread: threading.Thread
    stop_event: threading.Event
    status: ThreadStatus
    start_time: float
    error: Optional[Exception] = None
    
    def get_uptime(self) -> float:
        """스레드 실행 시간 반환 (초)"""
        return time.time() - self.start_time
    
    def is_alive(self) -> bool:
        """스레드가 살아있는지 확인"""
        return self.thread.is_alive()


class ThreadManager:
    """
    스레드 생명주기를 관리하는 클래스
    
    Features:
        - 스레드 등록 및 시작
        - Graceful shutdown (타임아웃 지원)
        - 스레드 상태 모니터링
        - 오류 추적 및 로깅
        - 자동 재시작 (옵션)
    
    Example:
        >>> manager = ThreadManager()
        >>> 
        >>> def worker(stop_event):
        >>>     while not stop_event.is_set():
        >>>         print("Working...")
        >>>         time.sleep(1)
        >>> 
        >>> manager.register_thread("worker1", worker)
        >>> manager.start_all()
        >>> 
        >>> # ... 작업 수행 ...
        >>> 
        >>> manager.stop_all(timeout=5.0)
    """
    
    def __init__(self):
        """ThreadManager 초기화"""
        self._threads: Dict[str, ManagedThread] = {}
        self._lock = threading.Lock()
        self._global_stop_event = threading.Event()
        logger.info("ThreadManager 초기화됨")
    
    def register_thread(
        self,
        name: str,
        target: Callable,
        daemon: bool = True,
        args: tuple = (),
        kwargs: dict = None
    ) -> bool:
        """
        스레드 등록
        
        Args:
            name: 스레드 이름 (고유해야 함)
            target: 실행할 함수 (stop_event를 첫 번째 인자로 받아야 함)
            daemon: 데몬 스레드 여부
            args: 추가 위치 인자 (stop_event 다음에 전달됨)
            kwargs: 추가 키워드 인자
        
        Returns:
            bool: 등록 성공 여부
        
        Note:
            target 함수는 반드시 stop_event를 첫 번째 매개변수로 받아야 합니다.
            예: def my_worker(stop_event, arg1, arg2): ...
        """
        with self._lock:
            if name in self._threads:
                logger.warning(f"스레드 '{name}'이 이미 등록되어 있습니다")
                return False
            
            stop_event = threading.Event()
            kwargs = kwargs or {}
            
            # stop_event를 첫 번째 인자로 전달
            thread = threading.Thread(
                target=target,
                args=(stop_event,) + args,
                kwargs=kwargs,
                name=name,
                daemon=daemon
            )
            
            managed_thread = ManagedThread(
                name=name,
                thread=thread,
                stop_event=stop_event,
                status=ThreadStatus.PENDING,
                start_time=time.time()
            )
            
            self._threads[name] = managed_thread
            logger.info(f"스레드 '{name}' 등록됨 (daemon={daemon})")
            return True
    
    def start_thread(self, name: str) -> bool:
        """
        특정 스레드 시작
        
        Args:
            name: 시작할 스레드 이름
        
        Returns:
            bool: 시작 성공 여부
        """
        with self._lock:
            if name not in self._threads:
                logger.error(f"스레드 '{name}'이 등록되지 않았습니다")
                return False
            
            managed_thread = self._threads[name]
            
            if managed_thread.status == ThreadStatus.RUNNING:
                logger.warning(f"스레드 '{name}'이 이미 실행 중입니다")
                return False
            
            try:
                managed_thread.thread.start()
                managed_thread.status = ThreadStatus.RUNNING
                managed_thread.start_time = time.time()
                logger.info(f"스레드 '{name}' 시작됨")
                return True
            except Exception as e:
                managed_thread.status = ThreadStatus.ERROR
                managed_thread.error = e
                logger.error(f"스레드 '{name}' 시작 실패: {e}")
                return False
    
    def start_all(self) -> int:
        """
        모든 등록된 스레드 시작
        
        Returns:
            int: 성공적으로 시작된 스레드 수
        """
        success_count = 0
        with self._lock:
            thread_names = list(self._threads.keys())
        
        for name in thread_names:
            if self.start_thread(name):
                success_count += 1
        
        logger.info(f"{success_count}/{len(thread_names)}개 스레드 시작됨")
        return success_count
    
    def stop_thread(self, name: str, timeout: Optional[float] = None) -> bool:
        """
        특정 스레드 중지 (graceful)
        
        Args:
            name: 중지할 스레드 이름
            timeout: 최대 대기 시간 (초). None이면 무한 대기
        
        Returns:
            bool: 중지 성공 여부
        """
        with self._lock:
            if name not in self._threads:
                logger.warning(f"스레드 '{name}'이 등록되지 않았습니다")
                return False
            
            managed_thread = self._threads[name]
        
        if managed_thread.status != ThreadStatus.RUNNING:
            logger.info(f"스레드 '{name}'이 실행 중이 아닙니다")
            return True
        
        try:
            logger.info(f"스레드 '{name}' 중지 요청...")
            managed_thread.status = ThreadStatus.STOPPING
            managed_thread.stop_event.set()
            
            managed_thread.thread.join(timeout=timeout)
            
            if managed_thread.thread.is_alive():
                logger.warning(f"스레드 '{name}'이 타임아웃 내에 종료되지 않았습니다")
                return False
            else:
                managed_thread.status = ThreadStatus.STOPPED
                logger.info(f"스레드 '{name}' 정상 종료됨")
                return True
                
        except Exception as e:
            logger.error(f"스레드 '{name}' 중지 중 오류: {e}")
            managed_thread.status = ThreadStatus.ERROR
            managed_thread.error = e
            return False
    
    def stop_all(self, timeout: float = 10.0) -> Dict[str, bool]:
        """
        모든 스레드 중지 (graceful)
        
        Args:
            timeout: 각 스레드별 최대 대기 시간 (초)
        
        Returns:
            Dict[str, bool]: 스레드 이름과 중지 성공 여부 매핑
        """
        logger.info(f"모든 스레드 중지 시작 (timeout={timeout}초)...")
        self._global_stop_event.set()
        
        results = {}
        with self._lock:
            thread_names = list(self._threads.keys())
        
        # 모든 스레드에 stop 신호 전송
        for name in thread_names:
            managed_thread = self._threads[name]
            if managed_thread.status == ThreadStatus.RUNNING:
                managed_thread.stop_event.set()
                managed_thread.status = ThreadStatus.STOPPING
        
        # 모든 스레드가 종료될 때까지 대기
        for name in thread_names:
            success = self.stop_thread(name, timeout=timeout)
            results[name] = success
        
        success_count = sum(results.values())
        logger.info(f"{success_count}/{len(thread_names)}개 스레드 정상 종료됨")
        return results
    
    def is_running(self, name: str) -> bool:
        """스레드가 실행 중인지 확인"""
        with self._lock:
            if name not in self._threads:
                return False
            return self._threads[name].status == ThreadStatus.RUNNING
    
    def get_status(self, name: str) -> Optional[ThreadStatus]:
        """스레드 상태 조회"""
        with self._lock:
            if name not in self._threads:
                return None
            return self._threads[name].status
    
    def get_all_status(self) -> Dict[str, str]:
        """모든 스레드 상태 조회"""
        with self._lock:
            return {
                name: thread.status.value
                for name, thread in self._threads.items()
            }
    
    def get_thread_info(self, name: str) -> Optional[Dict[str, Any]]:
        """스레드 상세 정보 조회"""
        with self._lock:
            if name not in self._threads:
                return None
            
            thread = self._threads[name]
            return {
                'name': thread.name,
                'status': thread.status.value,
                'is_alive': thread.is_alive(),
                'uptime': thread.get_uptime(),
                'daemon': thread.thread.daemon,
                'error': str(thread.error) if thread.error else None
            }
    
    def get_all_thread_info(self) -> Dict[str, Dict[str, Any]]:
        """모든 스레드 상세 정보 조회"""
        with self._lock:
            return {
                name: {
                    'status': thread.status.value,
                    'is_alive': thread.is_alive(),
                    'uptime': thread.get_uptime(),
                    'daemon': thread.thread.daemon,
                    'error': str(thread.error) if thread.error else None
                }
                for name, thread in self._threads.items()
            }
    
    def wait_for_all(self, timeout: Optional[float] = None) -> bool:
        """
        모든 스레드가 종료될 때까지 대기
        
        Args:
            timeout: 최대 대기 시간 (초)
        
        Returns:
            bool: 모든 스레드가 정상 종료되었는지 여부
        """
        start_time = time.time()
        
        while True:
            with self._lock:
                all_stopped = all(
                    not thread.is_alive()
                    for thread in self._threads.values()
                )
            
            if all_stopped:
                logger.info("모든 스레드가 종료되었습니다")
                return True
            
            if timeout and (time.time() - start_time) >= timeout:
                logger.warning("스레드 대기 타임아웃")
                return False
            
            time.sleep(0.1)
    
    def cleanup(self) -> None:
        """모든 스레드 정리 및 제거"""
        logger.info("ThreadManager 정리 시작...")
        self.stop_all(timeout=5.0)
        
        with self._lock:
            self._threads.clear()
            self._global_stop_event.clear()
        
        logger.info("ThreadManager 정리 완료")
    
    def get_statistics(self) -> Dict[str, Any]:
        """스레드 통계 정보 반환"""
        with self._lock:
            total = len(self._threads)
            running = sum(1 for t in self._threads.values() if t.status == ThreadStatus.RUNNING)
            stopped = sum(1 for t in self._threads.values() if t.status == ThreadStatus.STOPPED)
            error = sum(1 for t in self._threads.values() if t.status == ThreadStatus.ERROR)
            
            return {
                'total_threads': total,
                'running': running,
                'stopped': stopped,
                'error': error,
                'pending': total - running - stopped - error
            }
    
    def __repr__(self) -> str:
        """ThreadManager 문자열 표현"""
        stats = self.get_statistics()
        return (
            f"ThreadManager(total={stats['total_threads']}, "
            f"running={stats['running']}, stopped={stats['stopped']}, "
            f"error={stats['error']})"
        )


# 전역 ThreadManager 인스턴스 (싱글톤 패턴)
_thread_manager_instance: Optional[ThreadManager] = None
_thread_manager_lock = threading.Lock()


def get_thread_manager() -> ThreadManager:
    """
    전역 ThreadManager 인스턴스 반환 (싱글톤)
    
    Returns:
        ThreadManager: 스레드 관리자 인스턴스
    
    Example:
        >>> from modules.thread_manager import get_thread_manager
        >>> manager = get_thread_manager()
        >>> manager.register_thread("worker", my_worker_func)
    """
    global _thread_manager_instance
    
    if _thread_manager_instance is None:
        with _thread_manager_lock:
            if _thread_manager_instance is None:
                _thread_manager_instance = ThreadManager()
    
    return _thread_manager_instance


if __name__ == '__main__':
    # 테스트 코드
    import sys
    
    print("=== ThreadManager 테스트 ===\n")
    
    def test_worker(stop_event, worker_id):
        """테스트 워커 함수"""
        count = 0
        while not stop_event.is_set():
            count += 1
            print(f"Worker {worker_id}: {count}")
            time.sleep(1)
        print(f"Worker {worker_id} 종료됨 (총 {count}회 실행)")
    
    # ThreadManager 생성
    manager = get_thread_manager()
    
    # 스레드 등록
    manager.register_thread("worker1", test_worker, args=(1,))
    manager.register_thread("worker2", test_worker, args=(2,))
    manager.register_thread("worker3", test_worker, args=(3,))
    
    print(f"등록된 스레드: {manager.get_all_status()}\n")
    
    # 모든 스레드 시작
    manager.start_all()
    print(f"\n스레드 상태: {manager.get_all_status()}")
    print(f"통계: {manager.get_statistics()}\n")
    
    # 3초 대기
    print("3초 동안 실행...")
    time.sleep(3)
    
    # 스레드 정보 출력
    print(f"\n스레드 정보:")
    for name, info in manager.get_all_thread_info().items():
        print(f"  {name}: {info}")
    
    # 모든 스레드 중지
    print("\n모든 스레드 중지 중...")
    results = manager.stop_all(timeout=2.0)
    print(f"중지 결과: {results}")
    
    # 최종 상태
    print(f"\n최종 상태: {manager.get_all_status()}")
    print(f"최종 통계: {manager.get_statistics()}")
    
    print("\n✅ 테스트 완료!")

