# -*- coding: utf-8 -*-

"""
SystemState 클래스 단위 테스트
"""

import pytest
import time
from modules.system_state import SystemState, get_system_state, ThreatStatistics, DefenseStatistics


@pytest.fixture
def system_state():
    """각 테스트마다 새로운 SystemState 인스턴스 생성"""
    SystemState.reset_instance()
    state = get_system_state()
    state.reset_all()
    return state


class TestThreatStatistics:
    """ThreatStatistics 클래스 테스트"""
    
    def test_increment(self):
        stats = ThreatStatistics()
        stats.increment('high')
        stats.increment('high')
        stats.increment('medium')
        
        assert stats.high == 2
        assert stats.medium == 1
        assert stats.low == 0
    
    def test_get_total(self):
        stats = ThreatStatistics(high=5, medium=3, low=2, safe=10)
        assert stats.get_total() == 20
    
    def test_to_dict(self):
        stats = ThreatStatistics(high=1, medium=2, low=3, safe=4)
        data = stats.to_dict()
        
        assert data['high'] == 1
        assert data['medium'] == 2
        assert data['low'] == 3
        assert data['safe'] == 4


class TestDefenseStatistics:
    """DefenseStatistics 클래스 테스트"""
    
    def test_increment(self):
        stats = DefenseStatistics()
        stats.increment('blocked')
        stats.increment('blocked')
        stats.increment('alerts')
        
        assert stats.blocked == 2
        assert stats.alerts == 1
        assert stats.monitored == 0
    
    def test_get_total(self):
        stats = DefenseStatistics(blocked=10, monitored=5, alerts=3)
        assert stats.get_total() == 18


class TestSystemState:
    """SystemState 클래스 테스트"""
    
    def test_singleton(self, system_state):
        """싱글톤 패턴 검증"""
        state1 = get_system_state()
        state2 = get_system_state()
        assert state1 is state2
        assert state1 is system_state
    
    def test_threat_stats(self, system_state):
        """위협 통계 관리 테스트"""
        system_state.increment_threat('high')
        system_state.increment_threat('high')
        system_state.increment_threat('medium')
        
        stats = system_state.get_threat_stats()
        assert stats['high'] == 2
        assert stats['medium'] == 1
        assert stats['low'] == 0
        assert stats['safe'] == 0
    
    def test_defense_stats(self, system_state):
        """방어 통계 관리 테스트"""
        system_state.increment_defense('blocked')
        system_state.increment_defense('monitored')
        system_state.increment_defense('blocked')
        
        stats = system_state.get_defense_stats()
        assert stats['blocked'] == 2
        assert stats['monitored'] == 1
        assert stats['alerts'] == 0
    
    def test_ml_stats(self, system_state):
        """ML 통계 관리 테스트"""
        system_state.update_ml_training(0.95)
        
        stats = system_state.get_ml_stats()
        assert stats['total_trained'] == 1
        assert stats['model_accuracy'] == 0.95
        assert stats['last_train_time'] is not None
        assert not stats['training_in_progress']
    
    def test_ml_training_status(self, system_state):
        """ML 학습 상태 설정 테스트"""
        system_state.set_ml_training_status(True)
        assert system_state.get_ml_stats()['training_in_progress']
        
        system_state.set_ml_training_status(False)
        assert not system_state.get_ml_stats()['training_in_progress']
    
    def test_uptime(self, system_state):
        """가동 시간 테스트"""
        time.sleep(0.1)
        uptime = system_state.get_uptime()
        assert uptime > 0
        
        uptime_str = system_state.get_uptime_str()
        assert isinstance(uptime_str, str)
        assert ':' in uptime_str
    
    def test_stop_request(self, system_state):
        """중지 요청 관리 테스트"""
        assert not system_state.is_stop_requested()
        
        system_state.request_stop()
        assert system_state.is_stop_requested()
        
        system_state.reset_stop_request()
        assert not system_state.is_stop_requested()
    
    def test_component_management(self, system_state):
        """컴포넌트 관리 테스트"""
        # 컴포넌트 등록
        system_state.register_component('test_model', {'type': 'RF'})
        system_state.register_component('test_defense', {'type': 'Defense'})
        
        # 조회
        model = system_state.get_component('test_model')
        assert model == {'type': 'RF'}
        
        # 목록
        components = system_state.list_components()
        assert 'test_model' in components
        assert 'test_defense' in components
        
        # 등록 해제
        system_state.unregister_component('test_model')
        assert system_state.get_component('test_model') is None
    
    def test_config_management(self, system_state):
        """설정 관리 테스트"""
        # 설정 저장
        system_state.set_config('mode', 'lightweight')
        system_state.set_config('max_packets', 1000)
        
        # 조회
        assert system_state.get_config('mode') == 'lightweight'
        assert system_state.get_config('max_packets') == 1000
        assert system_state.get_config('nonexistent', 'default') == 'default'
        
        # 업데이트
        system_state.update_config({'mode': 'performance', 'debug': True})
        assert system_state.get_config('mode') == 'performance'
        assert system_state.get_config('debug') == True
        
        # 전체 조회
        all_config = system_state.get_all_config()
        assert 'mode' in all_config
        assert 'max_packets' in all_config
    
    def test_summary(self, system_state):
        """시스템 요약 테스트"""
        system_state.increment_threat('high')
        system_state.increment_defense('blocked')
        system_state.update_ml_training(0.9)
        system_state.register_component('test', {})
        
        summary = system_state.get_summary()
        
        assert 'uptime' in summary
        assert 'threat_stats' in summary
        assert 'defense_stats' in summary
        assert 'ml_stats' in summary
        assert 'components' in summary
        assert 'test' in summary['components']
    
    def test_reset_all(self, system_state):
        """전체 리셋 테스트"""
        # 데이터 설정
        system_state.increment_threat('high')
        system_state.increment_defense('blocked')
        system_state.update_ml_training(0.9)
        
        # 리셋
        system_state.reset_all()
        
        # 검증
        assert system_state.get_threat_stats()['high'] == 0
        assert system_state.get_defense_stats()['blocked'] == 0
        assert system_state.get_ml_stats()['total_trained'] == 0
        assert not system_state.is_stop_requested()


class TestThreadSafety:
    """스레드 안전성 테스트"""
    
    def test_concurrent_threat_increment(self, system_state):
        """동시 위협 통계 증가 테스트"""
        import threading
        
        def increment_many():
            for _ in range(100):
                system_state.increment_threat('high')
        
        threads = [threading.Thread(target=increment_many) for _ in range(10)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # 100 * 10 = 1000
        assert system_state.get_threat_stats()['high'] == 1000
    
    def test_concurrent_config_access(self, system_state):
        """동시 설정 접근 테스트"""
        import threading
        
        def set_config():
            for i in range(50):
                system_state.set_config(f'key_{threading.current_thread().name}', i)
        
        threads = [threading.Thread(target=set_config, name=f'thread_{i}') for i in range(5)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # 각 스레드가 독립적으로 설정을 저장했는지 확인
        all_config = system_state.get_all_config()
        for i in range(5):
            assert f'key_thread_{i}' in all_config


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--cov=modules.system_state'])

