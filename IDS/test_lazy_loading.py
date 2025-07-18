"""
지연 로딩 테스트 스크립트
메모리 사용량과 로딩 시간 개선 효과를 측정합니다.
"""

import sys
import os
import time
import gc
import psutil
import traceback

# 모듈 경로 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_dir, 'modules'))

def measure_memory():
    """현재 프로세스의 메모리 사용량 측정"""
    try:
        process = psutil.Process()
        return process.memory_info().rss / (1024 * 1024)  # MB
    except:
        return 0

def measure_startup_time():
    """시작 시간 측정"""
    return time.time()

def test_immediate_loading():
    """즉시 로딩 방식 테스트 (기존 방식)"""
    print("🔴 즉시 로딩 테스트 시작...")
    
    start_time = measure_startup_time()
    start_memory = measure_memory()
    
    try:
        # 기존 방식: 모든 모듈 즉시 임포트
        print("  - PyTorch/강화학습 모듈 로딩...")
        from reinforcement_learning import NetworkEnv, DQNAgent, train_rl_agent
        pytorch_loaded_time = time.time()
        pytorch_memory = measure_memory()
        
        print("  - 머신러닝 모듈 로딩...")
        from ml_models import MLTrainingWindow, train_random_forest
        ml_loaded_time = time.time()
        ml_memory = measure_memory()
        
        print("  - 시각화 모듈 로딩...")
        import matplotlib.pyplot as plt
        import seaborn as sns
        viz_loaded_time = time.time()
        viz_memory = measure_memory()
        
        end_time = time.time()
        end_memory = measure_memory()
        
        return {
            'total_time': end_time - start_time,
            'pytorch_time': pytorch_loaded_time - start_time,
            'ml_time': ml_loaded_time - pytorch_loaded_time,
            'viz_time': viz_loaded_time - ml_loaded_time,
            'start_memory': start_memory,
            'pytorch_memory': pytorch_memory,
            'ml_memory': ml_memory,
            'viz_memory': viz_memory,
            'end_memory': end_memory,
            'total_memory_used': end_memory - start_memory
        }
        
    except Exception as e:
        print(f"  ❌ 즉시 로딩 오류: {e}")
        return None

def test_lazy_loading():
    """지연 로딩 방식 테스트"""
    print("\n🟢 지연 로딩 테스트 시작...")
    
    start_time = measure_startup_time()
    start_memory = measure_memory()
    
    try:
        # 지연 로딩 시스템 초기화
        from lazy_loading import get_lazy_importer, get_lazy_model_loader, get_lazy_gui_manager
        
        lazy_importer = get_lazy_importer()
        lazy_model_loader = get_lazy_model_loader()
        lazy_gui_manager = get_lazy_gui_manager()
        
        # 모듈 등록 (실제 로딩 없음)
        def _import_reinforcement_learning():
            from reinforcement_learning import NetworkEnv, DQNAgent, train_rl_agent, plot_training_results, save_model, load_model
            return {
                'NetworkEnv': NetworkEnv,
                'DQNAgent': DQNAgent, 
                'train_rl_agent': train_rl_agent,
                'plot_training_results': plot_training_results,
                'save_model': save_model,
                'load_model': load_model
            }
        
        def _import_ml_models():
            from ml_models import MLTrainingWindow, train_random_forest, add_rf_predictions
            return {
                'MLTrainingWindow': MLTrainingWindow,
                'train_random_forest': train_random_forest,
                'add_rf_predictions': add_rf_predictions
            }
        
        def _import_visualization():
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            import seaborn as sns
            return {'plt': plt, 'sns': sns}
        
        lazy_importer.register_module('reinforcement_learning', _import_reinforcement_learning)
        lazy_importer.register_module('ml_models', _import_ml_models)
        lazy_importer.register_module('visualization', _import_visualization)
        
        registration_time = time.time()
        registration_memory = measure_memory()
        
        print(f"  ✅ 모듈 등록 완료 ({registration_time - start_time:.2f}초, {registration_memory - start_memory:.1f}MB)")
        
        # 실제 사용 시점에 로딩
        print("  - 강화학습 모듈 지연 로딩...")
        rl_modules = lazy_importer.get_module('reinforcement_learning')
        rl_loaded_time = time.time()
        rl_memory = measure_memory()
        
        print("  - 머신러닝 모듈 지연 로딩...")
        ml_modules = lazy_importer.get_module('ml_models')
        ml_loaded_time = time.time()
        ml_memory = measure_memory()
        
        print("  - 시각화 모듈 지연 로딩...")
        viz_modules = lazy_importer.get_module('visualization')
        viz_loaded_time = time.time()
        viz_memory = measure_memory()
        
        end_time = time.time()
        end_memory = measure_memory()
        
        # 통계 정보
        lazy_stats = lazy_importer.get_status()
        
        return {
            'total_time': end_time - start_time,
            'registration_time': registration_time - start_time,
            'rl_loading_time': rl_loaded_time - registration_time,
            'ml_loading_time': ml_loaded_time - rl_loaded_time,
            'viz_loading_time': viz_loaded_time - ml_loaded_time,
            'start_memory': start_memory,
            'registration_memory': registration_memory,
            'rl_memory': rl_memory,
            'ml_memory': ml_memory,
            'viz_memory': viz_memory,
            'end_memory': end_memory,
            'total_memory_used': end_memory - start_memory,
            'lazy_stats': lazy_stats
        }
        
    except Exception as e:
        print(f"  ❌ 지연 로딩 오류: {e}")
        traceback.print_exc()
        return None

def test_model_lazy_loading():
    """모델 파일 지연 로딩 테스트"""
    print("\n🟡 모델 파일 지연 로딩 테스트...")
    
    try:
        from lazy_loading import get_lazy_model_loader
        import joblib
        
        model_loader = get_lazy_model_loader()
        
        # 가짜 모델 파일 생성 (테스트용)
        test_model_data = {'test': 'data', 'size': list(range(1000))}
        test_model_path = 'test_model.pkl'
        
        print("  - 테스트 모델 파일 생성...")
        joblib.dump(test_model_data, test_model_path)
        
        def _load_test_model(path):
            return joblib.load(path)
        
        # 모델 등록 (실제 로딩 없음)
        start_memory = measure_memory()
        model_loader.register_model('test_model', test_model_path, _load_test_model)
        register_memory = measure_memory()
        
        print(f"  ✅ 모델 등록 완료 (메모리 증가: {register_memory - start_memory:.1f}MB)")
        
        # 실제 로딩
        print("  - 모델 지연 로딩 실행...")
        model = model_loader.get_model('test_model')
        loaded_memory = measure_memory()
        
        print(f"  ✅ 모델 로딩 완료 (메모리 증가: {loaded_memory - register_memory:.1f}MB)")
        
        # 통계
        stats = model_loader.get_stats()
        
        # 테스트 파일 정리
        if os.path.exists(test_model_path):
            os.remove(test_model_path)
        
        return {
            'register_memory': register_memory - start_memory,
            'loaded_memory': loaded_memory - register_memory,
            'total_memory': loaded_memory - start_memory,
            'stats': stats
        }
        
    except Exception as e:
        print(f"  ❌ 모델 지연 로딩 오류: {e}")
        return None

def compare_startup_scenarios():
    """시작 시나리오 비교"""
    print("\n🔸 시작 시나리오 비교")
    print("=" * 60)
    
    scenarios = [
        ("즉시 로딩 (모든 모듈)", "immediate_full"),
        ("지연 로딩 (등록만)", "lazy_registration"),
        ("지연 로딩 (1개 모듈 사용)", "lazy_single"),
        ("지연 로딩 (모든 모듈 사용)", "lazy_full")
    ]
    
    results = {}
    
    for scenario_name, scenario_key in scenarios:
        print(f"\n📋 시나리오: {scenario_name}")
        print("-" * 40)
        
        # 새로운 프로세스 시뮬레이션을 위한 가비지 컬렉션
        gc.collect()
        
        start_time = time.time()
        start_memory = measure_memory()
        
        if scenario_key == "immediate_full":
            # 즉시 로딩: 모든 모듈
            try:
                from reinforcement_learning import NetworkEnv
                from ml_models import train_random_forest
                import matplotlib.pyplot as plt
                loaded_time = time.time()
                loaded_memory = measure_memory()
                
                results[scenario_key] = {
                    'time': loaded_time - start_time,
                    'memory': loaded_memory - start_memory
                }
                print(f"  ⏱️  시간: {results[scenario_key]['time']:.2f}초")
                print(f"  💾 메모리: {results[scenario_key]['memory']:.1f}MB")
                
            except Exception as e:
                print(f"  ❌ 오류: {e}")
                results[scenario_key] = None
                
        elif scenario_key == "lazy_registration":
            # 지연 로딩: 등록만
            try:
                from lazy_loading import get_lazy_importer
                lazy_importer = get_lazy_importer()
                
                # 등록만 수행
                def dummy_import():
                    return {}
                
                lazy_importer.register_module('test1', dummy_import)
                lazy_importer.register_module('test2', dummy_import)
                lazy_importer.register_module('test3', dummy_import)
                
                register_time = time.time()
                register_memory = measure_memory()
                
                results[scenario_key] = {
                    'time': register_time - start_time,
                    'memory': register_memory - start_memory
                }
                print(f"  ⏱️  시간: {results[scenario_key]['time']:.2f}초")
                print(f"  💾 메모리: {results[scenario_key]['memory']:.1f}MB")
                
            except Exception as e:
                print(f"  ❌ 오류: {e}")
                results[scenario_key] = None
                
        elif scenario_key == "lazy_single":
            # 지연 로딩: 1개 모듈만 사용
            try:
                from lazy_loading import get_lazy_importer
                lazy_importer = get_lazy_importer()
                
                def _import_single():
                    from reinforcement_learning import NetworkEnv
                    return {'NetworkEnv': NetworkEnv}
                
                lazy_importer.register_module('single', _import_single)
                
                # 1개 모듈만 로딩
                module = lazy_importer.get_module('single')
                
                single_time = time.time()
                single_memory = measure_memory()
                
                results[scenario_key] = {
                    'time': single_time - start_time,
                    'memory': single_memory - start_memory
                }
                print(f"  ⏱️  시간: {results[scenario_key]['time']:.2f}초")
                print(f"  💾 메모리: {results[scenario_key]['memory']:.1f}MB")
                
            except Exception as e:
                print(f"  ❌ 오류: {e}")
                results[scenario_key] = None
                
        elif scenario_key == "lazy_full":
            # 지연 로딩: 모든 모듈 사용
            try:
                from lazy_loading import get_lazy_importer
                lazy_importer = get_lazy_importer()
                
                def _import_rl():
                    from reinforcement_learning import NetworkEnv
                    return {'NetworkEnv': NetworkEnv}
                
                def _import_ml():
                    from ml_models import train_random_forest
                    return {'train_random_forest': train_random_forest}
                
                def _import_viz():
                    import matplotlib.pyplot as plt
                    return {'plt': plt}
                
                lazy_importer.register_module('rl', _import_rl)
                lazy_importer.register_module('ml', _import_ml)
                lazy_importer.register_module('viz', _import_viz)
                
                # 모든 모듈 로딩
                rl_module = lazy_importer.get_module('rl')
                ml_module = lazy_importer.get_module('ml')
                viz_module = lazy_importer.get_module('viz')
                
                full_time = time.time()
                full_memory = measure_memory()
                
                results[scenario_key] = {
                    'time': full_time - start_time,
                    'memory': full_memory - start_memory
                }
                print(f"  ⏱️  시간: {results[scenario_key]['time']:.2f}초")
                print(f"  💾 메모리: {results[scenario_key]['memory']:.1f}MB")
                
            except Exception as e:
                print(f"  ❌ 오류: {e}")
                results[scenario_key] = None
    
    return results

def main():
    """메인 테스트 함수"""
    print("🔥 지연 로딩 효과 테스트")
    print("=" * 80)
    
    # 초기 메모리 상태
    initial_memory = measure_memory()
    print(f"📊 초기 메모리 사용량: {initial_memory:.1f}MB")
    
    # 즉시 로딩 테스트
    immediate_result = test_immediate_loading()
    
    # 메모리 정리
    gc.collect()
    time.sleep(1)
    
    # 지연 로딩 테스트  
    lazy_result = test_lazy_loading()
    
    # 모델 지연 로딩 테스트
    model_result = test_model_lazy_loading()
    
    # 시나리오 비교
    scenario_results = compare_startup_scenarios()
    
    # 결과 분석
    print("\n" + "=" * 80)
    print("📊 테스트 결과 분석")
    print("=" * 80)
    
    if immediate_result and lazy_result:
        print("\n🔸 로딩 시간 비교")
        print("-" * 40)
        
        immediate_time = immediate_result['total_time']
        lazy_time = lazy_result['total_time']
        time_difference = immediate_time - lazy_time
        time_improvement = (time_difference / immediate_time) * 100 if immediate_time > 0 else 0
        
        print(f"즉시 로딩 시간: {immediate_time:.2f}초")
        print(f"지연 로딩 시간: {lazy_time:.2f}초")
        print(f"시간 개선: {time_difference:.2f}초 ({time_improvement:.1f}% 단축)")
        
        print("\n🔸 메모리 사용량 비교")
        print("-" * 40)
        
        immediate_memory = immediate_result['total_memory_used']
        lazy_memory = lazy_result['total_memory_used']
        memory_difference = immediate_memory - lazy_memory
        memory_improvement = (memory_difference / immediate_memory) * 100 if immediate_memory > 0 else 0
        
        print(f"즉시 로딩 메모리: {immediate_memory:.1f}MB")
        print(f"지연 로딩 메모리: {lazy_memory:.1f}MB")
        print(f"메모리 절약: {memory_difference:.1f}MB ({memory_improvement:.1f}% 절약)")
        
        print("\n🔸 시작 시 메모리 절약 효과")
        print("-" * 40)
        
        # 등록만 했을 때의 메모리 사용량
        registration_memory = lazy_result['registration_memory'] - lazy_result['start_memory']
        startup_savings = immediate_memory - registration_memory
        startup_improvement = (startup_savings / immediate_memory) * 100 if immediate_memory > 0 else 0
        
        print(f"즉시 로딩 시작 메모리: {immediate_memory:.1f}MB")
        print(f"지연 로딩 시작 메모리: {registration_memory:.1f}MB")
        print(f"시작 시 절약: {startup_savings:.1f}MB ({startup_improvement:.1f}% 절약)")
        
    if model_result:
        print("\n🔸 모델 파일 지연 로딩")
        print("-" * 40)
        print(f"등록 시 메모리: {model_result['register_memory']:.1f}MB")
        print(f"로딩 시 메모리: {model_result['loaded_memory']:.1f}MB")
        print(f"총 메모리 사용: {model_result['total_memory']:.1f}MB")
    
    print("\n🔸 권장사항")
    print("-" * 40)
    
    if immediate_result and lazy_result:
        if time_improvement > 20:
            print("✅ 지연 로딩: 시작 시간 크게 개선 - 적극 권장")
        elif time_improvement > 10:
            print("✅ 지연 로딩: 시작 시간 개선 - 권장")
        elif time_improvement > 0:
            print("🟡 지연 로딩: 시작 시간 소폭 개선")
        else:
            print("🔴 지연 로딩: 시작 시간 개선 효과 없음")
            
        if memory_improvement > 30:
            print("✅ 지연 로딩: 메모리 크게 절약 - 필수 적용")
        elif memory_improvement > 15:
            print("✅ 지연 로딩: 메모리 절약 효과 있음 - 권장")
        elif memory_improvement > 0:
            print("🟡 지연 로딩: 메모리 소폭 절약")
        else:
            print("🔴 지연 로딩: 메모리 절약 효과 없음")
            
        if startup_improvement > 50:
            print("✅ 시작 시 메모리 절약: 매우 효과적 - 사용자 경험 크게 개선")
        elif startup_improvement > 30:
            print("✅ 시작 시 메모리 절약: 효과적 - 빠른 시작 가능")
        else:
            print("🟡 시작 시 메모리 절약: 제한적 효과")

if __name__ == "__main__":
    main() 