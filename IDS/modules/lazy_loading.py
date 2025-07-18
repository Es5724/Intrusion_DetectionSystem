"""
지연 로딩 모듈 - 메모리 최적화를 위한 지연 초기화
대용량 라이브러리와 모델들을 실제 사용 시점에 로딩하여 메모리 사용량 최적화
"""

import threading
import time
import logging
import os
import sys
import importlib
from typing import Dict, Any, Optional, Callable

logger = logging.getLogger('LazyLoading')


class LazyImporter:
    """
    모듈 지연 임포트를 위한 클래스
    대용량 라이브러리들을 실제 사용 시점에 임포트하여 메모리 절약
    """
    
    def __init__(self):
        self._modules = {}
        self._loading_status = {}
        self._lock = threading.Lock()
        self.load_times = {}
        
    def register_module(self, module_name: str, import_func: Callable, dependencies: list = None):
        """
        지연 로딩할 모듈 등록
        
        Args:
            module_name: 모듈 식별 이름
            import_func: 실제 임포트를 수행하는 함수
            dependencies: 의존성 모듈 리스트
        """
        with self._lock:
            self._modules[module_name] = {
                'import_func': import_func,
                'dependencies': dependencies or [],
                'loaded': False,
                'module': None
            }
            self._loading_status[module_name] = 'not_loaded'
    
    def get_module(self, module_name: str):
        """모듈 가져오기 (필요시 로딩)"""
        with self._lock:
            if module_name not in self._modules:
                raise ValueError(f"모듈 '{module_name}'이 등록되지 않았습니다.")
            
            module_info = self._modules[module_name]
            
            # 이미 로드된 경우
            if module_info['loaded']:
                return module_info['module']
            
            # 로딩 중인 경우 대기
            if self._loading_status[module_name] == 'loading':
                return self._wait_for_loading(module_name)
            
            # 의존성 모듈들 먼저 로딩
            for dep in module_info['dependencies']:
                if dep in self._modules:
                    self.get_module(dep)
            
            # 실제 로딩 수행
            return self._load_module(module_name)
    
    def _load_module(self, module_name: str):
        """실제 모듈 로딩 수행"""
        self._loading_status[module_name] = 'loading'
        start_time = time.time()
        
        try:
            logger.info(f"지연 로딩 시작: {module_name}")
            module_info = self._modules[module_name]
            
            # 임포트 함수 실행
            result = module_info['import_func']()
            
            # 로딩 완료 처리
            module_info['module'] = result
            module_info['loaded'] = True
            self._loading_status[module_name] = 'loaded'
            
            load_time = time.time() - start_time
            self.load_times[module_name] = load_time
            
            logger.info(f"지연 로딩 완료: {module_name} ({load_time:.2f}초)")
            return result
            
        except Exception as e:
            self._loading_status[module_name] = 'error'
            logger.error(f"지연 로딩 실패: {module_name} - {e}")
            raise
    
    def _wait_for_loading(self, module_name: str, timeout: int = 30):
        """다른 스레드의 로딩 완료 대기"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status = self._loading_status[module_name]
            if status == 'loaded':
                return self._modules[module_name]['module']
            elif status == 'error':
                raise RuntimeError(f"모듈 '{module_name}' 로딩 실패")
            
            time.sleep(0.1)
        
        raise TimeoutError(f"모듈 '{module_name}' 로딩 타임아웃")
    
    def get_status(self):
        """로딩 상태 및 통계 반환"""
        with self._lock:
            stats = {
                'total_modules': len(self._modules),
                'loaded_modules': sum(1 for m in self._modules.values() if m['loaded']),
                'loading_times': self.load_times.copy(),
                'status_by_module': self._loading_status.copy()
            }
            return stats
    
    def preload_module(self, module_name: str):
        """특정 모듈 미리 로딩"""
        threading.Thread(target=self.get_module, args=(module_name,), daemon=True).start()


class LazyModelLoader:
    """
    머신러닝 모델 파일들의 지연 로딩을 위한 클래스
    모델 파일들을 실제 사용 시점에 로딩하여 메모리 절약
    """
    
    def __init__(self):
        self._models = {}
        self._lock = threading.Lock()
        self.load_times = {}
        
    def register_model(self, model_name: str, file_path: str, loader_func: Callable):
        """
        지연 로딩할 모델 등록
        
        Args:
            model_name: 모델 식별 이름
            file_path: 모델 파일 경로
            loader_func: 실제 로딩을 수행하는 함수
        """
        with self._lock:
            self._models[model_name] = {
                'file_path': file_path,
                'loader_func': loader_func,
                'loaded': False,
                'model': None,
                'file_size': 0
            }
            
            # 파일 크기 확인
            if os.path.exists(file_path):
                self._models[model_name]['file_size'] = os.path.getsize(file_path)
    
    def get_model(self, model_name: str):
        """모델 가져오기 (필요시 로딩)"""
        with self._lock:
            if model_name not in self._models:
                raise ValueError(f"모델 '{model_name}'이 등록되지 않았습니다.")
            
            model_info = self._models[model_name]
            
            # 이미 로드된 경우
            if model_info['loaded']:
                return model_info['model']
            
            # 파일 존재 확인
            if not os.path.exists(model_info['file_path']):
                logger.warning(f"모델 파일이 없습니다: {model_info['file_path']}")
                return None
            
            # 실제 로딩 수행
            return self._load_model(model_name)
    
    def _load_model(self, model_name: str):
        """실제 모델 로딩 수행"""
        start_time = time.time()
        
        try:
            model_info = self._models[model_name]
            file_size_mb = model_info['file_size'] / (1024 * 1024)
            
            logger.info(f"모델 지연 로딩 시작: {model_name} ({file_size_mb:.1f}MB)")
            
            # 로더 함수 실행
            model = model_info['loader_func'](model_info['file_path'])
            
            # 로딩 완료 처리
            model_info['model'] = model
            model_info['loaded'] = True
            
            load_time = time.time() - start_time
            self.load_times[model_name] = load_time
            
            logger.info(f"모델 지연 로딩 완료: {model_name} ({load_time:.2f}초)")
            return model
            
        except Exception as e:
            logger.error(f"모델 로딩 실패: {model_name} - {e}")
            return None
    
    def unload_model(self, model_name: str):
        """모델 메모리에서 해제"""
        with self._lock:
            if model_name in self._models and self._models[model_name]['loaded']:
                self._models[model_name]['model'] = None
                self._models[model_name]['loaded'] = False
                logger.info(f"모델 메모리 해제: {model_name}")
    
    def get_stats(self):
        """모델 로딩 통계 반환"""
        with self._lock:
            stats = {
                'total_models': len(self._models),
                'loaded_models': sum(1 for m in self._models.values() if m['loaded']),
                'total_file_size': sum(m['file_size'] for m in self._models.values()),
                'loaded_file_size': sum(m['file_size'] for m in self._models.values() if m['loaded']),
                'loading_times': self.load_times.copy()
            }
            return stats


class LazyGUIManager:
    """
    GUI 컴포넌트들의 지연 생성을 위한 클래스
    GUI 컴포넌트들을 실제 사용 시점에 생성하여 메모리 절약
    """
    
    def __init__(self):
        self._components = {}
        self._lock = threading.Lock()
        self.creation_times = {}
    
    def register_component(self, component_name: str, creator_func: Callable):
        """
        지연 생성할 GUI 컴포넌트 등록
        
        Args:
            component_name: 컴포넌트 식별 이름
            creator_func: 실제 생성을 수행하는 함수
        """
        with self._lock:
            self._components[component_name] = {
                'creator_func': creator_func,
                'created': False,
                'component': None
            }
    
    def get_component(self, component_name: str):
        """컴포넌트 가져오기 (필요시 생성)"""
        with self._lock:
            if component_name not in self._components:
                raise ValueError(f"컴포넌트 '{component_name}'이 등록되지 않았습니다.")
            
            comp_info = self._components[component_name]
            
            # 이미 생성된 경우
            if comp_info['created']:
                return comp_info['component']
            
            # 실제 생성 수행
            return self._create_component(component_name)
    
    def _create_component(self, component_name: str):
        """실제 컴포넌트 생성 수행"""
        start_time = time.time()
        
        try:
            logger.info(f"GUI 컴포넌트 지연 생성 시작: {component_name}")
            
            comp_info = self._components[component_name]
            component = comp_info['creator_func']()
            
            # 생성 완료 처리
            comp_info['component'] = component
            comp_info['created'] = True
            
            creation_time = time.time() - start_time
            self.creation_times[component_name] = creation_time
            
            logger.info(f"GUI 컴포넌트 지연 생성 완료: {component_name} ({creation_time:.2f}초)")
            return component
            
        except Exception as e:
            logger.error(f"GUI 컴포넌트 생성 실패: {component_name} - {e}")
            return None
    
    def destroy_component(self, component_name: str):
        """컴포넌트 제거"""
        with self._lock:
            if component_name in self._components and self._components[component_name]['created']:
                comp = self._components[component_name]['component']
                if hasattr(comp, 'destroy'):
                    comp.destroy()
                elif hasattr(comp, 'close'):
                    comp.close()
                
                self._components[component_name]['component'] = None
                self._components[component_name]['created'] = False
                logger.info(f"GUI 컴포넌트 제거: {component_name}")


# 전역 인스턴스들
_lazy_importer = None
_lazy_model_loader = None
_lazy_gui_manager = None


def get_lazy_importer():
    """전역 LazyImporter 인스턴스 반환"""
    global _lazy_importer
    if _lazy_importer is None:
        _lazy_importer = LazyImporter()
    return _lazy_importer


def get_lazy_model_loader():
    """전역 LazyModelLoader 인스턴스 반환"""
    global _lazy_model_loader
    if _lazy_model_loader is None:
        _lazy_model_loader = LazyModelLoader()
    return _lazy_model_loader


def get_lazy_gui_manager():
    """전역 LazyGUIManager 인스턴스 반환"""
    global _lazy_gui_manager
    if _lazy_gui_manager is None:
        _lazy_gui_manager = LazyGUIManager()
    return _lazy_gui_manager 