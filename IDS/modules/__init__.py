"""
IPS 시스템 모듈 패키지

이 패키지는 침입 방지 시스템의 핵심 모듈들을 포함합니다.
"""
# 모듈 가져오기를 편리하게 하기 위한 초기화 파일
# 이 파일이 존재하면 Python이 디렉토리를 패키지로 인식합니다.

# 버전 정보
__version__ = '1.0.0'

import os
import sys
import subprocess

# 필요한 라이브러리 확인 및 설치 (Windows에서 문제가 되는 패키지 제외)
required_packages = [
    'scapy', 'pandas', 'numpy', 'matplotlib', 'seaborn', 'joblib', 'scikit-learn',
    'psutil', 'pyyaml'
]

def install_missing_packages():
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"{package} 모듈이 설치되어 있지 않습니다. 설치 중...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print(f"{package} 모듈 설치 완료!")

# 모듈 임포트 전에 필요한 패키지 설치 (필요시에만 활성화)
# install_missing_packages()  # 주석 처리: 이미 설치된 환경에서는 불필요

# ====================================================================
# 핵심 모듈 임포트 (항상 사용)
# ====================================================================
# 방어 메커니즘 (필수)
from .defense_mechanism import DefenseManager, create_defense_manager, register_to_packet_capture

# 머신러닝 모델 (필수)
from .ml_models import train_random_forest, add_rf_predictions

# 유틸리티 함수 (필수)
from .utils import is_colab, is_admin, run_as_admin, clear_screen, wait_for_enter

# ====================================================================
# 선택적 모듈 임포트 (기능별)
# ====================================================================

# 패킷 캡처 모듈 (필수)
try:
    from .packet_capture import PacketCaptureCore
    PACKET_CAPTURE_AVAILABLE = True
except ImportError:
    print("❌ packet_capture 모듈을 불러올 수 없습니다.")
    PACKET_CAPTURE_AVAILABLE = False

# 최적화된 패킷 캡처 모듈 (필수)
try:
    from .optimized_packet_capture_simple import OptimizedPacketCapture
    OPTIMIZED_CAPTURE_AVAILABLE = True
except ImportError:
    try:
        from .optimized_packet_capture import OptimizedPacketCapture
        OPTIMIZED_CAPTURE_AVAILABLE = True
    except ImportError:
        print("❌ 최적화된 패킷 캡처 모듈을 불러올 수 없습니다.")
        OPTIMIZED_CAPTURE_AVAILABLE = False

# Experience Replay Buffer 모듈 (Conservative RL에서 사용)
try:
    from .experience_replay_buffer import ExperienceReplayBuffer, PrioritizedExperienceReplayBuffer, IDSExperienceReplayBuffer
    REPLAY_BUFFER_AVAILABLE = True
except ImportError:
    print("⚠️ experience_replay_buffer 모듈을 불러올 수 없습니다.")
    REPLAY_BUFFER_AVAILABLE = False

# 포트 스캔 및 취약점 탐지 (필수)
try:
    from .port_scan_detector import PortScanDetector, VulnerabilityScanner, SecurityHardening
    PORT_SCAN_AVAILABLE = True
except ImportError:
    print("❌ port_scan_detector 모듈을 불러올 수 없습니다.")
    PORT_SCAN_AVAILABLE = False

# 수리카타 관리자 (선택적)
try:
    from .suricata_manager import SuricataManager
    SURICATA_SUPPORT = True
except ImportError:
    print("⚠️ 수리카타 매니저 모듈을 불러올 수 없습니다. (선택적 기능)")
    SURICATA_SUPPORT = False

# ====================================================================
# Conservative RL 시스템 (반응형 AI의 핵심)
# ====================================================================
try:
    from .defense_policy_env import DefensePolicyEnv
    from .conservative_rl_agent import ConservativeRLAgent
    from .ope_evaluator import OPEEvaluator
    CONSERVATIVE_RL_AVAILABLE = True
except ImportError:
    print("❌ Conservative RL 모듈을 불러올 수 없습니다.")
    CONSERVATIVE_RL_AVAILABLE = False

# 모델 최적화 (선택적)
try:
    from .model_optimization import ModelOptimizer
    MODEL_OPTIMIZER_AVAILABLE = True
except ImportError:
    print("⚠️ model_optimization 모듈을 불러올 수 없습니다. (선택적 기능)")
    MODEL_OPTIMIZER_AVAILABLE = False

# ====================================================================
# 반응형 AI 통합 모듈 (자동 취약점 진단의 핵심)
# ====================================================================
try:
    from .rl_state_extractor import RLStateExtractor, get_state_extractor
    from .realtime_reward_calculator import RealtimeRewardCalculator, get_reward_calculator
    from .online_rl_trainer import OnlineRLTrainer, RealTimeRLIntegrator, get_online_trainer, get_rl_integrator
    from .rl_defense_wrapper import RLDefenseWrapper, create_rl_defense_system
    from .vulnerability_auto_scanner import VulnerabilityAutoScanner, get_auto_scanner
    from .vulnerability_priority_analyzer import VulnerabilityPriorityAnalyzer, get_priority_analyzer, CVEDatabase
    INTEGRATED_MODULES_AVAILABLE = True
except ImportError as e:
    print(f"❌ 통합 모듈을 불러올 수 없습니다: {e}")
    INTEGRATED_MODULES_AVAILABLE = False

# ====================================================================
# 시스템 관리 모듈 
# ====================================================================
try:
    from .system_state import SystemState, ThreatStatistics, DefenseStatistics, MLStatistics, get_system_state
    from .thread_manager import ThreadManager, ThreadStatus, ManagedThread, get_thread_manager
    from .ips_agent import IPSAgent, create_ips_agent
    SYSTEM_MANAGEMENT_AVAILABLE = True
except ImportError as e:
    print(f"❌ 시스템 관리 모듈을 불러올 수 없습니다: {e}")
    SYSTEM_MANAGEMENT_AVAILABLE = False

# 설정 파일 로더 
try:
    from .config_loader import ConfigLoader, get_config, migrate_json_to_yaml
    CONFIG_LOADER_AVAILABLE = True
except ImportError as e:
    print(f"❌ 설정 로더 모듈을 불러올 수 없습니다: {e}")
    CONFIG_LOADER_AVAILABLE = False

__all__ = [
    # ========== 핵심 모듈 ==========
    
    # 방어 메커니즘 (필수)
    'DefenseManager', 'create_defense_manager', 'register_to_packet_capture',
    
    # 머신러닝 (필수)
    'train_random_forest', 'add_rf_predictions',
    
    # 유틸리티 (필수)
    'is_colab', 'is_admin', 'run_as_admin', 'clear_screen', 'wait_for_enter',
    
    # ========== 패킷 처리 ==========
    
    # 패킷 캡처
    'PacketCaptureCore',
    'OptimizedPacketCapture',
    
    # ========== 강화학습 시스템 ==========
    
    # Conservative RL 시스템 (현재 사용 중)
    'ConservativeRLAgent', 'DefensePolicyEnv', 'OPEEvaluator',
    
    # Experience Replay Buffer
    'ExperienceReplayBuffer', 'PrioritizedExperienceReplayBuffer', 'IDSExperienceReplayBuffer',
    
    # ========== 보안 기능 ==========
    
    # 포트 스캔 및 취약점 탐지
    'PortScanDetector', 'VulnerabilityScanner', 'SecurityHardening',
]

# ========== 조건부 모듈 (선택적 기능) ==========

# 반응형 AI 통합 모듈
if INTEGRATED_MODULES_AVAILABLE:
    __all__.extend([
        # RL 통합 시스템
        'RLStateExtractor', 'get_state_extractor',
        'RealtimeRewardCalculator', 'get_reward_calculator',
        'OnlineRLTrainer', 'RealTimeRLIntegrator', 'get_online_trainer', 'get_rl_integrator',
        'RLDefenseWrapper', 'create_rl_defense_system',
        
        # 자동 취약점 진단
        'VulnerabilityAutoScanner', 'get_auto_scanner',
        'VulnerabilityPriorityAnalyzer', 'get_priority_analyzer', 'CVEDatabase'
    ])

# 시스템 관리 모듈 (P0 개선)
if SYSTEM_MANAGEMENT_AVAILABLE:
    __all__.extend([
        # 시스템 상태 관리
        'SystemState', 'ThreatStatistics', 'DefenseStatistics', 'MLStatistics', 'get_system_state',
        
        # 스레드 관리
        'ThreadManager', 'ThreadStatus', 'ManagedThread', 'get_thread_manager',
        
        # IPS 에이전트 클래스
        'IPSAgent', 'create_ips_agent'
    ])

# 설정 로더 (P1 개선)
if CONFIG_LOADER_AVAILABLE:
    __all__.extend([
        'ConfigLoader', 'get_config', 'migrate_json_to_yaml'
    ])

# 모델 최적화 (선택적)
if MODEL_OPTIMIZER_AVAILABLE:
    __all__.append('ModelOptimizer')

# 수리카타 지원 (선택적)
if SURICATA_SUPPORT:
    __all__.append('SuricataManager')

