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

# 모듈 임포트 전에 필요한 패키지 설치
install_missing_packages()

# 모듈 임포트
from .packet_capture import PacketCapture, PacketCaptureCore, preprocess_packet_data
from .reinforcement_learning import NetworkEnv, DQNAgent, train_rl_agent, plot_training_results, save_model, load_model
from .ml_models import train_random_forest, add_rf_predictions
from .utils import is_colab, is_admin, run_as_admin, clear_screen, wait_for_enter, syn_scan
from .port_scan_detector import PortScanDetector, VulnerabilityScanner, SecurityHardening

# 수리카타 관리자 모듈 임포트 시도
try:
    from .suricata_manager import SuricataManager
    SURICATA_SUPPORT = True
except ImportError:
    print("수리카타 매니저 모듈을 임포트할 수 없습니다. 수리카타가 정상적으로 설치되었는지 확인하세요.")
    SURICATA_SUPPORT = False

# 방어 모듈 마지막으로 임포트 (다른 모듈에 의존성이 있음)
from .defense_mechanism import create_defense_manager, register_to_packet_capture

# 패킷 캡처 모듈
try:
    from .packet_capture import PacketCapture, PacketCaptureCore, preprocess_packet_data
except ImportError:
    print("packet_capture 모듈을 불러올 수 없습니다.")

# 최적화된 패킷 캡처 모듈
try:
    from .optimized_packet_capture_simple import OptimizedPacketCapture
except ImportError:
    try:
        from .optimized_packet_capture import OptimizedPacketCapture
    except ImportError:
        print("최적화된 패킷 캡처 모듈을 불러올 수 없습니다.")

# 머신러닝 모델
try:
    from .ml_models import train_random_forest, add_rf_predictions
except ImportError:
    print("ml_models 모듈을 불러올 수 없습니다.")

# 강화학습 모듈
try:
    from .reinforcement_learning import NetworkEnv, DQNAgent, train_rl_agent, plot_training_results, save_model, load_model
except ImportError:
    print("reinforcement_learning 모듈을 불러올 수 없습니다.")

# Experience Replay Buffer 모듈
try:
    from .experience_replay_buffer import ExperienceReplayBuffer, PrioritizedExperienceReplayBuffer, IDSExperienceReplayBuffer
except ImportError:
    print("experience_replay_buffer 모듈을 불러올 수 없습니다.")

# 유틸리티 함수
try:
    from .utils import is_colab, is_admin, run_as_admin, clear_screen, wait_for_enter, syn_scan
except ImportError:
    print("utils 모듈을 불러올 수 없습니다.")

# 방어 메커니즘
try:
    from .defense_mechanism import DefenseManager, create_defense_manager, register_to_packet_capture
except ImportError:
    print("defense_mechanism 모듈을 불러올 수 없습니다.")

# 위협 알림 시스템
try:
    from .threat_alert_system import ThreatAlertSystem
except ImportError:
    print("threat_alert_system 모듈을 불러올 수 없습니다.")

# 포트 스캔 탐지
try:
    from .port_scan_detector import PortScanDetector, VulnerabilityScanner, SecurityHardening
except ImportError:
    print("port_scan_detector 모듈을 불러올 수 없습니다.")

# 새로운 Conservative RL 시스템 추가
try:
    from .defense_policy_env import DefensePolicyEnv
    from .conservative_rl_agent import ConservativeRLAgent
except ImportError:
    print("Conservative RL 모듈을 불러올 수 없습니다.")
# 모델 최적화
try:
    from .model_optimization import ModelOptimizer, QuantizedDQNAgent, TinyMLConverter
except ImportError:
    print("model_optimization 모듈을 불러올 수 없습니다.")

__all__ = [
    'PacketCapture', 'PacketCaptureCore', 'preprocess_packet_data',
    'OptimizedPacketCapture',
    'train_random_forest', 'add_rf_predictions',
    'NetworkEnv', 'DQNAgent', 'train_rl_agent', 'plot_training_results', 
    'save_model', 'load_model',
    'ExperienceReplayBuffer', 'PrioritizedExperienceReplayBuffer', 'IDSExperienceReplayBuffer',
    'is_colab', 'is_admin', 'run_as_admin', 'clear_screen', 'wait_for_enter', 'syn_scan',
    'DefenseManager', 'create_defense_manager', 'register_to_packet_capture',
    'ThreatAlertSystem',
    'PortScanDetector', 'VulnerabilityScanner', 'SecurityHardening',
    'ModelOptimizer','ConservativeRLAgent', 'DefensePolicyEnv'
] 

# 수리카타 지원이 있는 경우에만 export
if SURICATA_SUPPORT:
    __all__.append('SuricataManager') 