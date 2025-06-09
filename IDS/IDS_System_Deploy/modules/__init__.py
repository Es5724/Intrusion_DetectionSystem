"""
IDS 시스템 모듈 패키지
"""
# 모듈 가져오기를 편리하게 하기 위한 초기화 파일
# 이 파일이 존재하면 Python이 디렉토리를 패키지로 인식합니다.

# 버전 정보
__version__ = '1.0.0'

import os
import sys
import subprocess

# 필요한 라이브러리 확인 및 설치
required_packages = [
    'gym', 'torch', 'scapy', 'pandas', 'numpy', 'matplotlib', 'seaborn', 'joblib', 'scikit-learn','PyQt6',     
    'pypcap', 'dpkt', 'netfilterqueue', 'psutil',
    'ipaddress', 'pywin32','pyyaml'
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
from .ml_models import MLTrainingWindow, train_random_forest, add_rf_predictions
from .utils import is_colab, is_admin, run_as_admin, clear_screen, wait_for_enter, syn_scan

# 수리카타 관리자 모듈 임포트 시도
try:
    from .suricata_manager import SuricataManager
    SURICATA_SUPPORT = True
except ImportError:
    print("수리카타 매니저 모듈을 임포트할 수 없습니다. 수리카타가 정상적으로 설치되었는지 확인하세요.")
    SURICATA_SUPPORT = False

# 방어 모듈 마지막으로 임포트 (다른 모듈에 의존성이 있음)
from .defense_mechanism import create_defense_manager, register_to_packet_capture

__all__ = [
    'PacketCapture', 'PacketCaptureCore', 'preprocess_packet_data',
    'NetworkEnv', 'DQNAgent', 'train_rl_agent', 'plot_training_results', 'save_model', 'load_model',
    'MLTrainingWindow', 'train_random_forest', 'add_rf_predictions',
    'is_colab', 'is_admin', 'run_as_admin', 'clear_screen', 'wait_for_enter', 'syn_scan',
    'create_defense_manager', 'register_to_packet_capture'
] 

# 수리카타 지원이 있는 경우에만 export
if SURICATA_SUPPORT:
    __all__.append('SuricataManager') 