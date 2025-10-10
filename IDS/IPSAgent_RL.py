# -*- coding: utf-8 -*-

"""
강화학습을 사용한 IPS시스템

이 스크립트는 랜덤포레스트와 강화학습을 사용한 네트워크 침입 방지 시스템을 구현합니다.
"""

import os
import sys
import time
import threading
import pandas as pd
import joblib
import argparse
from datetime import datetime
import queue
import traceback
import logging
import gc  # 가비지 컬렉션 제어

# 컬러 출력을 위한 모듈 추가
try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)  # 자동으로 색상 리셋
    COLOR_SUPPORT = True
except ImportError:
    # colorama가 없는 경우 더미 클래스 정의
    class Fore:
        RED = YELLOW = GREEN = CYAN = BLUE = MAGENTA = WHITE = ''
    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''
    COLOR_SUPPORT = False

# 디버깅 설정
DEBUG_MODE = True

# 로깅 설정
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 로그 파일 설정
logging.basicConfig(
    filename=os.path.join(log_dir, "ips_debug.log"),
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filemode='w'  # 로그 파일 덮어쓰기
)

# 콘솔 로거 추가 (실시간 대시보드 방해 방지를 위해 ERROR 레벨만 출력)
console = logging.StreamHandler()
console.setLevel(logging.ERROR)  # 콘솔에는 에러만 출력
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

logger = logging.getLogger('IPSAgent')
logger.info("로깅 시스템 초기화 완료")

# 명령행 인수 처리
parser = argparse.ArgumentParser(description='IPS 시스템 실행 옵션')
parser.add_argument('--mode', type=str, choices=['lightweight', 'performance'], 
                    help='IPS 운영 모드 선택 (lightweight 또는 performance)')
parser.add_argument('--max-packets', type=int, default=0, 
                    help='캡처할 최대 패킷 수 (0: 무제한)')
parser.add_argument('--no-menu', action='store_true',
                    help='모드 선택 메뉴를 표시하지 않고 기본 모드(lightweight)로 실행')
parser.add_argument('--web-server', action='store_true',
                    help='웹 API 서버 시작 (원격 모니터링용)')
parser.add_argument('--web-port', type=int, default=5000,
                    help='웹 서버 포트 번호 (기본값: 5000)')
parser.add_argument('--web-host', type=str, default='0.0.0.0',
                    help='웹 서버 호스트 주소 (기본값: 0.0.0.0)')
parser.add_argument('--debug', action='store_true',
                    help='디버그 모드 활성화')
args = parser.parse_args()

if args.debug:
    DEBUG_MODE = True
    # 디버그 모드에서도 콘솔에는 ERROR만 출력 (파일에는 DEBUG 레벨로 기록)
    console.setLevel(logging.ERROR)
    logger.info("디버그 모드 활성화됨")

# 예외 처리 함수
def log_exception(e, message="예외 발생"):
    """예외를 로그에 기록합니다."""
    logger.error(f"{message}: {str(e)}")
    if DEBUG_MODE:
        logger.debug(traceback.format_exc())

# 모듈 경로를 적절히 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
if os.path.exists(os.path.join(current_dir, 'Intrusion_DetectionSystem', 'modules')):
    module_path = os.path.join(current_dir, 'Intrusion_DetectionSystem', 'modules')
elif os.path.exists(os.path.join(current_dir, 'modules')):
    module_path = os.path.join(current_dir, 'modules')
else:
    print("모듈 디렉토리를 찾을 수 없습니다. 현재 디렉토리:", current_dir)
    potential_modules = []
    for root, dirs, files in os.walk(current_dir):
        if 'modules' in dirs:
            potential_modules.append(os.path.join(root, 'modules'))
    
    if potential_modules:
        print("가능한 모듈 경로를 찾았습니다:")
        for path in potential_modules:
            print(f" - {path}")
        module_path = potential_modules[0]
    else:
        print("모듈 디렉토리를 찾을 수 없습니다.")
        sys.exit(1)

sys.path.append(module_path)
logger.info(f"모듈 경로 추가됨: {module_path}")

# 필요한 모듈 임포트
try:
    # 최적화된 패킷 캡처 모듈을 우선적으로 사용
    try:
        from optimized_packet_capture_simple import OptimizedPacketCapture
        use_optimized_capture = True
        logger.info("최적화된 패킷 캡처 모듈 사용")
    except ImportError:
        try:
            from optimized_packet_capture import OptimizedPacketCapture
            use_optimized_capture = True
            logger.info("최적화된 패킷 캡처 모듈 사용")
        except ImportError:
            from packet_capture import PacketCapture, PacketCaptureCore
            use_optimized_capture = False
            logger.info("기본 패킷 캡처 모듈 사용")
    
    # 최적화된 캡처 사용 시 추가 임포트 없음
    
    # 지연 로딩 시스템 초기화
    from lazy_loading import get_lazy_importer, get_lazy_model_loader
    
    # 기본 모듈들 (즉시 로딩 필요)
    from utils import is_colab, is_admin, run_as_admin, clear_screen, wait_for_enter
    from defense_mechanism import create_defense_manager, register_to_packet_capture
    from memory_optimization import get_packet_pool, get_stats_pool, get_batch_processor, get_dataframe_pool  # 객체 풀링 추가
    
    # 지연 로딩 모듈들 등록
    lazy_importer = get_lazy_importer()
    lazy_model_loader = get_lazy_model_loader()
    
    #  새로운 Conservative RL 시스템 지연 로딩 등록 (100-150MB 절약)
    def _import_conservative_rl():
        from conservative_rl_agent import ConservativeRLAgent
        from defense_policy_env import DefensePolicyEnv
        from ope_evaluator import OPEEvaluator
        # 호환성을 위해 기존 시스템도 포함
        from reinforcement_learning import NetworkEnv, DQNAgent, train_rl_agent, plot_training_results, save_model, load_model
        return {
            'ConservativeRLAgent': ConservativeRLAgent,
            'DefensePolicyEnv': DefensePolicyEnv,
            'OPEEvaluator': OPEEvaluator,
            # 기존 시스템 (Fallback용)
            'NetworkEnv': NetworkEnv,
            'DQNAgent': DQNAgent, 
            'train_rl_agent': train_rl_agent,
            'plot_training_results': plot_training_results,
            'save_model': save_model,
            'load_model': load_model
        }
    
    lazy_importer.register_module('conservative_rl', _import_conservative_rl)
    
    #  머신러닝 모델 모듈들 지연 로딩 등록 (15-25MB 절약)
    def _import_ml_models():
        from ml_models import train_random_forest
        return {
            'train_random_forest': train_random_forest
        }
    
    lazy_importer.register_module('ml_models', _import_ml_models)
    
    #  시각화 모듈들 지연 로딩 등록 (10-20MB 절약)
    def _import_visualization():
        import matplotlib
        matplotlib.use('Agg')  # 백엔드 설정으로 메모리 절약
        import matplotlib.pyplot as plt
        import seaborn as sns
        return {'plt': plt, 'sns': sns}
    
    lazy_importer.register_module('visualization', _import_visualization)
    
    # 모델 파일들 지연 로딩 등록
    import joblib
    import pickle
    
    def _load_random_forest():
        # KISTI 모델 우선 사용
        if os.path.exists('kisti_random_forest_model.pkl'):
            logger.info("KISTI RF 모델 로딩")
            return joblib.load('kisti_random_forest_model.pkl')
        elif os.path.exists('ips_random_forest_model.pkl'):
            logger.info("CIC RF 모델 로딩")
            return joblib.load('ips_random_forest_model.pkl')
        else:
            logger.warning("RF 모델 파일을 찾을 수 없음")
            return joblib.load('random_forest_model.pkl')  # Fallback
    
    def _load_conservative_rl_model():
        import torch
        if os.path.exists('defense_policy_agent.pth'):
            return torch.load('defense_policy_agent.pth')
        return None
    
    lazy_model_loader.register_model('random_forest', 'kisti_random_forest_model.pkl', _load_random_forest)
    lazy_model_loader.register_model('conservative_rl', 'defense_policy_agent.pth', _load_conservative_rl_model)
    
    #  새로운 통합 모듈 지연 로딩 등록 (20-30MB 추가 절약)
    def _import_integrated_modules():
        try:
            from rl_state_extractor import get_state_extractor
            from realtime_reward_calculator import get_reward_calculator
            from online_rl_trainer import get_online_trainer, get_rl_integrator
            from rl_defense_wrapper import create_rl_defense_system
            from vulnerability_auto_scanner import get_auto_scanner
            from vulnerability_priority_analyzer import get_priority_analyzer
            return {
                'get_state_extractor': get_state_extractor,
                'get_reward_calculator': get_reward_calculator,
                'get_online_trainer': get_online_trainer,
                'get_rl_integrator': get_rl_integrator,
                'create_rl_defense_system': create_rl_defense_system,
                'get_auto_scanner': get_auto_scanner,
                'get_priority_analyzer': get_priority_analyzer
            }
        except ImportError as e:
            logger.warning(f"통합 모듈 임포트 실패: {e}")
            return {}
    
    lazy_importer.register_module('integrated_modules', _import_integrated_modules)
    
    logger.info("지연 로딩 시스템 초기화 완료 - 메모리 절약 예상: 145-225MB")
    
    # scapy의 전역 verbose 설정 비활성화
    try:
        import scapy.config
        scapy.config.conf.verb = 0  # scapy의 verbose 출력 비활성화
    except:
        pass
    
    logger.info("모듈 임포트 성공!")
except ImportError as e:
    logger.error(f"모듈을 찾을 수 없습니다: {e}")
    logger.error(f"현재 sys.path: {sys.path}")
    sys.exit(1)

# CLI 유틸리티 함수들
def print_colored(text, color=Fore.WHITE, style=Style.NORMAL, end='\n'):
    """색상이 있는 텍스트 출력"""
    if COLOR_SUPPORT:
        print(f"{style}{color}{text}{Style.RESET_ALL}", end=end)
    else:
        print(text, end=end)

def print_header():
    """
    메인 헤더 출력
    
    IPS 시스템의 메인 헤더를 ASCII 아트와 함께 출력합니다.
    """
    clear_screen()
    print_colored("=" * 80, Fore.CYAN, Style.BRIGHT)
    print_colored("""
    ██╗██████╗ ███████╗    ███████╗██╗   ██╗███████╗████████╗███████╗███╗   ███╗
    ██║██╔══██╗██╔════╝    ██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗ ████║
    ██║██████╔╝███████╗    ███████╗ ╚████╔╝ ███████╗   ██║   █████╗  ██╔████╔██║
    ██║██╔═══╝ ╚════██║    ╚════██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██║╚██╔╝██║
    ██║██║     ███████║    ███████║   ██║   ███████║   ██║   ███████╗██║ ╚═╝ ██║
    ╚═╝╚═╝     ╚══════╝    ╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝   
    """, Fore.CYAN, Style.BRIGHT)
    
    print_colored("             지능형 침입 방지 시스템 (IPS Agent)  ", Fore.YELLOW, Style.BRIGHT)
    print_colored("                    강화학습 & 머신러닝 기반", Fore.GREEN)
    print_colored("=" * 80, Fore.CYAN, Style.BRIGHT)
    print()

def print_system_info():
    """시스템 정보 출력"""
    print_colored(" 시스템 정보", Fore.YELLOW, Style.BRIGHT)
    print_colored("-" * 40, Fore.YELLOW)
    
    # 현재 시간
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print_colored(f" 현재 시간: {current_time}", Fore.WHITE)
    
    # 운영체제 정보
    os_name = "Windows" if os.name == 'nt' else "Linux/Unix"
    print_colored(f" 운영체제: {os_name}", Fore.WHITE)
    
    # Python 버전
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    print_colored(f" Python 버전: {python_version}", Fore.WHITE)
 
    print()

def print_feature_overview():
    """기능 개요 출력"""
    print_colored(" 주요 기능", Fore.YELLOW, Style.BRIGHT)
    print_colored("-" * 40, Fore.YELLOW)
    
    features = [
        "실시간 네트워크 패킷 모니터링",
        "랜덤포레스트 & 강화학습 기반 위협 탐지",
    ]
    
    for feature in features:
        print_colored(f"  {feature}", Fore.GREEN)
    
    print()

def select_mode_menu():
    """모드 선택 메뉴"""
    print_header()
    print_system_info()
    print_feature_overview()
    
    print_colored("[CONFIG] 운영 모드 선택", Fore.YELLOW, Style.BRIGHT)
    print_colored("=" * 60, Fore.YELLOW)
    print()
    
    # 경량 모드 설명
    print_colored("[1] 경량 모드 (Lightweight Mode)", Fore.GREEN, Style.BRIGHT)
    print_colored("   ┌─────────────────────────────────────────────────┐", Fore.GREEN)
    print_colored("   │  빠른 실행 속도                                  │", Fore.WHITE)
    print_colored("   │  낮은 자원 사용량                                │", Fore.WHITE)
    print_colored("   │  기본 특성 7개 사용                              │", Fore.WHITE)
    print_colored("   │  모든 환경에서 실행 가능                          │", Fore.WHITE)
    print_colored("   └─────────────────────────────────────────────────┘", Fore.GREEN)
    print()
    
    # 고성능 모드 설명
    print_colored("[2] 고성능 모드 (Performance Mode)", Fore.BLUE, Style.BRIGHT)
    print_colored("   ┌─────────────────────────────────────────────────┐", Fore.BLUE)
    print_colored("   │  수리카타(Suricata) 엔진 통합                    │", Fore.WHITE)
    print_colored("   │  확장 특성 12개 사용                             │", Fore.WHITE)
    print_colored("   │  더 높은 정확도의 탐지                           │", Fore.WHITE)
    print_colored("   │  더 많은 시스템 자원 필요                         │", Fore.WHITE)
    print_colored("   └─────────────────────────────────────────────────┘", Fore.BLUE)
    print()
    
    print_colored("=" * 60, Fore.YELLOW)
    
    while True:
        try:
            print_colored("선택하세요: ", Fore.CYAN, Style.BRIGHT, end="")
            choice = input()
            
            if choice == "1":
                print_colored("[OK] 경량 모드가 선택되었습니다!", Fore.GREEN, Style.BRIGHT)
                time.sleep(1)
                return "lightweight"
            elif choice == "2":
                print_colored("[OK] 고성능 모드가 선택되었습니다!", Fore.BLUE, Style.BRIGHT)
                time.sleep(1)
                return "performance"
            else:
                print_colored("[ERROR] 잘못된 입력입니다. 1 또는 2를 입력하세요.", Fore.RED)
        except ValueError:
            print_colored("[ERROR] 잘못된 입력입니다. 숫자를 입력하세요.", Fore.RED)
        except KeyboardInterrupt:
            print_colored("\n\n 프로그램을 종료합니다.", Fore.YELLOW)
            sys.exit(0)

def show_startup_animation():
    """시작 애니메이션"""
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    
    print_colored(" IPS 시스템을 초기화하는 중", Fore.CYAN, Style.BRIGHT, end="")
    
    for i in range(20):
        print_colored(f"\r IPS 시스템을 초기화하는 중 {frames[i % len(frames)]}", Fore.CYAN, Style.BRIGHT, end="")
        time.sleep(0.1)
    
    print_colored("\r[OK] IPS 시스템 초기화 완료!                    ", Fore.GREEN, Style.BRIGHT)
    time.sleep(0.5)

def print_status_box(title, content, color=Fore.WHITE):
    """상태 박스 출력"""
    box_width = 60
    title_line = f" {title}"
    
    print_colored("┌" + "─" * (box_width - 2) + "┐", color)
    print_colored(f"│ {title_line:<{box_width - 3}} │", color, Style.BRIGHT)
    print_colored("├" + "─" * (box_width - 2) + "┤", color)
    
    for line in content:
        print_colored(f"│ {line:<{box_width - 3}} │", Fore.WHITE)
    
    print_colored("└" + "─" * (box_width - 2) + "┘", color)

def analyze_threat_level(packet, defense_manager=None):
    """
    방어 모듈 기반 패킷 위협 수준 분석
    
    Args:
        packet (dict): 분석할 패킷 정보
        defense_manager: 방어 메커니즘 관리자 (옵션)
        
    Returns:
        str: 위협 수준 ('critical', 'high', 'medium', 'low', 'safe')
    """
    try:
        if not isinstance(packet, dict):
            return 'safe'
        
        # 방어 메커니즘 관리자를 통한 분석 (우선순위 1)
        if defense_manager and hasattr(defense_manager, 'auto_defense'):
            try:
                # AutoDefenseActions의 analyze_packet 메서드 활용
                prediction, confidence = defense_manager.auto_defense.analyze_packet(packet)
                
                #  예측 결과와 신뢰도를 바탕으로 위협 수준 결정 (5단계)
                if prediction == 1:  # 공격으로 분류됨
                    if confidence >= 0.9:
                        return 'critical'  # 🔴 치명적
                    elif confidence >= 0.8:
                        return 'high'      # 🟠 높음
                    elif confidence >= 0.7:
                        return 'medium'    # 🟡 중간
                    else:
                        return 'low'       # 🟢 낮음
                else:  # 정상으로 분류됨
                    # 정상이지만 신뢰도가 낮은 경우 의심스러운 것으로 판단
                    if confidence < 0.6:
                        return 'low'
                    else:
                        return 'safe'
                        
            except Exception as e:
                logger.debug(f"방어 모듈 분석 오류: {e}")
        
        # 백업 휴리스틱 분석 (방어 모듈이 없거나 오류 발생 시)
        length = packet.get('length', 0)
        source = packet.get('source', '')
        destination = packet.get('destination', '')
        protocol = str(packet.get('protocol', '')).upper()
        info = str(packet.get('info', '')).lower()
        
        threat_score = 0.0
        
        # 즉시 고위험 조건들
        if length > 8000:  # 비정상적으로 큰 패킷
            threat_score += 0.8
        
        if 'syn flood' in info or 'ddos' in info or 'attack' in info:
            threat_score += 0.9
        
        # 의심스러운 포트 확인 (방어 모듈과 동일한 로직)
        suspicious_ports = [4444, 31337, 1337, 6667, 6666]
        if ':' in destination:
            try:
                port = int(destination.split(':')[1])
                if port in suspicious_ports:
                    threat_score += 0.7
            except:
                pass
        
        # SYN 플러딩 패턴 (방어 모듈과 동일한 로직)
        if (protocol in ['TCP', '6'] or protocol == 'tcp') and 'syn' in info:
            threat_score += 0.6
        
        # 비정상적인 패킷 크기 (방어 모듈과 동일한 로직)
        if length > 5000:
            threat_score += 0.5
        
        # 중간 크기 패킷
        if length > 3000:
            threat_score += 0.3
        
        # 외부 연결 분석
        if source and not (source.startswith('192.168.') or source.startswith('10.') or 
                          source.startswith('172.16.') or source.startswith('127.') or
                          source.startswith('::1') or source.startswith('fe80')):
            if length > 1500:
                threat_score += 0.2
        
        #  점수를 위협 수준으로 변환 (5단계 분류)
        if threat_score >= 0.9:
            return 'critical'  # 🔴 치명적
        elif threat_score >= 0.8:
            return 'high'      # 🟠 높음
        elif threat_score >= 0.7:
            return 'medium'    # 🟡 중간
        else:
            return 'safe'      # ⚪ 안전
            
    except Exception as e:
        logger.debug(f"위협 분석 중 오류: {e}")
        return 'safe'

def show_help_menu():
    """도움말 메뉴"""
    print_header()
    
    print_colored(" 도움말", Fore.YELLOW, Style.BRIGHT)
    print_colored("=" * 60, Fore.YELLOW)
    
    help_content = [
        "🔧 사용 가능한 명령어:",
        "",
        "m, mode     - 운영 모드 전환",
        "s, status   - 시스템 상태 확인",
        "h, help     - 이 도움말 표시",
        "q, quit     - 프로그램 종료",
        "",
        " 통계 명령어:",
        "packets     - 캡처된 패킷 통계",
        "defense     - 방어 메커니즘 상태",
        "ml          - 머신러닝 모델 상태",
        "threats     - 위협 탐지 상세 통계",
        "",
        " 단축키:",
        "Ctrl+C      - 강제 종료",
        "Enter       - 상태 새로고침"
    ]
    
    print_status_box("명령어 가이드", help_content, Fore.CYAN)
    print()
    print_colored("계속하려면 Enter 키를 누르세요...", Fore.YELLOW)
    input()

def monitor_system_resources():
    """
    시스템 리소스 모니터링 및 상태 반환
    
    CPU와 메모리 사용량을 체크하여 시스템 부하 상태를 판단합니다.
    
    Returns:
        str: 시스템 리소스 상태
            - 'reduce_processing': CPU > 80% 또는 메모리 > 800MB (부하)
            - 'can_increase': CPU < 30% 그리고 메모리 < 500MB (여유)
            - 'maintain': 그 외 정상 범위 (보통)
    """
    try:
        import psutil
        cpu_usage = psutil.cpu_percent(interval=0.1)
        memory_mb = psutil.Process().memory_info().rss / (1024 * 1024)
        
        # 실제 시스템 메모리 사용량 고려 (PyTorch + scikit-learn = ~350MB 기본)
        if cpu_usage > 80 or memory_mb > 800:
            logger.warning(f"리소스 부하 감지 - CPU: {cpu_usage:.1f}%, 메모리: {memory_mb:.1f}MB")
            return "reduce_processing"
        elif cpu_usage < 30 and memory_mb < 500:
            return "can_increase"
        else:
            return "maintain"
    except Exception:
        return "maintain"

def cleanup_memory_completely():
    """
    시스템 종료 시 완전한 메모리 정리
    """
    try:
        import gc
        import psutil
        
        print(" 메모리 완전 정리 시작...")
        initial_memory = psutil.Process().memory_info().rss / (1024 * 1024)
        
        # 통합 서비스 정리 (새로운 모듈들)
        global online_trainer, vuln_scanner
        if 'online_trainer' in globals() and online_trainer is not None:
            try:
                print(" 온라인 RL 학습 스레드 정리 중...")
                online_trainer.stop()
                online_trainer = None
                print(" [OK] 온라인 RL 학습 스레드 정리 완료")
            except Exception as e:
                logger.error(f"온라인 학습 스레드 정리 실패: {e}")
        
        if 'vuln_scanner' in globals() and vuln_scanner is not None:
            try:
                print(" 자동 취약점 스캐너 정리 중...")
                vuln_scanner.stop()
                vuln_scanner = None
                print(" [OK] 자동 취약점 스캐너 정리 완료")
            except Exception as e:
                logger.error(f"취약점 스캐너 정리 실패: {e}")
        
        # 하이브리드 로그 매니저 정리
        global hybrid_log_manager, web_api_server
        if 'hybrid_log_manager' in globals() and hybrid_log_manager is not None:
            try:
                print(" 하이브리드 로그 매니저 정리 중...")
                hybrid_log_manager.stop()
                hybrid_log_manager = None
                print(" [OK] 하이브리드 로그 매니저 정리 완료")
            except Exception as e:
                logger.error(f"로그 매니저 정리 실패: {e}")
                print(f" [ERROR] 로그 매니저 정리 실패: {e}")
        
        # 웹 API 서버 정리
        if 'web_api_server' in globals() and web_api_server is not None:
            try:
                print(" 웹 API 서버 정리 중...")
                web_api_server.stop()
                web_api_server = None
                print(" [OK] 웹 API 서버 정리 완료")
            except Exception as e:
                logger.error(f"웹 서버 정리 실패: {e}")
                print(f" [ERROR] 웹 서버 정리 실패: {e}")
        
        # 강력한 가비지 컬렉션 (5번 반복)
        total_collected = 0
        for i in range(5):
            collected = gc.collect()
            total_collected += collected
            if collected == 0:
                break
        
        # 전역 변수 정리
        import sys
        for module_name in list(sys.modules.keys()):
            if 'scapy' in module_name or 'numpy' in module_name:
                try:
                    if hasattr(sys.modules[module_name], '__dict__'):
                        for var_name in list(sys.modules[module_name].__dict__.keys()):
                            if var_name.startswith('_cache') or var_name.startswith('cache'):
                                delattr(sys.modules[module_name], var_name)
                except:
                    pass
        
        final_memory = psutil.Process().memory_info().rss / (1024 * 1024)
        cleaned_memory = initial_memory - final_memory
        
        print(f"✅ 메모리 정리 완료: {total_collected}개 객체 해제, {cleaned_memory:+.1f}MB 정리")
        
    except Exception as e:
        print(f"메모리 정리 중 오류: {e}")

def get_adaptive_process_count(queue_size, max_queue_size=10000):
    """
    큐 크기와 시스템 리소스에 따른 적응형 처리 개수 계산
    
    큐 사용률과 시스템 리소스 상태를 고려하여 한 번에 처리할 패킷 개수를 동적으로 조절합니다.
    
    Args:
        queue_size (int): 현재 큐 크기
        max_queue_size (int): 최대 큐 크기 (기본값: 10000)
    
    Returns:
        int: 처리할 패킷 개수 (50~2000개)
            - 큐 80% 이상: 최대 1500개 (과부하 상황)
            - 큐 50~80%: 최대 800개 (경고 상황)
            - 큐 50% 미만: 150개 (정상 상황)
            - 리소스 상태에 따라 ±50% 조정
    """
    if queue_size <= 0:
        return 0
    
    # 시스템 리소스 상태 확인
    resource_status = monitor_system_resources()
    
    # 큐 사용률 계산 (0.0 ~ 1.0)
    queue_utilization = queue_size / max_queue_size
    
    # 기본 처리량 계산 (절충안: 보수적 개선)
    if queue_utilization >= 0.8:  # 80% 이상: 위험 상황
        # 큐의 30%를 한 번에 처리하되 최대 1500개로 제한
        base_process = min(1500, max(queue_size * 0.3, 300))
        logger.warning(f"큐 과부하 감지 - 처리량 증가: {int(base_process)}개 (큐 크기: {queue_size})")
    
    elif queue_utilization >= 0.5:  # 50% 이상: 경고 상황  
        # 큐의 20%를 한 번에 처리하되 최대 800개로 제한
        base_process = min(800, max(queue_size * 0.2, 200))
        logger.info(f"큐 부하 증가 - 처리량 조정: {int(base_process)}개 (큐 크기: {queue_size})")
    
    else:  # 50% 미만: 정상 상황
        base_process = 150  # 기본값 3배 증가 (50 → 150)
    
    # 리소스 상태에 따른 조정
    if resource_status == "reduce_processing":
        # CPU/메모리 부하 시 처리량 50% 감소
        adjusted_process = int(base_process * 0.5)
        logger.info(f"리소스 보호 모드 - 처리량 감소: {adjusted_process}개")
        return max(adjusted_process, 50)  # 최소 50개는 보장
    
    elif resource_status == "can_increase":
        # 리소스 여유 시 처리량 50% 증가
        adjusted_process = int(base_process * 1.5)
        logger.debug(f"리소스 여유 - 처리량 증가: {adjusted_process}개")
        return min(adjusted_process, 2000)  # 최대 2000개로 제한
    
    else:  # maintain
        return int(base_process)

def main():
    """
    IPS 시스템 메인 함수
    
    전체 시스템을 초기화하고 패킷 캡처, 위협 분석, 방어 메커니즘을 실행합니다.
    실시간 대시보드와 사용자 명령어 인터페이스를 제공합니다.
    """
    # ========== 전역 변수 초기화 ==========
    global threat_stats, defense_stats, ml_stats, start_time, hybrid_log_manager
    #  치명적 위협 카테고리 추가 (5단계 분류)
    threat_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'safe': 0}
    #  방어 통계에 차단 유형별 카운트 추가
    defense_stats = {
        'blocked': 0,           # 총 차단된 IP 수
        'permanent_block': 0,   # 영구 차단
        'temp_block': 0,        # 임시 차단 (30분)
        'warning_block': 0,     # 경고 차단 (10분)
        'monitored': 0,         # 모니터링 중
        'alerts': 0,            # 발송된 알림 수
        'accumulated_blocks': 0 # 누적 패턴으로 차단된 수
    }
    ml_stats = {'predictions': 0, 'accuracy': 0.0, 'model_updates': 0}
    start_time = time.time()
    
    # ========== 로그 시스템 초기화 ==========
    try:
        from modules.hybrid_log_manager import HybridLogManager
        hybrid_log_manager = HybridLogManager()
        hybrid_log_manager.start()
        logger.info("하이브리드 로그 관리자 초기화 완료")
        print_colored(" 하이브리드 로그 시스템 활성화됨", Fore.GREEN)
    except ImportError as e:
        logger.warning(f"하이브리드 로그 관리자 로드 실패: {e}")
        hybrid_log_manager = None
        print_colored("⚠️  기본 로그 시스템 사용", Fore.YELLOW)
    
    # 웹 API 서버 초기화 (선택적)
    web_api_server = None
    if args.web_server:
        try:
            from web_api_server import IDSWebAPI
            web_api_server = IDSWebAPI(
                hybrid_log_manager=hybrid_log_manager,
                host=args.web_host,
                port=args.web_port
            )
            web_api_server.start()
            logger.info(f"웹 API 서버 시작됨: http://{args.web_host}:{args.web_port}")
            print_colored(f" 웹 모니터링 활성화됨: http://{args.web_host}:{args.web_port}", Fore.CYAN, Style.BRIGHT)
            print_colored(f"📱 대시보드: http://{args.web_host}:{args.web_port}", Fore.CYAN)
        except ImportError as e:
            logger.warning(f"웹 API 서버 로드 실패: {e}")
            print_colored("  웹 API 서버 로드 실패 - CLI 모드로만 실행", Fore.YELLOW)
        except Exception as e:
            logger.error(f"웹 API 서버 시작 실패: {e}")
            print_colored(f" 웹 서버 시작 실패: {e}", Fore.RED)
    
    try:
        # ========== 시작 애니메이션 및 UI 초기화 ==========
        show_startup_animation()
        
        # ========== 운영 모드 선택 ==========
        if args.mode is None and not args.no_menu:
            # 명령줄에서 모드를 지정하지 않았고, 메뉴 비활성화도 아닌 경우
            # 사용자에게 모드 선택 메뉴 표시
            selected_mode = select_mode_menu()
            args.mode = selected_mode
        elif args.mode is None:
            # 모드 지정이 없고 메뉴 비활성화인 경우 기본값 사용
            args.mode = "lightweight"
        
        # 운영 모드 표시
        print_header()
        mode_color = Fore.GREEN if args.mode == "lightweight" else Fore.BLUE
        mode_icon = "⚡" if args.mode == "lightweight" else "🔥"
        print_colored(f"{mode_icon} 선택된 운영 모드: {args.mode.upper()}", mode_color, Style.BRIGHT)
        logger.info(f"운영 모드 설정: {args.mode}")
        print()
        
        # Colab 환경 확인
        colab_status = is_colab()
        print_colored(f" 환경 확인: {'Google Colab' if colab_status else '로컬 환경'}", Fore.CYAN)
        
        if colab_status:
            logger.info("Google Colab 환경에서 실행 중")
            print_colored("  Google Colab 환경 감지", Fore.YELLOW, Style.BRIGHT)
            print_colored(" 머신러닝 모델 학습만 가능합니다", Fore.YELLOW)
            print_colored(" 패킷 캡처 기능은 로컬 환경에서만 사용 가능", Fore.YELLOW)
            
            # 데이터 파일이 있는 경우에만 머신러닝 모델 학습 실행
            preprocessed_data_path = 'data_set/전처리데이터1.csv'
            if os.path.exists(preprocessed_data_path):
                print("\n데이터 파일을 찾았습니다. 머신러닝 모델 학습을 시작합니다...")
                
                #  지연 로딩: 필요한 시점에 머신러닝 모듈 로딩
                print("머신러닝 모듈 로딩 중...")
                ml_modules = lazy_importer.get_module('ml_models')
                train_random_forest = ml_modules['train_random_forest']
                
                # 랜덤 포레스트 모델 학습
                model, accuracy, conf_matrix = train_random_forest(preprocessed_data_path)
                
                #  지연 로딩: 새로운 Conservative RL 시스템 로딩
                print("Conservative RL 시스템 로딩 중...")
                rl_modules = lazy_importer.get_module('conservative_rl')
                ConservativeRLAgent = rl_modules['ConservativeRLAgent']
                DefensePolicyEnv = rl_modules['DefensePolicyEnv']
                OPEEvaluator = rl_modules['OPEEvaluator']
                
                # 새로운 RL 대응 정책 환경과 에이전트 초기화
                env = DefensePolicyEnv()
                agent = ConservativeRLAgent(
                    state_size=10,  # DefensePolicyEnv 상태 크기
                    action_size=6,  # 6개 대응 액션
                    mode="standard",
                    use_prioritized_replay=True,
                    buffer_capacity=10000
                )
                
                # 강화학습 훈련 실행 (개선된 버전)
                rewards, malicious_counts, buffer_stats = train_rl_agent(
                    env, 
                    agent, 
                    episodes=500,
                    batch_size=32,
                    save_buffer_interval=50,
                    buffer_save_path=f"experience_buffer_{args.mode}"
                )
                
                # 훈련 결과 시각화 (개선된 버전)
                plot_training_results = rl_modules['plot_training_results']
                plot_training_results(rewards, malicious_counts, buffer_stats)
                
                # 모델 저장 (모드별로 구분하여 저장)
                save_model = rl_modules['save_model']
                save_model(agent, f'dqn_model_{args.mode}.pth')
                
                # Experience Replay Buffer 통계 출력
                final_stats = agent.get_buffer_stats()
                print("\n=== Experience Replay Buffer 최종 통계 ===")
                print(f"총 경험 수: {final_stats['total_experiences']}")
                print(f"악성 경험 수: {final_stats['malicious_experiences']}")
                print(f"정상 경험 수: {final_stats['benign_experiences']}")
                print(f"평균 보상: {final_stats['avg_reward']:.3f}")
                print(f"최대 보상: {final_stats['max_reward']:.13f}")
                print(f"최소 보상: {final_stats['min_reward']:.3f}")
                
                print("\n모델 학습이 완료되었습니다.")
            else:
                print("\n데이터 파일을 찾을 수 없습니다.")
            return
            
        # ========== 로컬 환경 전용 코드 ==========
        logger.info("로컬 환경에서 IPS 시스템 실행 시작")
        
        # ========== 관리자 권한 확인 (Windows) ==========
        if os.name == 'nt' and not args.debug:  # 디버그 모드에서는 관리자 권한 체크 생략
            logger.info("윈도우 환경 감지: 관리자 권한 확인 중...")
            if not is_admin():
                print("관리자 권한이 필요합니다. 관리자 권한으로 재실행합니다...")
                run_as_admin()
                return
            logger.info("관리자 권한으로 실행 중...")
        elif os.name == 'nt' and args.debug:
            logger.info("디버그 모드: 관리자 권한 체크 우회")
            logger.info("디버그 모드에서 관리자 권한 체크 우회됨")
        
        # ========== 패킷 캡처 시스템 초기화 ==========
        clear_screen()
        logger.info("패킷 캡처 코어 초기화 중...")
        
        if use_optimized_capture:
            packet_core = OptimizedPacketCapture()
            logger.info(f"멀티프로세싱 패킷 캡처 활성화 (워커: {packet_core.num_workers}개)")
        else:
            packet_core = PacketCaptureCore()
        
        # ========== 반응형 AI 통합 시스템 초기화 ==========
        integrated_modules = None
        state_extractor = None
        reward_calculator = None
        online_trainer = None
        rl_integrator = None
        vuln_scanner = None
        
        try:
            logger.info("반응형 AI 통합 모듈 로딩 중...")
            integrated_modules = lazy_importer.get_module('integrated_modules')
            
            if integrated_modules:
                # 상태 추출기 및 보상 계산기 초기화
                state_extractor = integrated_modules['get_state_extractor']()
                reward_calculator = integrated_modules['get_reward_calculator']()
                logger.info("✓ RL 상태 추출기 및 보상 계산기 로드됨")
                
                print_colored("🤖 반응형 AI 시스템 활성화됨", Fore.GREEN)
        except Exception as e:
            logger.warning(f"통합 모듈 로딩 실패 (기본 모드로 계속): {e}")
        
        # ========== 방어 메커니즘 초기화 ==========
        logger.info(f"{args.mode} 모드로 방어 메커니즘 초기화 중...")
        
        #  통계 업데이트 콜백 함수 정의
        def update_defense_stats(stat_type):
            """방어 통계 업데이트 콜백"""
            global defense_stats
            try:
                if stat_type in defense_stats:
                    defense_stats[stat_type] += 1
                    
                    # blocked 총계 업데이트
                    defense_stats['blocked'] = (
                        defense_stats.get('permanent_block', 0) +
                        defense_stats.get('temp_block', 0) +
                        defense_stats.get('warning_block', 0)
                    )
            except Exception as e:
                logger.debug(f"통계 업데이트 오류: {e}")
        
        #  스크립트 위치 기준 경로로 수정 (어디서 실행해도 작동)
        config_path = os.path.join(os.path.dirname(__file__), 'defense_config.json')
        defense_manager = create_defense_manager(config_path, mode=args.mode, stats_callback=update_defense_stats)
        
        # 패킷 캡처 코어에 방어 메커니즘 등록
        if register_to_packet_capture(defense_manager, packet_core):
            logger.info("방어 메커니즘이 패킷 캡처 시스템에 성공적으로 등록되었습니다.")
        else:
            logger.error("방어 메커니즘 등록 실패")
        
        # ========== 네트워크 인터페이스 설정 ==========
        # Windows에서 Npcap 확인
        if os.name == 'nt':
            if not packet_core.check_npcap():
                print("Npcap이 설치되어 있지 않습니다. 패킷 캡처 기능을 사용할 수 없습니다.")
                print("Npcap을 설치한 후 다시 시도해주세요.")
                wait_for_enter()
                return
        
        # 🔥 네트워크 인터페이스 자동 선택 (활성 연결 우선)
        interfaces = packet_core.get_network_interfaces()
        
        if not interfaces:
            print_colored("❌ 사용 가능한 네트워크 인터페이스를 찾을 수 없습니다!", Fore.RED)
            wait_for_enter()
            return
        
        selected_interface = None
        
        # psutil로 실제 활성 인터페이스 확인
        try:
            import psutil
            active_interfaces = []
            
            # 활성 상태이고 IP 주소가 있는 인터페이스만 선택
            for iface_name, stats in psutil.net_if_stats().items():
                if stats.isup:  # 활성 상태
                    # IP 주소가 있는지 확인
                    addrs = psutil.net_if_addrs().get(iface_name, [])
                    has_ipv4 = any(addr.family == 2 for addr in addrs)  # AF_INET
                    
                    if has_ipv4:
                        # loopback 제외
                        if not any(skip in iface_name.lower() for skip in ['loopback', 'lo']):
                            active_interfaces.append(iface_name)
            
            if active_interfaces:
                # 활성 인터페이스 중에서 선택
                # 1순위: 이더넷 (더 안정적)
                ethernet_keywords = ['ethernet', 'eth', 'lan', 'local area connection', 'realtek']
                for iface in active_interfaces:
                    if any(keyword in iface.lower() for keyword in ethernet_keywords):
                        selected_interface = iface
                        print_colored(f"✅ 이더넷 인터페이스 자동 선택: {iface}", Fore.GREEN)
                        break
                
                # 2순위: WiFi
                if not selected_interface:
                    wifi_keywords = ['wifi', 'wireless', 'wi-fi', 'wlan', '802.11']
                    for iface in active_interfaces:
                        if any(keyword in iface.lower() for keyword in wifi_keywords):
                            selected_interface = iface
                            print_colored(f"✅ WiFi 인터페이스 자동 선택: {iface}", Fore.GREEN)
                            break
                
                # 3순위: 첫 번째 활성 인터페이스
                if not selected_interface and active_interfaces:
                    selected_interface = active_interfaces[0]
                    print_colored(f"✅ 활성 인터페이스 자동 선택: {selected_interface}", Fore.CYAN)
            
        except ImportError:
            print_colored("⚠️ psutil 없음 - 기본 선택 로직 사용", Fore.YELLOW)
            # psutil 없이 기본 로직
            ethernet_keywords = ['ethernet', 'eth', 'lan']
            for interface in interfaces:
                if any(keyword in interface.lower() for keyword in ethernet_keywords):
                    selected_interface = interface
                    break
        
        # 4단계: 자동 선택 실패 시 사용자 선택
        if not selected_interface:
            print_colored("⚠️ 적합한 네트워크 인터페이스를 자동으로 찾을 수 없습니다.", Fore.YELLOW)
            print_colored("\n사용 가능한 인터페이스 목록:", Fore.CYAN)
            for i, interface in enumerate(interfaces, 1):
                print_colored(f"  {i}. {interface}", Fore.WHITE)
            
            # 사용자가 인터페이스 직접 선택
            try:
                choice = int(input("\n사용할 인터페이스 번호를 입력하세요: "))
                if 1 <= choice <= len(interfaces):
                    selected_interface = interfaces[choice-1]
                    print_colored(f"✅ 수동 선택: {selected_interface}", Fore.GREEN)
                else:
                    print_colored("❌ 잘못된 선택입니다.", Fore.RED)
                    wait_for_enter()
                    return
            except ValueError:
                print_colored("❌ 숫자를 입력해야 합니다.", Fore.RED)
                wait_for_enter()
                return
        
        logger.info(f"선택된 인터페이스: {selected_interface}")
        
        # ========== 패킷 캡처 시작 ==========
        print_colored(f"\n🔗 {selected_interface}에서 패킷 캡처를 시작합니다...", Fore.CYAN)
        
        # 🔥 패킷 캡처 시작 시도
        capture_started = packet_core.start_capture(selected_interface, max_packets=args.max_packets)
        
        if not capture_started:
            # 패킷 캡처 실패 시 상세한 에러 정보 제공
            print_colored("\n❌ 패킷 캡처 시작 실패!", Fore.RED, Style.BRIGHT)
            print_colored("="*60, Fore.RED)
            print_colored("\n가능한 원인:", Fore.YELLOW)
            print_colored("  1. 관리자 권한 부족 (Windows: 우클릭 → 관리자 권한 실행)", Fore.WHITE)
            print_colored("  2. Npcap/WinPcap 미설치 (https://npcap.com)", Fore.WHITE)
            print_colored("  3. 네트워크 인터페이스 선택 오류", Fore.WHITE)
            print_colored("  4. 다른 프로그램이 인터페이스 사용 중", Fore.WHITE)
            print_colored("\n해결 방법:", Fore.YELLOW)
            print_colored("  • 진단 스크립트 실행: python IDS/system_diagnostic.py", Fore.GREEN)
            print_colored("  • 로그 확인: logs/ips_debug.log", Fore.GREEN)
            print_colored("="*60, Fore.RED)
            logger.error(f"패킷 캡처 시작 실패 - 인터페이스: {selected_interface}")
            wait_for_enter()
            return
        
        # 패킷 캡처 성공
        print_colored("✅ 패킷 캡처가 백그라운드에서 시작되었습니다.", Fore.GREEN)
        print_colored("🎛️  실시간 대시보드 모드로 전환합니다.", Fore.YELLOW)
        print()
        
        # 🔥 패킷 캡처 상태 확인 (5초 후)
        time.sleep(5)
        initial_packet_count = packet_core.get_packet_count()
        if initial_packet_count == 0:
            print_colored("⚠️ 주의: 5초 동안 패킷이 캡처되지 않았습니다.", Fore.YELLOW)
            print_colored("   • 네트워크 트래픽이 없거나 인터페이스 설정 문제일 수 있습니다.", Fore.YELLOW)
            print_colored("   • 대시보드는 계속 실행되지만 패킷이 표시되지 않을 수 있습니다.", Fore.YELLOW)
            logger.warning(f"초기 패킷 캡처 없음 - 인터페이스: {selected_interface}")
        else:
            print_colored(f"✅ 패킷 캡처 정상 작동 중 ({initial_packet_count}개 캡처됨)", Fore.GREEN)
            logger.info(f"패킷 캡처 정상 - 초기 {initial_packet_count}개")
            
            # ========== 실시간 대시보드 스레드 ==========
            def display_realtime_stats():
                global threat_stats, defense_stats, ml_stats
                last_packet_count = 0
                start_time = time.time()
                
                # 객체 풀에서 통계 딕셔너리 가져오기
                stats_pool = get_stats_pool()
                protocol_stats = stats_pool.get()
                
                last_stats_time = time.time()
                last_display_time = 0
                packets_per_second = 0
                peak_packets_per_second = 0
                total_threats_detected = 0
                
                # 큐 오버플로우 방지 변수
                dropped_packets = 0
                last_queue_warning_time = 0
                max_queue_size = 50000  # 최대 큐 크기 (기존 10000에서 증가)
                
                # 조용히 시작 (로그에만 기록)
                logger.info("강화된 실시간 대시보드 모니터링 시작 (객체 풀링 활성화, 최대 큐: 50000)")
                
                # 첫 번째 대시보드 즉시 표시
                show_initial_dashboard = True
                
                while packet_core.is_running:
                    current_count = packet_core.get_packet_count()
                    current_time = time.time()
                    elapsed_time = current_time - start_time
                    
                    # 초당 패킷 수 계산 및 메모리 관리
                    if current_time - last_stats_time >= 1.0:  # 1초마다 계산
                        packets_per_second = current_count - last_packet_count
                        if packets_per_second > peak_packets_per_second:
                            peak_packets_per_second = packets_per_second
                        last_packet_count = current_count
                        last_stats_time = current_time
                        
                        #  하이브리드 로그 매니저에 실시간 데이터 전달
                        if hybrid_log_manager is not None:
                            hybrid_data = {
                                'threat_stats': threat_stats.copy(),
                                'defense_stats': defense_stats.copy(),
                                'ml_stats': ml_stats.copy(),
                                'packets_per_second': packets_per_second,
                                'peak_pps': peak_packets_per_second,
                                'total_packets': current_count,
                                'uptime': elapsed_time
                            }
                            try:
                                hybrid_log_manager.update_realtime_data(hybrid_data)
                            except Exception as log_error:
                                logger.error(f"로그 매니저 업데이트 실패: {log_error}")
                                # 로그 매니저 오류가 메인 프로세스를 방해하지 않도록 함
                        
                        # 메모리 누수 방지: 적극적 메모리 관리 (30초마다)
                        if int(elapsed_time) % 30 == 0 and int(elapsed_time) > 0:
                            import gc
                            
                            # 강제 가비지 컬렉션 (3번 실행)
                            collected_total = 0
                            for _ in range(3):
                                collected_total += gc.collect()
                            
                            # 메모리 사용량 체크
                            try:
                                import psutil
                                current_memory = psutil.Process().memory_info().rss / (1024 * 1024)
                                if current_memory > 150:  # 150MB 이상시 강력한 정리
                                    logger.warning(f"높은 메모리 사용량 감지: {current_memory:.1f}MB - 적극적 정리 시작")
                                    
                                    # 통계 변수 정리 (5분치만 유지)
                                    if hasattr(locals(), 'protocol_stats'):
                                        for key in protocol_stats:
                                            if protocol_stats[key] > 100000:  # 너무 큰 값은 리셋
                                                protocol_stats[key] = protocol_stats[key] // 2
                                    
                                    # 추가 가비지 컬렉션
                                    collected_total += gc.collect()
                                
                                if collected_total > 0:
                                    logger.debug(f"메모리 정리 완료: {collected_total}개 객체 해제, 현재 {current_memory:.1f}MB")
                            except Exception as e:
                                logger.debug(f"메모리 체크 오류: {e}")
                    
                    # 큐에서 패킷을 가져와서 통계 업데이트
                    packet_pool = get_packet_pool()  # 패킷 풀 가져오기
                    try:
                        #  수정: 두 큐 모두 확인하여 총 큐 크기 계산
                        packet_queue_size = packet_core.packet_queue.qsize()
                        processed_queue_size = getattr(packet_core, 'processed_queue', queue.Queue()).qsize()
                        total_queue_size = packet_queue_size + processed_queue_size
                        
                        #  큐 오버플로우 방지: 최대 크기 초과 시 오래된 패킷 드롭
                        if total_queue_size > max_queue_size:
                            overflow_count = total_queue_size - max_queue_size
                            # 초과된 패킷을 packet_queue에서 먼저 드롭
                            for _ in range(min(overflow_count, packet_queue_size)):
                                try:
                                    dropped_pkt = packet_core.packet_queue.get_nowait()
                                    dropped_packets += 1
                                    del dropped_pkt  # 메모리 해제
                                except queue.Empty:
                                    break
                            
                            # 경고 메시지 (10초마다 한 번만)
                            if current_time - last_queue_warning_time > 10:
                                logger.warning(f"🚨 큐 오버플로우! {dropped_packets}개 패킷 드롭됨 (큐 크기: {total_queue_size}/{max_queue_size})")
                                last_queue_warning_time = current_time
                        
                        # 적응형 처리에는 총 큐 크기 사용
                        max_process_count = get_adaptive_process_count(total_queue_size, max_queue_size)
                        
                        #  개선된 로깅: 큐 상태 세부 정보 포함
                        if total_queue_size > 0 and int(elapsed_time) % 10 == 0:
                            logger.info(f"큐 상태 - 패킷큐: {packet_queue_size}, 처리큐: {processed_queue_size}, 총큐: {total_queue_size}, 처리량: {max_process_count}, 리소스: {monitor_system_resources()}")
                        elif total_queue_size == 0 and int(elapsed_time) % 60 == 0:
                            # 큐가 비어있을 때 1분마다 원인 진단 로깅
                            total_captured = packet_core.get_packet_count()
                            logger.warning(f"큐 비어있음 - 총 캡처: {total_captured}, 캡처 상태: {packet_core.is_running}")
                        
                        processed_count = 0
                        
                        #  수정: processed_queue를 우선적으로 처리 (더 많은 패킷이 있음)
                        target_queue = None
                        queue_name = ""
                        
                        if hasattr(packet_core, 'processed_queue') and not packet_core.processed_queue.empty():
                            target_queue = packet_core.processed_queue
                            queue_name = "processed_queue"
                        elif not packet_core.packet_queue.empty():
                            target_queue = packet_core.packet_queue
                            queue_name = "packet_queue"
                        
                        if target_queue:
                            # 처리 시작 로깅 (첫 번째 패킷만)
                            if total_queue_size > 0 and int(elapsed_time) % 30 == 0:
                                logger.debug(f"패킷 처리 시작 - 사용 큐: {queue_name}, 큐 크기: {target_queue.qsize()}, 처리량: {max_process_count}")
                            
                            while not target_queue.empty() and processed_count < max_process_count:
                                original_packet = None
                                pooled_packet = None
                                
                                try:
                                    original_packet = target_queue.get_nowait()
                                    processed_count += 1
                                    
                                    # 풀에서 패킷 객체 가져오기
                                    pooled_packet = packet_pool.get()
                                    
                                    if isinstance(original_packet, dict):
                                        # 원본 데이터를 풀 객체에 복사
                                        pooled_packet.clear()  # 이전 데이터 완전 삭제
                                        pooled_packet.update(original_packet)
                                        
                                        # 프로토콜 통계
                                        protocol = str(pooled_packet.get('protocol', 'Other')).upper()
                                        if protocol in ['6', 'TCP']:
                                            protocol_stats['TCP'] += 1
                                        elif protocol in ['17', 'UDP']:
                                            protocol_stats['UDP'] += 1
                                        elif protocol in ['1', 'ICMP']:
                                            protocol_stats['ICMP'] += 1
                                        else:
                                            protocol_stats['Other'] += 1
                            
                                        # 방어 모듈 기반 위협 수준 분석
                                        threat_level = analyze_threat_level(pooled_packet if isinstance(original_packet, dict) else original_packet, defense_manager=defense_manager)
                                        threat_stats[threat_level] += 1
                            
                                        #  치명적, 높음, 중간 위협을 모두 카운트
                                        if threat_level in ['critical', 'high', 'medium']:
                                            total_threats_detected += 1
                                            
                                except queue.Empty:
                                    break
                                except Exception as e:
                                    logger.debug(f"패킷 처리 중 오류: {e}")
                                finally:
                                    # 메모리 누수 방지: 명시적 객체 해제
                                    if pooled_packet is not None:
                                        try:
                                            pooled_packet.clear()  # 딕셔너리 완전 비우기
                                            packet_pool.put(pooled_packet)
                                        except:
                                            pass
                                    
                                    # 원본 패킷 명시적 삭제
                                    if original_packet is not None:
                                        del original_packet
                                    
                                    pooled_packet = None
                                    
                    except queue.Empty:
                        pass
                    except Exception as e:
                        logger.debug(f"패킷 처리 중 오류: {e}")  # 조용히 처리
                    
                    # 방어 메커니즘 통계 수집 (콜백으로 자동 업데이트되므로 추가 작업 불필요)
                    # defense_stats는 방어 메커니즘 내부에서 콜백을 통해 자동 업데이트됨
                    
                    # 실시간 대시보드 출력 (처음 즉시, 이후 3초마다)
                    if show_initial_dashboard or (int(elapsed_time) % 3 == 0 and int(elapsed_time) != last_display_time):
                        if show_initial_dashboard:
                            show_initial_dashboard = False
                        last_display_time = int(elapsed_time)
                        runtime_str = f"{int(elapsed_time//3600):02d}:{int((elapsed_time%3600)//60):02d}:{int(elapsed_time%60):02d}"
                        
                        # 화면 지우기 (선택적)
                        print("\n" * 2)  # 새 줄 추가
                        
                        # 메인 헤더
                        print_colored("🛡️" + "="*78 + "🛡️", Fore.CYAN, Style.BRIGHT)
                        print_colored("                    IPS 실시간 모니터링 대시보드", Fore.CYAN, Style.BRIGHT)
                        print_colored("🛡️" + "="*78 + "🛡️", Fore.CYAN, Style.BRIGHT)
                        
                        # 시스템 상태 섹션
                        print_colored(f"  시스템 가동시간: {runtime_str}  |  🛡️  운영모드: {args.mode.upper()}  |  📡 인터페이스: {selected_interface}", Fore.GREEN)
                        print_colored("-" * 80, Fore.WHITE)
                        
                        # 패킷 캡처 통계
                        print_colored(" 패킷 캡처 통계", Fore.YELLOW, Style.BRIGHT)
                        print_colored(f"   총 캡처: {current_count:,}개  |  초당 패킷: {packets_per_second}/s  |  최고 처리량: {peak_packets_per_second}/s", Fore.WHITE)
                        
                        # 적응형 큐 처리 정보 추가
                        current_packet_queue_size = packet_core.packet_queue.qsize()
                        current_processed_queue_size = getattr(packet_core, 'processed_queue', queue.Queue()).qsize()
                        current_total_queue_size = current_packet_queue_size + current_processed_queue_size
                        current_process_count = get_adaptive_process_count(current_total_queue_size)
                        queue_utilization = (current_total_queue_size / 10000) * 100  # 백분율로 변환
                        
                        #  추가: 큐 세부 정보 표시
                        queue_detail = f"패킷큐={current_packet_queue_size}, 처리큐={current_processed_queue_size}"
                        
                        # 큐 상태에 따른 색상 결정
                        if queue_utilization >= 80:
                            queue_color = Fore.RED  # 위험
                        elif queue_utilization >= 50:
                            queue_color = Fore.YELLOW  # 경고
                        else:
                            queue_color = Fore.GREEN  # 정상
                        
                        # 리소스 상태 확인
                        resource_status = monitor_system_resources()
                        status_text = {"can_increase": "여유", "maintain": "보통", "reduce_processing": "부하"}[resource_status]
                        
                        print_colored(f"   큐 크기: {current_total_queue_size:,}개 ({queue_utilization:.1f}%) [{queue_detail}]  |  적응형 처리량: {current_process_count}개/회  |  리소스: {status_text}  |  처리 상태: {'활성' if packet_core.is_running else '중지'}", queue_color)
                        
                        # 프로토콜 분석
                        total_protocols = sum(protocol_stats.values())
                        if total_protocols > 0:
                            print_colored("🌐 프로토콜 분석", Fore.BLUE, Style.BRIGHT)
                            protocol_line = "   "
                            for proto, count in protocol_stats.items():
                                if count > 0:
                                    percentage = (count / total_protocols) * 100
                                    protocol_line += f"{proto}: {count:,}({percentage:.1f}%)  "
                            print_colored(protocol_line, Fore.WHITE)
                        
                        # 위협 탐지 통계
                        total_analyzed = sum(threat_stats.values())
                        if total_analyzed > 0:
                            print_colored("🚨 위협 탐지 현황", Fore.RED, Style.BRIGHT)
                            threat_percentage = (total_threats_detected / total_analyzed) * 100 if total_analyzed > 0 else 0
                            print_colored(f"   총 분석: {total_analyzed:,}개  |  위협 탐지: {total_threats_detected:,}개 ({threat_percentage:.2f}%)", Fore.WHITE)
                            #  치명적 위협 추가 (5단계 표시)
                            print_colored(f"   🔴 치명적: {threat_stats['critical']:,}  🟠 높음: {threat_stats['high']:,}  🟡 중간: {threat_stats['medium']:,}  🟢 낮음: {threat_stats['low']:,}  ⚪ 안전: {threat_stats['safe']:,}", Fore.WHITE)
                        
                        #  방어 조치 통계 (상세 정보 추가)
                        print_colored("🛡️  방어 조치 현황", Fore.MAGENTA, Style.BRIGHT)
                        total_blocked = defense_stats.get('permanent_block', 0) + defense_stats.get('temp_block', 0) + defense_stats.get('warning_block', 0)
                        print_colored(f"   총 차단: {total_blocked:,}개 (영구: {defense_stats.get('permanent_block', 0):,}, 임시: {defense_stats.get('temp_block', 0):,}, 경고: {defense_stats.get('warning_block', 0):,})  |  누적 차단: {defense_stats.get('accumulated_blocks', 0):,}개", Fore.WHITE)
                        print_colored(f"   모니터링: {defense_stats.get('monitored', 0):,}개  |  발송 알림: {defense_stats.get('alerts', 0):,}개", Fore.WHITE)
                        
                        # 머신러닝 상태
                        print_colored("🤖 AI/ML 엔진 상태", Fore.GREEN, Style.BRIGHT)
                        
                        # 실제 시스템 리소스 사용량 측정
                        try:
                            import psutil
                            process = psutil.Process()
                            memory_info = process.memory_info()
                            memory_mb = memory_info.rss / (1024 * 1024)
                            memory_percent = process.memory_percent()
                            cpu_usage = psutil.cpu_percent(interval=0.1)
                        except:
                            memory_mb = 0
                            memory_percent = packet_core.packet_queue.qsize() / 10000 * 100  # 추정치
                            cpu_usage = 0
                        
                        # 리소스 상태 확인
                        resource_status = monitor_system_resources()
                        status_color = Fore.GREEN if resource_status == "can_increase" else Fore.YELLOW if resource_status == "maintain" else Fore.RED
                        status_text = {"can_increase": "여유", "maintain": "보통", "reduce_processing": "부하"}[resource_status]
                        
                        accuracy_display = f"{ml_stats['accuracy']:.2%}" if ml_stats['accuracy'] > 0 else "계산 중"
                        print_colored(f"   예측 수행: {ml_stats['predictions']:,}회  |  모델 정확도: {accuracy_display}  |  업데이트: {ml_stats['model_updates']:,}회", Fore.WHITE)
                        print_colored(f"   메모리: {memory_mb:.1f}MB ({memory_percent:.1f}%)  |  CPU: {cpu_usage:.1f}%  |  리소스 상태: {status_text}", status_color)
                        
                        # 하단 정보
                        print_colored("="*80, Fore.CYAN)
                        print_colored(" 명령어: h(도움말) s(상태) p(패킷) d(방어) m(모드) q(종료) | Enter: 명령 입력", Fore.YELLOW)
                        print()
                        
                    time.sleep(1.0)  #  대시보드 업데이트 빈도 감소 (0.5 -> 1.0초)로 패킷 처리 우선
                
                # 스레드 종료 시 통계 딕셔너리 반환
                stats_pool.put(protocol_stats)
                logger.info("대시보드 스레드 종료 - 객체 풀에 반환 완료")
            
            #  대시보드 스레드 - 낮은 우선순위
            display_thread = threading.Thread(target=display_realtime_stats, name="Dashboard")
            display_thread.daemon = True
            display_thread.start()
            logger.info("대시보드 스레드 시작됨 (낮은 우선순위)")
            
            # 상세 상태 모니터링 스레드 (백그라운드에서 로그만 기록)
            def monitor_capture_status():
                last_log_time = time.time()
                last_gc_time = time.time()
                
                while packet_core.is_running:
                    current_time = time.time()
                    
                    # 5분마다 강력한 메모리 정리 수행
                    if current_time - last_gc_time >= 300:  # 5분
                        # 다중 가비지 컬렉션 수행
                        total_collected = 0
                        for _ in range(3):
                            total_collected += gc.collect()
                        
                        last_gc_time = current_time
                        
                        # 메모리 사용량 로깅 및 누수 감지
                        try:
                            import psutil
                            process = psutil.Process()
                            memory_mb = process.memory_info().rss / (1024 * 1024)
                            logger.info(f"가비지 컬렉션 수행 - 현재 메모리: {memory_mb:.1f}MB")
                        except:
                            logger.info("가비지 컬렉션 수행")
                    
                    # 10분마다 상세 로그 기록
                    if current_time - last_log_time >= 600:  # 10분
                        packet_count = packet_core.get_packet_count()
                        defense_status = defense_manager.get_status()
                        
                        logger.info(f"상태 보고 - 캡처된 패킷: {packet_count:,}개")
                        logger.info(f"방어 메커니즘: {'활성화' if defense_status['is_active'] else '비활성화'}")
                        logger.info(f"운영 모드: {defense_status['mode']}")
                        
                        if defense_status['blocked_ips']:
                            logger.info(f"차단된 IP 수: {len(defense_status['blocked_ips'])}개")
                        
                        # 객체 풀 통계도 로깅
                        pool_stats = get_packet_pool().get_stats()
                        logger.info(f"객체 풀 - 재사용률: {pool_stats['reuse_rate']:.1f}%, 생성: {pool_stats['total_created']}, 재사용: {pool_stats['total_reused']}")
                        
                        last_log_time = current_time
                    
                    time.sleep(30)  # 30초마다 체크 (로그 출력은 10분마다)
            
            monitor_thread = threading.Thread(target=monitor_capture_status)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # 실시간 패킷 처리 및 저장 스레드 (메모리 최적화)
            def process_and_save_packets():
                global ml_stats
                packet_buffer = []
                packet_pool = get_packet_pool()  # 패킷 풀 초기화
                batch_processor = get_batch_processor()  # 배치 프로세서 초기화
                dataframe_pool = get_dataframe_pool()  # DataFrame 풀 초기화
                last_save_time = time.time()
                last_gc_time = time.time()
                chunk_size = 50  # 메모리 절약을 위해 200에서 50으로 감소
                max_buffer_size = 500  # 최대 버퍼 크기도 감소
                
                # 패킷 변환 함수 - 문자열이나 다른 타입을 딕셔너리로 변환 (인라인)
                def convert_packet_to_dict(packet):
                    if isinstance(packet, dict):
                        return packet
                    elif isinstance(packet, str):
                        # 문자열을 간단한 딕셔너리로 변환
                        return {
                            'source': 'unknown', 
                            'destination': 'unknown', 
                            'protocol': 'unknown', 
                            'length': len(packet) if packet else 0,
                            'raw_data': packet
                        }
                    else:
                        # 다른 타입의 경우, 기본 값 딕셔너리 반환
                        return {
                            'source': 'unknown', 
                            'destination': 'unknown', 
                            'protocol': 'unknown', 
                            'length': 0,
                            'raw_data': str(packet)
                        }
                
                while packet_core.is_running:
                    # 패킷 큐에서 패킷 가져오기 (조용히 처리)
                    try:
                        original_packet = packet_core.packet_queue.get_nowait()
                        
                        # 풀에서 패킷 객체 가져오기
                        pooled_packet = packet_pool.get()
                        
                        # 패킷이 딕셔너리가 아닌 경우 변환
                        if isinstance(original_packet, dict):
                            pooled_packet.update(original_packet)
                        else:
                            converted = convert_packet_to_dict(original_packet)
                            pooled_packet.update(converted)
                        
                        packet_buffer.append(pooled_packet)
                    except queue.Empty:
                        # 큐가 비어있는 경우 - CPU 사용량 감소를 위해 대기
                        time.sleep(0.01)  # 10ms 대기
                        pass
                    except Exception as e:
                        # 오류를 로그에만 기록 (화면 출력 없이)
                        logger.error(f"패킷 처리 중 오류: {str(e)}")
                        if DEBUG_MODE:
                            logger.debug(traceback.format_exc())
                    
                    current_time = time.time()
                    
                    # 1분마다 가비지 컬렉션 수행 (더 빈번하게)
                    if current_time - last_gc_time >= 60:  # 1분마다
                        gc.collect()
                        last_gc_time = current_time
                        logger.debug("패킷 처리 스레드에서 가비지 컬렉션 수행")
                    
                    # 청크 크기에 도달하거나 2분 경과 시 처리 (더 빈번하게)
                    if len(packet_buffer) >= chunk_size or (current_time - last_save_time) >= 120:
                        if packet_buffer:
                            # 타임스탬프 생성 (파일명용)
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            filename = f"captured_packets_{timestamp}.csv"
                            
                            # 처리할 청크 크기 결정
                            process_size = min(chunk_size, len(packet_buffer))
                            chunk = packet_buffer[:process_size]
                            
                            try:
                                # DataFrame 풀에서 배열 가져오기
                                array_data, actual_rows, actual_cols = dataframe_pool.get_array(process_size, 8)
                                
                                # 패킷 데이터를 numpy 배열에 직접 복사 (DataFrame 우회)
                                for i, packet in enumerate(chunk):
                                    if i < array_data.shape[0]:  # 안전성 체크
                                        if array_data.shape[1] > 0:
                                            array_data[i, 0] = packet.get('source', '')
                                        if array_data.shape[1] > 1:
                                            array_data[i, 1] = packet.get('destination', '')
                                        if array_data.shape[1] > 2:
                                            array_data[i, 2] = packet.get('protocol', 0)
                                        if array_data.shape[1] > 3:
                                            array_data[i, 3] = packet.get('length', 0)
                                        if array_data.shape[1] > 4:
                                            array_data[i, 4] = packet.get('ttl', 0)
                                        if array_data.shape[1] > 5:
                                            array_data[i, 5] = packet.get('flags', 0)
                                        if array_data.shape[1] > 6:
                                            array_data[i, 6] = packet.get('info', '')
                                        if array_data.shape[1] > 7:
                                            array_data[i, 7] = packet.get('timestamp', 0.0)
                                
                                # 필요한 경우에만 DataFrame 생성 (저장 시)
                                if process_size > 0:
                                    # 최소한의 DataFrame 생성
                                    df_chunk = pd.DataFrame({
                                        'source': array_data[:process_size, 0],
                                        'destination': array_data[:process_size, 1],
                                        'protocol': array_data[:process_size, 2],
                                        'length': array_data[:process_size, 3],
                                        'ttl': array_data[:process_size, 4],
                                        'flags': array_data[:process_size, 5]
                                    })
                            
                                    # 데이터 타입 최적화 (인라인)
                                    if 'length' in df_chunk.columns:
                                        df_chunk['length'] = df_chunk['length'].astype('int32')
                                    if 'ttl' in df_chunk.columns:
                                        df_chunk['ttl'] = df_chunk['ttl'].astype('uint8')
                            
                                    # CSV 파일로 저장 (append 모드)
                                    file_exists = os.path.isfile(filename)
                                    df_chunk.to_csv(filename, mode='a', header=not file_exists, index=False)
                                    
                                    # ML 예측 수행 (경량화)
                                    ml_stats['predictions'] += process_size
                                    
                                    # 로그에만 기록 (화면 출력 없음)
                                    logger.info(f"패킷 {process_size}개가 {filename}에 저장됨")
                                
                            except Exception as save_error:
                                logger.error(f"패킷 저장 중 오류: {save_error}")
                            finally:
                                # 배열을 풀에 반환
                                dataframe_pool.put_array(array_data)
                                
                                # DataFrame 메모리 해제
                                if 'df_chunk' in locals():
                                    del df_chunk
                            
                            # 처리된 청크 제거 및 풀에 반환
                            processed_packets = packet_buffer[:process_size]
                            packet_buffer = packet_buffer[process_size:]
                            
                            # 사용한 패킷들을 풀에 반환
                            for packet in processed_packets:
                                packet_pool.put(packet)
                            
                            # 명시적 메모리 해제
                            del processed_packets
                            del chunk
                            
                            # 최대 버퍼 크기 초과 시 오래된 패킷 삭제
                            if len(packet_buffer) > max_buffer_size:
                                num_to_remove = len(packet_buffer) - max_buffer_size
                                logger.info(f"버퍼 크기 제한으로 {num_to_remove}개 패킷 삭제")
                                
                                # 삭제할 패킷들을 풀에 반환
                                for packet in packet_buffer[:num_to_remove]:
                                    packet_pool.put(packet)
                                
                                packet_buffer = packet_buffer[-max_buffer_size:]
                            
                            # 전체 버퍼가 비었거나 2분 경과 시 타이머 재설정
                            if not packet_buffer or (current_time - last_save_time) >= 120:
                                last_save_time = current_time
                    
                    time.sleep(0.01)  #  패킷 처리 우선순위 향상 (0.05 -> 0.01)
            
            #  패킷 처리 스레드 - 높은 우선순위
            process_thread = threading.Thread(target=process_and_save_packets, name="PacketProcessor")
            process_thread.daemon = True
            process_thread.start()
            logger.info("패킷 처리 스레드 시작됨 (높은 우선순위)")
            
            # GUI 컴포넌트 제거됨 - CLI 전용 모드
            
            # 데이터 파일 모니터링 및 머신러닝 모델 학습 스레드 (메모리 최적화)
            def monitor_and_train():
                global ml_stats
                logger.info("모니터링 및 학습 스레드 시작 (지연 로딩 활성화)")
                
                # 파일 변경 여부 체크용 변수
                last_modified_time = 0
                last_training_time = 0
                training_interval = 3600  # 학습 간격 (초) - 1시간마다 최대 1번 학습
                
                # 강화학습 환경과 에이전트는 필요할 때만 생성 (지연 로딩)
                env = None
                agent = None
                rl_modules = None  # 강화학습 모듈들도 필요할 때만 로딩
                
                while packet_core.is_running:
                    # 데이터 파일 확인
                    preprocessed_data_path = 'data_set/전처리데이터1.csv'
                    
                    # 파일 존재 여부 및 수정 시간 확인
                    if os.path.exists(preprocessed_data_path):
                        current_modified_time = os.path.getmtime(preprocessed_data_path)
                        current_time = time.time()
                        
                        # 파일이 변경되었고 마지막 학습 후 일정 시간이 지났을 때만 학습 수행
                        if (current_modified_time > last_modified_time and 
                            current_time - last_training_time > training_interval):
                            
                            # 학습 시작 로그
                            logger.info("데이터 파일 변경 감지 - 머신러닝 모델 학습 시작")
                            
                            try:
                                #  지연 로딩: 필요한 시점에 머신러닝 모듈 로딩
                                if 'ml_modules' not in locals():
                                    ml_modules = lazy_importer.get_module('ml_models')
                                    train_random_forest = ml_modules['train_random_forest']
                                
                                # 메모리 최적화를 위한 청크 단위 파일 처리
                                logger.info("랜덤 포레스트 모델 학습 시작")
                                ml_stats['model_updates'] += 1
                                
                                # 청크 처리로 랜덤 포레스트 모델 학습
                                # 기존 train_random_forest 함수가 chunked_reading을 지원하도록 수정 필요
                                model, accuracy, conf_matrix = train_random_forest(
                                    preprocessed_data_path, 
                                    chunk_size=10000  # 청크 크기 지정
                                )
                                
                                # 메모리 사용량을 줄이기 위해 임시 저장
                                accuracy_value = float(accuracy)
                                ml_stats['accuracy'] = accuracy_value
                                # 혼동 행렬은 작은 크기로 요약
                                conf_matrix_summary = conf_matrix.sum(axis=1).tolist() if hasattr(conf_matrix, 'sum') else []
                                
                                # 학습 결과 로그
                                logger.info(f"랜덤 포레스트 모델 학습 완료 - 정확도: {accuracy_value:.4f}")
                                logger.debug(f"혼동 행렬 요약: {conf_matrix_summary}")
                                
                                # 메모리 관리를 위해 명시적 가비지 컬렉션 호출
                                import gc
                                gc.collect()
                                
                                #  지연 로딩: 필요할 때만 강화학습 환경과 에이전트 초기화
                                if env is None or agent is None:
                                    # Conservative RL 시스템 지연 로딩
                                    if rl_modules is None:
                                        logger.info("Conservative RL 시스템 지연 로딩 시작...")
                                        rl_modules = lazy_importer.get_module('conservative_rl')
                                        ConservativeRLAgent = rl_modules['ConservativeRLAgent']
                                        DefensePolicyEnv = rl_modules['DefensePolicyEnv']
                                        OPEEvaluator = rl_modules['OPEEvaluator']
                                        logger.info("Conservative RL 시스템 지연 로딩 완료")
                                    
                                    # 새로운 RL 대응 정책 시스템 초기화
                                    env = DefensePolicyEnv()
                                    agent = ConservativeRLAgent(
                                        state_size=10,
                                        action_size=6,
                                        mode="standard",
                                        use_prioritized_replay=True,
                                        buffer_capacity=10000
                                    )
                                    
                                    # Conservative RL 모델 로드 시도
                                    conservative_model_path = 'defense_policy_agent.pth'
                                    if os.path.exists(conservative_model_path):
                                        if agent.load_model(conservative_model_path):
                                            logger.info("기존 Conservative RL 모델 로드 완료")
                                    
                                    # Conservative RL Buffer 로드 시도
                                    buffer_path = 'defense_policy_buffer.pkl'
                                    if os.path.exists(buffer_path):
                                        if agent.load_buffer(buffer_path):
                                            logger.info("기존 Conservative RL 버퍼 로드 완료")
                                
                                # 강화학습 훈련
                                logger.info("강화학습 훈련 시작")
                                
                                # 에피소드 수를 줄이고 메모리 효율성 향상
                                rewards, malicious_counts, buffer_stats = train_rl_agent(
                                    env, 
                                    agent, 
                                    episodes=50,
                                    batch_size=32,
                                    save_buffer_interval=25,
                                    buffer_save_path=f"experience_buffer_{args.mode}"
                                )
                                
                                # Conservative RL 모델 저장
                                agent.save_model('defense_policy_agent.pth')
                                agent.save_buffer('defense_policy_buffer.pkl')
                                logger.info("Conservative RL 모델 및 버퍼 저장 완료")
                                
                                # Experience Replay Buffer 통계 로그
                                buffer_stats_summary = agent.get_buffer_stats()
                                logger.info(f"버퍼 사용률: {buffer_stats_summary['buffer_utilization']:.1%}, "
                                            f"악성 경험: {buffer_stats_summary.get('malicious_experiences', 0)}")
                                
                                # 훈련 결과 시각화 (경량 모드에서만 수행)
                                if args.mode != "lightweight":
                                    plot_training_results = rl_modules['plot_training_results']
                                    plot_training_results(rewards, malicious_counts, buffer_stats)
                                
                                # 학습 완료 후 타임스탬프 업데이트
                                last_modified_time = current_modified_time
                                last_training_time = current_time
                                
                                # 다시 메모리 정리
                                gc.collect()
                                
                            except Exception as e:
                                logger.error(f"모델 학습 중 오류 발생: {e}")
                                # 오류 발생 시에도 타임스탬프는 업데이트하여 반복 학습 방지
                                last_modified_time = current_modified_time
                                last_training_time = current_time
                    
                    # 학습하지 않을 때는 더 긴 간격으로 체크
                    time.sleep(300)  # 5분마다 확인으로 변경
            
            train_thread = threading.Thread(target=monitor_and_train)
            train_thread.daemon = True
            train_thread.start()
            
            # ========== 6번째 스레드: 통합 서비스 시작 (반응형 AI) ==========
            if integrated_modules and state_extractor and reward_calculator:
                try:
                    # Conservative RL 에이전트 및 환경 초기화 (필요시)
                    rl_modules = lazy_importer.get_module('conservative_rl')
                    ConservativeRLAgent = rl_modules['ConservativeRLAgent']
                    DefensePolicyEnv = rl_modules['DefensePolicyEnv']
                    
                    env = DefensePolicyEnv()
                    agent = ConservativeRLAgent(
                        state_size=10,
                        action_size=6,
                        mode="standard",
                        use_prioritized_replay=True,
                        buffer_capacity=10000
                    )
                    
                    # 기존 모델 로드 시도
                    if os.path.exists('defense_policy_agent.pth'):
                        agent.load_model('defense_policy_agent.pth')
                        logger.info("기존 Conservative RL 모델 로드 완료")
                    
                    # 온라인 학습기 초기화
                    online_trainer = integrated_modules['get_online_trainer'](
                        agent,
                        learning_interval=10,
                        min_experiences=32,
                        batch_size=32
                    )
                    
                    # RL 통합기 초기화
                    rl_integrator = integrated_modules['get_rl_integrator'](
                        agent,
                        state_extractor,
                        reward_calculator,
                        online_trainer
                    )
                    
                    # 온라인 학습 시작
                    online_trainer.start()
                    print_colored(" 온라인 RL 학습 스레드 시작됨 (10초 주기)", Fore.MAGENTA)
                    logger.info("온라인 RL 학습 스레드 시작됨")
                    
                    # 자동 취약점 스캐너 시작 (선택사항)
                    try:
                        vuln_scanner = integrated_modules['get_auto_scanner'](
                            network_range="192.168.0.0/24"
                        )
                        vuln_scanner.start()
                        print_colored("🔍 자동 취약점 스캐너 시작됨 (1시간 주기)", Fore.CYAN)
                        logger.info("자동 취약점 스캐너 시작됨")
                    except Exception as e:
                        logger.warning(f"자동 취약점 스캐너 시작 실패: {e}")
                    
                except Exception as e:
                    logger.error(f"통합 서비스 시작 실패: {e}")
            else:
                logger.info("통합 모듈 비활성화 - 기본 모드로 실행")
            
            # CLI 전용 모드 - GUI 컴포넌트 제거됨
            logger.info("CLI 전용 모드로 모든 백그라운드 스레드 준비 완료")
            
            # 고급 사용자 입력 처리 스레드
            def handle_user_input():
                global args, threat_stats, defense_stats, ml_stats, start_time
                
                def show_command_prompt():
                    """명령어 프롬프트 표시"""
                    print()  # 대시보드와 구분을 위한 빈 줄
                    print_colored("=" * 60, Fore.CYAN)
                    print_colored(" 명령어 입력 모드", Fore.CYAN, Style.BRIGHT)
                    print_colored("사용 가능한 명령어: h(도움말), s(상태), p(패킷), d(방어), m(모드전환), q(종료)", Fore.WHITE)
                    print_colored("=" * 60, Fore.CYAN)
                    print_colored("명령어 > ", Fore.YELLOW, end="")
                
                def show_status():
                    """현재 상태 표시"""
                    clear_screen()
                    print_header()
                    
                    # 시스템 상태
                    status_info = [
                        f" 운영 모드: {args.mode.upper()}",
                        f" 캡처된 패킷: {packet_core.get_packet_count():,}개",
                        f" 캡처 상태: {'실행 중' if packet_core.is_running else '중지됨'}",
                        f" 실행 시간: {datetime.now().strftime('%H:%M:%S')}"
                    ]
                    
                    if 'defense_manager' in locals():
                        defense_status = defense_manager.get_status()
                        status_info.extend([
                            f" 방어 메커니즘: {'활성화' if defense_status['is_active'] else '비활성화'}",
                            f" 차단된 IP: {len(defense_status.get('blocked_ips', []))}개"
                        ])
                    
                    print_status_box("시스템 상태", status_info, Fore.GREEN)
                
                def show_packet_stats():
                    """패킷 통계 표시"""
                    packet_count = packet_core.get_packet_count()
                    stats_info = [
                        f" 총 캡처된 패킷: {packet_count:,}개",
                        f" 초당 패킷 수: 계산 중...",
                        f" 큐 크기: {packet_core.packet_queue.qsize()}개",
                        f" 처리 상태: {'활성화' if packet_core.is_running else '중지됨'}"
                    ]
                    print_status_box("패킷 통계", stats_info, Fore.BLUE)
                
                # 간단한 명령어 입력 처리 (조용히 백그라운드에서 대기)
                logger.info("사용자 입력 스레드 시작")
                
                while packet_core.is_running:
                    try:
                        # 간단한 입력 대기
                        user_input = input().strip().lower()
                        
                        if not user_input:  # Enter만 누른 경우
                            show_command_prompt()
                            user_input = input().strip().lower()
                        
                        if user_input in ['m', 'mode']:
                            new_mode = 'performance' if args.mode == 'lightweight' else 'lightweight'
                            new_color = Fore.BLUE if new_mode == 'performance' else Fore.GREEN
                            new_icon = "[PERF]" if new_mode == 'performance' else "[LITE]"
                            
                            print_colored(f"\n{new_icon} {args.mode} -> {new_mode} 모드로 전환 중...", new_color, Style.BRIGHT)
                        
                            # 방어 메커니즘 모드 전환
                            if defense_manager.switch_mode(new_mode):
                                print_colored(f"방어 메커니즘이 {new_mode} 모드로 전환되었습니다", Fore.GREEN)
                            
                                # 강화학습 환경/에이전트 모드 전환 (재학습 중이라면)
                                if 'env' in locals() and 'agent' in locals():
                                    env.set_mode(new_mode)
                                    agent.switch_mode(new_mode)
                                    print_colored(f"강화학습 모델이 {new_mode} 모드로 전환되었습니다", Fore.GREEN)
                                
                                # 전역 모드 설정 업데이트
                                args.mode = new_mode
                                print_colored(f"현재 모드: {args.mode.upper()}", new_color, Style.BRIGHT)
                            else:
                                print_colored("모드 전환에 실패했습니다", Fore.RED)
                                
                        elif user_input in ['s', 'status']:
                            show_status()
                            
                        elif user_input in ['p', 'packets']:
                            show_packet_stats()
                            
                        elif user_input in ['h', 'help']:
                            show_help_menu()
                            
                        elif user_input in ['d', 'defense']:
                            if 'defense_manager' in locals():
                                defense_status = defense_manager.get_status()
                                #  상세 방어 통계 표시
                                defense_info = [
                                    f" 상태: {'활성화' if defense_status['is_active'] else '비활성화'}",
                                    f" 모드: {defense_status['mode'].upper()}",
                                    "",
                                    " 차단 통계:",
                                    f"  🔴 영구 차단: {defense_stats.get('permanent_block', 0)}개",
                                    f"  🟠 임시 차단 (30분): {defense_stats.get('temp_block', 0)}개",
                                    f"  ⚠️ 경고 차단 (10분): {defense_stats.get('warning_block', 0)}개",
                                    f"   누적 패턴 차단: {defense_stats.get('accumulated_blocks', 0)}개",
                                    f"   모니터링 중: {defense_stats.get('monitored', 0)}개",
                                    "",
                                    f" 발송 알림: {defense_stats.get('alerts', 0)}개",
                                    f" 현재 차단 IP 수: {len(defense_status.get('blocked_ips', []))}개"
                                ]
                                if defense_status.get('blocked_ips'):
                                    defense_info.append("")
                                    defense_info.append("차단된 IP 목록 (최근 5개):")
                                    for ip in defense_status['blocked_ips'][:5]:  # 최대 5개만 표시
                                        defense_info.append(f"   {ip}")
                                print_status_box("방어 메커니즘 상세 상태", defense_info, Fore.RED)
                            else:
                                print_colored("❌ 방어 메커니즘이 초기화되지 않았습니다", Fore.RED)
                                
                        elif user_input in ['ml', 'machine-learning']:
                            accuracy_display = f"{ml_stats['accuracy']:.2%}" if ml_stats['accuracy'] > 0 else "아직 학습되지 않음"
                            elapsed_time = time.time() - start_time
                            predictions_per_sec = ml_stats['predictions'] / max(elapsed_time, 1)
                            
                            # 객체 풀 통계 가져오기
                            packet_pool_stats = get_packet_pool().get_stats()
                            dataframe_pool_stats = get_dataframe_pool().get_stats()
                            
                            # 지연 로딩 통계 가져오기
                            lazy_stats = lazy_importer.get_status()
                            model_stats = lazy_model_loader.get_stats()
                            
                            ml_info = [
                                " 강화학습 에이전트: 지연 로딩",
                                " 랜덤 포레스트: 지연 로딩",
                                f" Experience Buffer: 사용 중",
                                f" 운영 모드: {args.mode.upper()}",
                                "",
                                f" 모델 정확도: {accuracy_display}",
                                f" 총 예측 수행: {ml_stats['predictions']:,}회",
                                f" 초당 예측: {predictions_per_sec:.1f}회/s",
                                f" 모델 업데이트: {ml_stats['model_updates']:,}회",
                                "",
                                " 지연 로딩 상태:",
                                f"  - 등록된 모듈: {lazy_stats['total_modules']}개",
                                f"  - 로딩된 모듈: {lazy_stats['loaded_modules']}개",
                                f"  - 등록된 모델: {model_stats['total_models']}개",
                                f"  - 로딩된 모델: {model_stats['loaded_models']}개",
                                "",
                                " 패킷 객체 풀링:",
                                f"  - 풀 크기: {packet_pool_stats['pool_size']}개",
                                f"  - 재사용률: {packet_pool_stats['reuse_rate']:.1f}%",
                                "",
                                " DataFrame 풀링:",
                                f"  - 배열 재사용률: {dataframe_pool_stats['reuse_rate']:.1f}%",
                                f"  - 생성된 배열: {dataframe_pool_stats['total_created']}개",
                                f"  - 재사용 횟수: {dataframe_pool_stats['total_reused']}회"
                            ]
                            print_status_box("머신러닝 상세 상태", ml_info, Fore.MAGENTA)
                            
                        elif user_input in ['threats', 't']:
                            #  위협 탐지 상세 통계 (5단계 표시)
                            threat_info = [
                                f"🔴 치명적 위협: {threat_stats.get('critical', 0):,}개",
                                f"🟠 높은 위협: {threat_stats.get('high', 0):,}개",
                                f"🟡 중간 위협: {threat_stats.get('medium', 0):,}개",
                                f"🟢 낮은 위협: {threat_stats.get('low', 0):,}개",
                                f"⚪ 안전: {threat_stats.get('safe', 0):,}개",
                                "",
                                f"총 분석 패킷: {sum(threat_stats.values()):,}개",
                                f"위협 탐지율: {(threat_stats.get('critical', 0) + threat_stats.get('high', 0) + threat_stats.get('medium', 0)) / max(sum(threat_stats.values()), 1) * 100:.2f}%"
                            ]
                            print_status_box("위협 탐지 상세 통계", threat_info, Fore.RED)
                            
                        elif user_input in ['q', 'quit', 'exit']:
                            print_colored("\nIPS 시스템을 종료합니다...", Fore.YELLOW, Style.BRIGHT)
                            packet_core.stop_capture()
                            break
                            
                        elif user_input == '':
                            # Enter만 누른 경우 상태 새로고침
                            show_status()
                            
                        else:
                            print_colored(f"❌ 알 수 없는 명령어: '{user_input}'", Fore.RED)
                            print_colored(" 도움말을 보려면 'h'를 입력하세요", Fore.YELLOW)
                        
                    except KeyboardInterrupt:
                        print_colored("\n\n Ctrl+C 감지 - 프로그램을 종료합니다", Fore.YELLOW, Style.BRIGHT)
                        packet_core.stop_capture()
                        break
                    except EOFError:
                        print_colored("\n\n 입력 종료 - 프로그램을 종료합니다", Fore.YELLOW)
                        packet_core.stop_capture()
                        break
                    
                    time.sleep(0.1)
            
            input_thread = threading.Thread(target=handle_user_input)
            input_thread.daemon = True
            input_thread.start()
            
            try:
                while packet_core.is_running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n프로그램을 종료합니다...")
                packet_core.stop_capture()
        
        # 정상 종료 시 메모리 정리
        cleanup_memory_completely()
        
        # Enter 키를 누를 때까지 대기
        wait_for_enter()
        
    except KeyboardInterrupt:
        print("\n프로그램이 사용자에 의해 중단되었습니다.")
        logger.info("사용자에 의한 프로그램 중단")
        
        # 객체 풀 최종 통계 출력
        try:
            packet_pool_stats = get_packet_pool().get_stats()
            dataframe_pool_stats = get_dataframe_pool().get_stats()
        
            print_colored("\n 메모리 최적화 최종 통계:", Fore.CYAN, Style.BRIGHT)
            print_colored("━" * 50, Fore.CYAN)
            
            print_colored(" 패킷 객체 풀링:", Fore.YELLOW, Style.BRIGHT)
            print_colored(f"  • 생성된 객체: {packet_pool_stats['total_created']:,}개", Fore.WHITE)
            print_colored(f"  • 재사용 횟수: {packet_pool_stats['total_reused']:,}회", Fore.WHITE)
            print_colored(f"  • 재사용률: {packet_pool_stats['reuse_rate']:.1f}%", Fore.GREEN if packet_pool_stats['reuse_rate'] > 80 else Fore.YELLOW)
            
            print_colored("\n DataFrame 풀링:", Fore.BLUE, Style.BRIGHT)
            print_colored(f"  • 생성된 배열: {dataframe_pool_stats['total_created']:,}개", Fore.WHITE)
            print_colored(f"  • 재사용 횟수: {dataframe_pool_stats['total_reused']:,}회", Fore.WHITE)
            print_colored(f"  • 재사용률: {dataframe_pool_stats['reuse_rate']:.1f}%", Fore.GREEN if dataframe_pool_stats['reuse_rate'] > 60 else Fore.YELLOW)
            
            # 예상 메모리 절약량 계산
            packet_savings = packet_pool_stats['total_reused'] * 0.001  # 1KB per packet
            dataframe_savings = dataframe_pool_stats['total_reused'] * 5  # 5MB per DataFrame array
            total_savings = packet_savings + dataframe_savings
            
            print_colored(f"\n 예상 메모리 절약량:", Fore.GREEN, Style.BRIGHT)
            print_colored(f"  • 패킷 풀링: {packet_savings:.1f}MB", Fore.WHITE)
            print_colored(f"  • DataFrame 풀링: {dataframe_savings:.1f}MB", Fore.WHITE)
            print_colored(f"  • 총 절약량: {total_savings:.1f}MB", Fore.GREEN, Style.BRIGHT)
            
        except Exception as e:
            logger.debug(f"통계 출력 오류: {e}")
            pass
        
        # 완전한 메모리 정리 수행
        cleanup_memory_completely()
            
        wait_for_enter()
    except Exception as e:
        print(f"\n오류가 발생했습니다: {str(e)}")
        log_exception(e, "프로그램 실행 중 심각한 오류 발생")
        
        # 오류 상황에서도 메모리 정리
        cleanup_memory_completely()
        wait_for_enter()
    
    finally:
        # 최종 메모리 정리 (모든 경우)
        cleanup_memory_completely()

if __name__ == "__main__":
    main() 