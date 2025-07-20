# -*- coding: utf-8 -*-

"""
강화학습을 사용한 IDS시스템

이 스크립트는 랜덤포레스트와 강화학습을 사용한 네트워크 보안 시스템을 구현합니다.
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
    filename=os.path.join(log_dir, "ids_debug.log"),
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

logger = logging.getLogger('IDSAgent')
logger.info("로깅 시스템 초기화 완료")

# 명령행 인수 처리
parser = argparse.ArgumentParser(description='IDS 시스템 실행 옵션')
parser.add_argument('--mode', type=str, choices=['lightweight', 'performance'], 
                    help='IDS 운영 모드 선택 (lightweight 또는 performance)')
parser.add_argument('--max-packets', type=int, default=0, 
                    help='캡처할 최대 패킷 수 (0: 무제한)')
parser.add_argument('--no-menu', action='store_true',
                    help='모드 선택 메뉴를 표시하지 않고 기본 모드(lightweight)로 실행')
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
            from packet_capture import PacketCapture, PacketCaptureCore, preprocess_packet_data
            use_optimized_capture = False
            logger.info("기본 패킷 캡처 모듈 사용")
    
    # preprocess_packet_data는 항상 packet_capture에서 가져옴
    if use_optimized_capture:
        from packet_capture import preprocess_packet_data
    
    # 지연 로딩 시스템 초기화
    from lazy_loading import get_lazy_importer, get_lazy_model_loader
    
    # 기본 모듈들 (즉시 로딩 필요)
    from utils import is_colab, is_admin, run_as_admin, clear_screen, wait_for_enter, syn_scan
    from defense_mechanism import create_defense_manager, register_to_packet_capture
    from threat_alert_system import ThreatAlertSystem  # 위협 알림 시스템 추가
    from memory_optimization import get_packet_pool, get_stats_pool, get_batch_processor, get_dataframe_pool  # 객체 풀링 추가
    
    # 지연 로딩 모듈들 등록
    lazy_importer = get_lazy_importer()
    lazy_model_loader = get_lazy_model_loader()
    
    #  PyTorch/강화학습 모듈들 지연 로딩 등록 (100-150MB 절약)
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
    
    lazy_importer.register_module('reinforcement_learning', _import_reinforcement_learning)
    
    #  머신러닝 모델 모듈들 지연 로딩 등록 (15-25MB 절약)
    def _import_ml_models():
        from ml_models import train_random_forest, add_rf_predictions
        return {
            'train_random_forest': train_random_forest,
            'add_rf_predictions': add_rf_predictions
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
        return joblib.load('random_forest_model.pkl')
    
    def _load_dqn_model(mode):
        import torch
        return torch.load(f'dqn_model_{mode}.pth')
    
    lazy_model_loader.register_model('random_forest', 'random_forest_model.pkl', _load_random_forest)
    
    logger.info("지연 로딩 시스템 초기화 완료 - 메모리 절약 예상: 125-195MB")
    
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
    """메인 헤더 출력"""
    clear_screen()
    print_colored("=" * 80, Fore.CYAN, Style.BRIGHT)
    print_colored("""
    ██╗██████╗ ███████╗     █████╗  ██████╗ ███████╗███╗   ██╗████████╗
    ██║██╔══██╗██╔════╝    ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
    ██║██║  ██║███████╗    ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   
    ██║██║  ██║╚════██║    ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   
    ██║██████╔╝███████║    ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   
    ╚═╝╚═════╝ ╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   
    """, Fore.CYAN, Style.BRIGHT)
    
    print_colored("             지능형 침입 탐지 시스템 (IDS Agent)  ", Fore.YELLOW, Style.BRIGHT)
    print_colored("                    강화학습 & 머신러닝 기반", Fore.GREEN)
    print_colored("=" * 80, Fore.CYAN, Style.BRIGHT)
    print()

def print_system_info():
    """시스템 정보 출력"""
    print_colored("📊 시스템 정보", Fore.YELLOW, Style.BRIGHT)
    print_colored("-" * 40, Fore.YELLOW)
    
    # 현재 시간
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print_colored(f"⏰ 현재 시간: {current_time}", Fore.WHITE)
    
    # 운영체제 정보
    os_name = "Windows" if os.name == 'nt' else "Linux/Unix"
    print_colored(f"💻 운영체제: {os_name}", Fore.WHITE)
    
    # Python 버전
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    print_colored(f"🐍 Python 버전: {python_version}", Fore.WHITE)
 
    print()

def print_feature_overview():
    """기능 개요 출력"""
    print_colored("🚀 주요 기능", Fore.YELLOW, Style.BRIGHT)
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
    
    print_colored("⚙️  운영 모드 선택", Fore.YELLOW, Style.BRIGHT)
    print_colored("=" * 60, Fore.YELLOW)
    print()
    
    # 경량 모드 설명
    print_colored("1️⃣  경량 모드 (Lightweight Mode)", Fore.GREEN, Style.BRIGHT)
    print_colored("   ┌─────────────────────────────────────────────────┐", Fore.GREEN)
    print_colored("   │  빠른 실행 속도                                  │", Fore.WHITE)
    print_colored("   │  낮은 자원 사용량                                │", Fore.WHITE)
    print_colored("   │  기본 특성 7개 사용                              │", Fore.WHITE)
    print_colored("   │  모든 환경에서 실행 가능                          │", Fore.WHITE)
    print_colored("   └─────────────────────────────────────────────────┘", Fore.GREEN)
    print()
    
    # 고성능 모드 설명
    print_colored("2️⃣  고성능 모드 (Performance Mode)", Fore.BLUE, Style.BRIGHT)
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
                print_colored("✅ 경량 모드가 선택되었습니다!", Fore.GREEN, Style.BRIGHT)
                time.sleep(1)
                return "lightweight"
            elif choice == "2":
                print_colored("✅ 고성능 모드가 선택되었습니다!", Fore.BLUE, Style.BRIGHT)
                time.sleep(1)
                return "performance"
            else:
                print_colored("❌ 잘못된 입력입니다. 1 또는 2를 입력하세요.", Fore.RED)
        except ValueError:
            print_colored("❌ 잘못된 입력입니다. 숫자를 입력하세요.", Fore.RED)
        except KeyboardInterrupt:
            print_colored("\n\n👋 프로그램을 종료합니다.", Fore.YELLOW)
            sys.exit(0)

def show_startup_animation():
    """시작 애니메이션"""
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    
    print_colored("🚀 IDS 시스템을 초기화하는 중", Fore.CYAN, Style.BRIGHT, end="")
    
    for i in range(20):
        print_colored(f"\r🚀 IDS 시스템을 초기화하는 중 {frames[i % len(frames)]}", Fore.CYAN, Style.BRIGHT, end="")
        time.sleep(0.1)
    
    print_colored("\r✅ IDS 시스템 초기화 완료!                    ", Fore.GREEN, Style.BRIGHT)
    time.sleep(0.5)

def print_status_box(title, content, color=Fore.WHITE):
    """상태 박스 출력"""
    box_width = 60
    title_line = f"📋 {title}"
    
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
        str: 위협 수준 ('high', 'medium', 'low', 'safe')
    """
    try:
        if not isinstance(packet, dict):
            return 'safe'
        
        # 방어 메커니즘 관리자를 통한 분석 (우선순위 1)
        if defense_manager and hasattr(defense_manager, 'auto_defense'):
            try:
                # AutoDefenseActions의 analyze_packet 메서드 활용
                prediction, confidence = defense_manager.auto_defense.analyze_packet(packet)
                
                # 예측 결과와 신뢰도를 바탕으로 위협 수준 결정
                if prediction == 1:  # 공격으로 분류됨
                    if confidence >= 0.9:
                        return 'high'
                    elif confidence >= 0.8:
                        return 'medium'
                    elif confidence >= 0.7:
                        return 'low'
                    else:
                        return 'safe'
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
        
        # 점수를 위협 수준으로 변환 (방어 모듈의 신뢰도 기준과 일치)
        if threat_score >= 0.9:
            return 'high'
        elif threat_score >= 0.8:
            return 'medium'  
        elif threat_score >= 0.7:
            return 'low'
        else:
            return 'safe'
            
    except Exception as e:
        logger.debug(f"위협 분석 중 오류: {e}")
        return 'safe'

def show_help_menu():
    """도움말 메뉴"""
    print_header()
    
    print_colored("📖 도움말", Fore.YELLOW, Style.BRIGHT)
    print_colored("=" * 60, Fore.YELLOW)
    
    help_content = [
        "🔧 사용 가능한 명령어:",
        "",
        "m, mode     - 운영 모드 전환",
        "s, status   - 시스템 상태 확인",
        "h, help     - 이 도움말 표시",
        "q, quit     - 프로그램 종료",
        "",
        "📊 통계 명령어:",
        "packets     - 캡처된 패킷 통계",
        "defense     - 방어 메커니즘 상태",
        "ml          - 머신러닝 모델 상태",
        "threats     - 위협 탐지 상세 통계",
        "",
        "⚡ 단축키:",
        "Ctrl+C      - 강제 종료",
        "Enter       - 상태 새로고침"
    ]
    
    print_status_box("명령어 가이드", help_content, Fore.CYAN)
    print()
    print_colored("계속하려면 Enter 키를 누르세요...", Fore.YELLOW)
    input()

def main():
    # 전역 통계 변수들
    global threat_stats, defense_stats, ml_stats, start_time
    threat_stats = {'high': 0, 'medium': 0, 'low': 0, 'safe': 0}
    defense_stats = {'blocked': 0, 'monitored': 0, 'alerts': 0}
    ml_stats = {'predictions': 0, 'accuracy': 0.0, 'model_updates': 0}
    start_time = time.time()
    
    try:
        # 시작 애니메이션
        show_startup_animation()
        
        # 모드 선택 (CLI 인수 또는 메뉴)
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
        print_colored(f"🔍 환경 확인: {'Google Colab' if colab_status else '로컬 환경'}", Fore.CYAN)
        
        if colab_status:
            logger.info("Google Colab 환경에서 실행 중")
            print_colored("⚠️  Google Colab 환경 감지", Fore.YELLOW, Style.BRIGHT)
            print_colored("📚 머신러닝 모델 학습만 가능합니다", Fore.YELLOW)
            print_colored("🚫 패킷 캡처 기능은 로컬 환경에서만 사용 가능", Fore.YELLOW)
            
            # 데이터 파일이 있는 경우에만 머신러닝 모델 학습 실행
            preprocessed_data_path = 'data_set/전처리데이터1.csv'
            if os.path.exists(preprocessed_data_path):
                print("\n데이터 파일을 찾았습니다. 머신러닝 모델 학습을 시작합니다...")
                
                # 🔥 지연 로딩: 필요한 시점에 머신러닝 모듈 로딩
                print("머신러닝 모듈 로딩 중...")
                ml_modules = lazy_importer.get_module('ml_models')
                train_random_forest = ml_modules['train_random_forest']
                
                # 랜덤 포레스트 모델 학습
                model, accuracy, conf_matrix = train_random_forest(preprocessed_data_path)
                
                # 🔥 지연 로딩: 필요한 시점에 강화학습 모듈 로딩
                print("강화학습 모듈 로딩 중...")
                rl_modules = lazy_importer.get_module('reinforcement_learning')
                NetworkEnv = rl_modules['NetworkEnv']
                DQNAgent = rl_modules['DQNAgent']
                train_rl_agent = rl_modules['train_rl_agent']
                
                # 강화학습 환경과 에이전트 초기화 (모드 적용)
                env = NetworkEnv(max_steps=1000, mode=args.mode)
                state_size = env.observation_space.shape[0]
                action_size = env.action_space.n
                
                # 새로운 Experience Replay Buffer를 사용하는 DQNAgent 초기화
                agent = DQNAgent(
                    state_size, 
                    action_size, 
                    mode=args.mode,
                    use_prioritized_replay=True,  # Prioritized Experience Replay 사용
                    replay_buffer_capacity=10000  # 버퍼 크기 설정
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
            
        # 여기서부터 로컬 환경 코드
        
        # 시작 로그
        logger.info("로컬 환경에서 IDS 시스템 실행 시작")
        
        # 관리자 권한 확인 및 필요시 재실행 (Windows 환경에서만)
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
        
        # 화면 초기화
        clear_screen()
        
        # 패킷 캡처 코어 초기화
        logger.info("패킷 캡처 코어 초기화 중...")
        if use_optimized_capture:
            # 최적화된 멀티프로세싱 캡처 사용
            packet_core = OptimizedPacketCapture()
            logger.info(f"멀티프로세싱 패킷 캡처 활성화 (워커: {packet_core.num_workers}개)")
        else:
            packet_core = PacketCaptureCore()
        
        # 방어 메커니즘 초기화 (선택한 모드 적용)
        logger.info(f"{args.mode} 모드로 방어 메커니즘 초기화 중...")
        defense_manager = create_defense_manager('defense_config.json', mode=args.mode)
        
        # 패킷 캡처 코어에 방어 메커니즘 등록
        if register_to_packet_capture(defense_manager, packet_core):
            logger.info("방어 메커니즘이 패킷 캡처 시스템에 성공적으로 등록되었습니다.")
        else:
            logger.error("방어 메커니즘 등록 실패")
        
        # Windows 환경에서만 Npcap 설치 확인
        if os.name == 'nt':
            if not packet_core.check_npcap():
                print("Npcap이 설치되어 있지 않습니다. 패킷 캡처 기능을 사용할 수 없습니다.")
                print("Npcap을 설치한 후 다시 시도해주세요.")
                wait_for_enter()
                return
        
        # 네트워크 인터페이스 목록 가져오기
        interfaces = packet_core.get_network_interfaces()
        
        # 와이파이 인터페이스 찾기
        selected_interface = None
        wifi_keywords = ['wifi', 'wireless', 'wi-fi', 'wlan']
        
        for interface in interfaces:
            interface_lower = interface.lower()
            if any(keyword in interface_lower for keyword in wifi_keywords):
                selected_interface = interface
                break
        
        if not selected_interface:
            print("와이파이 인터페이스를 찾을 수 없습니다.")
            print("사용 가능한 인터페이스 목록:")
            for i, interface in enumerate(interfaces, 1):
                print(f"{i}. {interface}")
            
            # 사용자가 인터페이스 직접 선택
            try:
                choice = int(input("\n사용할 인터페이스 번호를 입력하세요: "))
                if 1 <= choice <= len(interfaces):
                    selected_interface = interfaces[choice-1]
                else:
                    print("잘못된 선택입니다.")
                    wait_for_enter()
                    return
            except ValueError:
                print("숫자를 입력해야 합니다.")
                wait_for_enter()
                return
        
        logger.info(f"선택된 인터페이스: {selected_interface}")
        
        # 백그라운드에서 패킷 캡처 시작
        print_colored(f"\n🔗 {selected_interface}에서 패킷 캡처를 시작합니다...", Fore.CYAN)
        if packet_core.start_capture(selected_interface, max_packets=args.max_packets):
            print_colored("✅ 패킷 캡처가 백그라운드에서 시작되었습니다.", Fore.GREEN)
            print_colored("🎛️  실시간 대시보드 모드로 전환합니다.", Fore.YELLOW)
            print()
            
            # 강화된 실시간 대시보드 표시 스레드
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
                
                # 조용히 시작 (로그에만 기록)
                logger.info("강화된 실시간 대시보드 모니터링 시작 (객체 풀링 활성화)")
                
                # 첫 번째 대시보드 즉시 표시
                show_initial_dashboard = True
                
                while packet_core.is_running:
                    current_count = packet_core.get_packet_count()
                    current_time = time.time()
                    elapsed_time = current_time - start_time
                    
                    # 초당 패킷 수 계산
                    if current_time - last_stats_time >= 1.0:  # 1초마다 계산
                        packets_per_second = current_count - last_packet_count
                        if packets_per_second > peak_packets_per_second:
                            peak_packets_per_second = packets_per_second
                        last_packet_count = current_count
                        last_stats_time = current_time
                    
                    # 큐에서 패킷을 가져와서 통계 업데이트
                    packet_pool = get_packet_pool()  # 패킷 풀 가져오기
                    try:
                        processed_count = 0
                        while not packet_core.packet_queue.empty() and processed_count < 50:  # 한 번에 최대 50개만 처리
                            original_packet = packet_core.packet_queue.get_nowait()
                            processed_count += 1
                            
                            # 풀에서 패킷 객체 가져와서 사용
                            pooled_packet = packet_pool.get()
                            
                            try:
                                if isinstance(original_packet, dict):
                                    # 원본 데이터를 풀 객체에 복사
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
                                
                                if threat_level in ['high', 'medium']:
                                    total_threats_detected += 1
                            finally:
                                # 사용 완료 후 풀에 반환
                                packet_pool.put(pooled_packet)
                                
                    except queue.Empty:
                        pass
                    except Exception as e:
                        logger.debug(f"패킷 처리 중 오류: {e}")  # 조용히 처리
                    
                    # 방어 메커니즘 통계 수집
                    try:
                        if 'defense_manager' in locals():
                            defense_status = defense_manager.get_status()
                            defense_stats['blocked'] = len(defense_status.get('blocked_ips', []))
                    except:
                        pass
                    
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
                        print_colored("                    📊 IDS 실시간 모니터링 대시보드 📊", Fore.CYAN, Style.BRIGHT)
                        print_colored("🛡️" + "="*78 + "🛡️", Fore.CYAN, Style.BRIGHT)
                        
                        # 시스템 상태 섹션
                        print_colored(f"⏱️  시스템 가동시간: {runtime_str}  |  🛡️  운영모드: {args.mode.upper()}  |  📡 인터페이스: {selected_interface}", Fore.GREEN)
                        print_colored("-" * 80, Fore.WHITE)
                        
                        # 패킷 캡처 통계
                        print_colored("📦 패킷 캡처 통계", Fore.YELLOW, Style.BRIGHT)
                        print_colored(f"   총 캡처: {current_count:,}개  |  초당 패킷: {packets_per_second}/s  |  최고 처리량: {peak_packets_per_second}/s", Fore.WHITE)
                        print_colored(f"   큐 크기: {packet_core.packet_queue.qsize():,}개  |  처리 상태: {'🟢 활성' if packet_core.is_running else '🔴 중지'}", Fore.WHITE)
                        
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
                            print_colored(f"   🔴 높음: {threat_stats['high']:,}  🟡 중간: {threat_stats['medium']:,}  🟢 낮음: {threat_stats['low']:,}  ⚪ 안전: {threat_stats['safe']:,}", Fore.WHITE)
                        
                        # 방어 조치 통계
                        print_colored("🛡️  방어 조치 현황", Fore.MAGENTA, Style.BRIGHT)
                        print_colored(f"   차단된 IP: {defense_stats['blocked']:,}개  |  모니터링 중: {defense_stats['monitored']:,}개  |  발송 알림: {defense_stats['alerts']:,}개", Fore.WHITE)
                        
                        # 머신러닝 상태
                        print_colored("🤖 AI/ML 엔진 상태", Fore.GREEN, Style.BRIGHT)
                        
                        # 실제 메모리 사용량 측정
                        try:
                            import psutil
                            process = psutil.Process()
                            memory_info = process.memory_info()
                            memory_mb = memory_info.rss / (1024 * 1024)
                            memory_percent = process.memory_percent()
                        except:
                            memory_mb = 0
                            memory_percent = packet_core.packet_queue.qsize() / 10000 * 100  # 추정치
                        
                        accuracy_display = f"{ml_stats['accuracy']:.2%}" if ml_stats['accuracy'] > 0 else "계산 중"
                        print_colored(f"   예측 수행: {ml_stats['predictions']:,}회  |  모델 정확도: {accuracy_display}  |  업데이트: {ml_stats['model_updates']:,}회", Fore.WHITE)
                        print_colored(f"   메모리 사용: {memory_mb:.1f}MB ({memory_percent:.1f}%)", Fore.WHITE)
                        
                        # 하단 정보
                        print_colored("="*80, Fore.CYAN)
                        print_colored("💡 명령어: h(도움말) s(상태) p(패킷) d(방어) m(모드) q(종료) | Enter: 명령 입력", Fore.YELLOW)
                        print()
                        
                    time.sleep(1)  # 1초마다 체크
                
                # 스레드 종료 시 통계 딕셔너리 반환
                stats_pool.put(protocol_stats)
                logger.info("대시보드 스레드 종료 - 객체 풀에 반환 완료")
            
            display_thread = threading.Thread(target=display_realtime_stats)
            display_thread.daemon = True
            display_thread.start()
            
            # 상세 상태 모니터링 스레드 (백그라운드에서 로그만 기록)
            def monitor_capture_status():
                last_log_time = time.time()
                last_gc_time = time.time()
                
                while packet_core.is_running:
                    current_time = time.time()
                    
                    # 5분마다 가비지 컬렉션 수행
                    if current_time - last_gc_time >= 300:  # 5분
                        gc.collect()
                        last_gc_time = current_time
                        
                        # 메모리 사용량 로깅
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
                
                # 필요한 컬럼만 선택하는 함수
                def select_necessary_columns(df):
                    necessary_columns = ['source', 'destination', 'protocol', 'length', 'ttl', 'flags']
                    return df[necessary_columns] if all(col in df.columns for col in necessary_columns) else df
                
                # 데이터 타입 최적화 함수
                def optimize_dtypes(df):
                    if 'length' in df.columns:
                        df['length'] = df['length'].astype('int32')
                    if 'ttl' in df.columns:
                        df['ttl'] = df['ttl'].astype('uint8')
                    return df
                
                # 패킷 변환 함수 - 문자열이나 다른 타입을 딕셔너리로 변환
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
                        # 큐가 비어있는 경우 - 정상적인 상황
                        pass
                    except Exception as e:
                        # 오류를 로그에만 기록 (화면 출력 없음)
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
                                
                                    # 데이터 타입 최적화
                                    df_chunk = optimize_dtypes(df_chunk)
                                    
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
                    
                    time.sleep(0.05)  # CPU 사용량 감소를 위한 더 짧은 대기
            
            process_thread = threading.Thread(target=process_and_save_packets)
            process_thread.daemon = True
            process_thread.start()
            
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
                                # 🔥 지연 로딩: 필요한 시점에 머신러닝 모듈 로딩
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
                                
                                # 🔥 지연 로딩: 필요할 때만 강화학습 환경과 에이전트 초기화
                                if env is None or agent is None:
                                    # 강화학습 모듈들 지연 로딩
                                    if rl_modules is None:
                                        logger.info("강화학습 모듈 지연 로딩 시작...")
                                        rl_modules = lazy_importer.get_module('reinforcement_learning')
                                        NetworkEnv = rl_modules['NetworkEnv']
                                        DQNAgent = rl_modules['DQNAgent']
                                        load_model = rl_modules['load_model']
                                        train_rl_agent = rl_modules['train_rl_agent']
                                        save_model = rl_modules['save_model']
                                        logger.info("강화학습 모듈 지연 로딩 완료")
                                    
                                    env = NetworkEnv(max_steps=1000, mode=args.mode)
                                    state_size = env.observation_space.shape[0]
                                    action_size = env.action_space.n
                                    
                                    # 새로운 Experience Replay Buffer를 사용하는 DQNAgent 초기화
                                    agent = DQNAgent(
                                        state_size, 
                                        action_size, 
                                        mode=args.mode,
                                        use_prioritized_replay=True,
                                        replay_buffer_capacity=10000
                                    )
                                    
                                    # 기존 모델 로드 시도
                                    model_path = f'dqn_model_{args.mode}.pth'
                                    if os.path.exists(model_path):
                                        load_model(agent, model_path)
                                    
                                    # 기존 Experience Buffer 로드 시도
                                    buffer_path = f'experience_buffer_{args.mode}.pkl'
                                    if os.path.exists(buffer_path):
                                        if agent.load_buffer(buffer_path):
                                            logger.info("기존 Experience Buffer 로드 완료")
                                
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
                                
                                # 강화학습 모델 저장
                                save_model(agent, f'dqn_model_{args.mode}.pth')
                                logger.info(f"{args.mode} 모드용 강화학습 모델 저장 완료")
                                
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
            
            # CLI 전용 모드 - GUI 컴포넌트 제거됨
            logger.info("CLI 전용 모드로 모든 백그라운드 스레드 준비 완료")
            
            # 고급 사용자 입력 처리 스레드
            def handle_user_input():
                global args, threat_stats, defense_stats, ml_stats, start_time
                
                def show_command_prompt():
                    """명령어 프롬프트 표시"""
                    print()  # 대시보드와 구분을 위한 빈 줄
                    print_colored("=" * 60, Fore.CYAN)
                    print_colored("💻 명령어 입력 모드", Fore.CYAN, Style.BRIGHT)
                    print_colored("사용 가능한 명령어: h(도움말), s(상태), p(패킷), d(방어), m(모드전환), q(종료)", Fore.WHITE)
                    print_colored("=" * 60, Fore.CYAN)
                    print_colored("명령어 > ", Fore.YELLOW, end="")
                
                def show_status():
                    """현재 상태 표시"""
                    clear_screen()
                    print_header()
                    
                    # 시스템 상태
                    status_info = [
                        f"⚡ 운영 모드: {args.mode.upper()}",
                        f"📊 캡처된 패킷: {packet_core.get_packet_count():,}개",
                        f"🔄 캡처 상태: {'실행 중' if packet_core.is_running else '중지됨'}",
                        f"⏰ 실행 시간: {datetime.now().strftime('%H:%M:%S')}"
                    ]
                    
                    if 'defense_manager' in locals():
                        defense_status = defense_manager.get_status()
                        status_info.extend([
                            f"🛡️ 방어 메커니즘: {'활성화' if defense_status['is_active'] else '비활성화'}",
                            f"🚫 차단된 IP: {len(defense_status.get('blocked_ips', []))}개"
                        ])
                    
                    print_status_box("시스템 상태", status_info, Fore.GREEN)
                
                def show_packet_stats():
                    """패킷 통계 표시"""
                    packet_count = packet_core.get_packet_count()
                    stats_info = [
                        f"📦 총 캡처된 패킷: {packet_count:,}개",
                        f"📈 초당 패킷 수: 계산 중...",
                        f"💾 큐 크기: {packet_core.packet_queue.qsize()}개",
                        f"🔄 처리 상태: {'활성화' if packet_core.is_running else '중지됨'}"
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
                            new_icon = "🔥" if new_mode == 'performance' else "⚡"
                            
                            print_colored(f"\n{new_icon} {args.mode} → {new_mode} 모드로 전환 중...", new_color, Style.BRIGHT)
                        
                            # 방어 메커니즘 모드 전환
                            if defense_manager.switch_mode(new_mode):
                                print_colored(f"✅ 방어 메커니즘이 {new_mode} 모드로 전환되었습니다", Fore.GREEN)
                            
                                # 강화학습 환경/에이전트 모드 전환 (재학습 중이라면)
                                if 'env' in locals() and 'agent' in locals():
                                    env.set_mode(new_mode)
                                    agent.switch_mode(new_mode)
                                    print_colored(f"✅ 강화학습 모델이 {new_mode} 모드로 전환되었습니다", Fore.GREEN)
                                
                                # 전역 모드 설정 업데이트
                                args.mode = new_mode
                                print_colored(f"🎯 현재 모드: {args.mode.upper()}", new_color, Style.BRIGHT)
                            else:
                                print_colored("❌ 모드 전환에 실패했습니다", Fore.RED)
                                
                        elif user_input in ['s', 'status']:
                            show_status()
                            
                        elif user_input in ['p', 'packets']:
                            show_packet_stats()
                            
                        elif user_input in ['h', 'help']:
                            show_help_menu()
                            
                        elif user_input in ['d', 'defense']:
                            if 'defense_manager' in locals():
                                defense_status = defense_manager.get_status()
                                defense_info = [
                                    f"상태: {'활성화' if defense_status['is_active'] else '비활성화'}",
                                    f"모드: {defense_status['mode'].upper()}",
                                    f"차단된 IP 수: {len(defense_status.get('blocked_ips', []))}개"
                                ]
                                if defense_status.get('blocked_ips'):
                                    defense_info.append("차단된 IP 목록:")
                                    for ip in defense_status['blocked_ips'][:5]:  # 최대 5개만 표시
                                        defense_info.append(f"  🚫 {ip}")
                                print_status_box("방어 메커니즘 상태", defense_info, Fore.RED)
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
                                "🤖 강화학습 에이전트: 지연 로딩",
                                "🌲 랜덤 포레스트: 지연 로딩",
                                f"💾 Experience Buffer: 사용 중",
                                f"⚙️ 운영 모드: {args.mode.upper()}",
                                "",
                                f"📊 모델 정확도: {accuracy_display}",
                                f"🔢 총 예측 수행: {ml_stats['predictions']:,}회",
                                f"⚡ 초당 예측: {predictions_per_sec:.1f}회/s",
                                f"🔄 모델 업데이트: {ml_stats['model_updates']:,}회",
                                "",
                                "🔥 지연 로딩 상태:",
                                f"  - 등록된 모듈: {lazy_stats['total_modules']}개",
                                f"  - 로딩된 모듈: {lazy_stats['loaded_modules']}개",
                                f"  - 등록된 모델: {model_stats['total_models']}개",
                                f"  - 로딩된 모델: {model_stats['loaded_models']}개",
                                "",
                                "📦 패킷 객체 풀링:",
                                f"  - 풀 크기: {packet_pool_stats['pool_size']}개",
                                f"  - 재사용률: {packet_pool_stats['reuse_rate']:.1f}%",
                                "",
                                "🔢 DataFrame 풀링:",
                                f"  - 배열 재사용률: {dataframe_pool_stats['reuse_rate']:.1f}%",
                                f"  - 생성된 배열: {dataframe_pool_stats['total_created']}개",
                                f"  - 재사용 횟수: {dataframe_pool_stats['total_reused']}회"
                            ]
                            print_status_box("머신러닝 상세 상태", ml_info, Fore.MAGENTA)
                            
                        elif user_input in ['threats', 't']:
                            # 위협 탐지 상세 통계
                            threat_info = [
                                f"🔴 높은 위협: {threat_stats.get('high', 0):,}개",
                                f"🟡 중간 위협: {threat_stats.get('medium', 0):,}개",
                                f"🟢 낮은 위협: {threat_stats.get('low', 0):,}개",
                                f"⚪ 안전: {threat_stats.get('safe', 0):,}개",
                                "",
                                f"총 분석 패킷: {sum(threat_stats.values()):,}개",
                                f"위협 탐지율: {(threat_stats.get('high', 0) + threat_stats.get('medium', 0)) / max(sum(threat_stats.values()), 1) * 100:.2f}%"
                            ]
                            print_status_box("위협 탐지 상세 통계", threat_info, Fore.RED)
                            
                        elif user_input in ['q', 'quit', 'exit']:
                            print_colored("\n👋 IDS 시스템을 종료합니다...", Fore.YELLOW, Style.BRIGHT)
                            packet_core.stop_capture()
                            break
                            
                        elif user_input == '':
                            # Enter만 누른 경우 상태 새로고침
                            show_status()
                            
                        else:
                            print_colored(f"❌ 알 수 없는 명령어: '{user_input}'", Fore.RED)
                            print_colored("💡 도움말을 보려면 'h'를 입력하세요", Fore.YELLOW)
                        
                    except KeyboardInterrupt:
                        print_colored("\n\n🛑 Ctrl+C 감지 - 프로그램을 종료합니다", Fore.YELLOW, Style.BRIGHT)
                        packet_core.stop_capture()
                        break
                    except EOFError:
                        print_colored("\n\n👋 입력 종료 - 프로그램을 종료합니다", Fore.YELLOW)
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
        
        # Enter 키를 누를 때까지 대기
        wait_for_enter()
        
    except KeyboardInterrupt:
        print("\n프로그램이 사용자에 의해 중단되었습니다.")
        logger.info("사용자에 의한 프로그램 중단")
        
        # 객체 풀 최종 통계 출력
        try:
            packet_pool_stats = get_packet_pool().get_stats()
            dataframe_pool_stats = get_dataframe_pool().get_stats()
            
            print_colored("\n📊 메모리 최적화 최종 통계:", Fore.CYAN, Style.BRIGHT)
            print_colored("━" * 50, Fore.CYAN)
            
            print_colored("📦 패킷 객체 풀링:", Fore.YELLOW, Style.BRIGHT)
            print_colored(f"  • 생성된 객체: {packet_pool_stats['total_created']:,}개", Fore.WHITE)
            print_colored(f"  • 재사용 횟수: {packet_pool_stats['total_reused']:,}회", Fore.WHITE)
            print_colored(f"  • 재사용률: {packet_pool_stats['reuse_rate']:.1f}%", Fore.GREEN if packet_pool_stats['reuse_rate'] > 80 else Fore.YELLOW)
            
            print_colored("\n🔢 DataFrame 풀링:", Fore.BLUE, Style.BRIGHT)
            print_colored(f"  • 생성된 배열: {dataframe_pool_stats['total_created']:,}개", Fore.WHITE)
            print_colored(f"  • 재사용 횟수: {dataframe_pool_stats['total_reused']:,}회", Fore.WHITE)
            print_colored(f"  • 재사용률: {dataframe_pool_stats['reuse_rate']:.1f}%", Fore.GREEN if dataframe_pool_stats['reuse_rate'] > 60 else Fore.YELLOW)
            
            # 예상 메모리 절약량 계산
            packet_savings = packet_pool_stats['total_reused'] * 0.001  # 1KB per packet
            dataframe_savings = dataframe_pool_stats['total_reused'] * 5  # 5MB per DataFrame array
            total_savings = packet_savings + dataframe_savings
            
            print_colored(f"\n💾 예상 메모리 절약량:", Fore.GREEN, Style.BRIGHT)
            print_colored(f"  • 패킷 풀링: {packet_savings:.1f}MB", Fore.WHITE)
            print_colored(f"  • DataFrame 풀링: {dataframe_savings:.1f}MB", Fore.WHITE)
            print_colored(f"  • 총 절약량: {total_savings:.1f}MB", Fore.GREEN, Style.BRIGHT)
            
        except Exception as e:
            logger.debug(f"통계 출력 오류: {e}")
            pass
            
        wait_for_enter()
    except Exception as e:
        print(f"\n오류가 발생했습니다: {str(e)}")
        log_exception(e, "프로그램 실행 중 심각한 오류 발생")
        wait_for_enter()

if __name__ == "__main__":
    main() 