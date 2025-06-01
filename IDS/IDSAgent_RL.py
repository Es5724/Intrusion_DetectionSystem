# -*- coding: utf-8 -*-

"""
강화학습을 사용한 IDS시스템

이 스크립트는 랜덤포레스트와 강화학습을 사용한 네트워크 보안 시스템을 구현합니다.
"""

import os
import sys
import time
import threading
# import pandas as pd
import argparse
from datetime import datetime
import queue
import traceback
import logging

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

# 콘솔 로거 추가
console = logging.StreamHandler()
console.setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)
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
    console.setLevel(logging.DEBUG)
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
print(f"모듈 경로 추가됨: {module_path}")

# 필요한 모듈 임포트
try:
    from packet_capture import PacketCapture, PacketCaptureCore, preprocess_packet_data
    from reinforcement_learning import NetworkEnv, DQNAgent, train_rl_agent, plot_training_results, save_model, load_model
    from ml_models import MLTrainingWindow, train_random_forest, add_rf_predictions
    from utils import is_colab, is_admin, run_as_admin, clear_screen, wait_for_enter, syn_scan
    from defense_mechanism import create_defense_manager, register_to_packet_capture
    print("모듈 임포트 성공!")
except ImportError as e:
    print(f"모듈을 찾을 수 없습니다: {e}")
    print(f"현재 sys.path: {sys.path}")
    sys.exit(1)

def select_mode_menu():
    """사용자에게 모드 선택 메뉴를 표시하고 선택 결과를 반환합니다."""
    clear_screen()
    print("="*50)
    print("        침입 탐지 시스템(IDS) 모드 선택        ")
    print("="*50)
    print("\n다음 중 사용할 모드를 선택하세요:")
    print("\n1. 경량 모드 (Lightweight)")
    print("   - 적은 시스템 자원 사용")
    print("   - 기본 특성 7개 사용")
    print("   - 모든 환경에서 실행 가능")
    print("\n2. 고성능 모드 (Performance)")
    print("   - 수리카타(Suricata) 엔진 통합")
    print("   - 확장 특성 12개 사용")
    print("   - 더 높은 정확도의 탐지")
    print("   - 더 많은 시스템 자원 필요")
    print("="*50)
    
    while True:
        try:
            choice = int(input("\n선택 (1 또는 2): "))
            if choice == 1:
                return "lightweight"
            elif choice == 2:
                return "performance"
            else:
                print("잘못된 입력입니다. 1 또는 2를 입력하세요.")
        except ValueError:
            print("잘못된 입력입니다. 숫자를 입력하세요.")

def main():
    try:
        print("프로그램 시작...")
        
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
        print(f"운영 모드: {args.mode}")
        logger.info(f"운영 모드 설정: {args.mode}")
        
        # Colab 환경 확인
        print(f"Colab 환경 확인: {is_colab()}")
        if is_colab():
            logger.info("Google Colab 환경에서 실행 중")
            print("Google Colab 환경에서는 머신러닝 모델 학습만 가능합니다.")
            print("포트 스캔 및 패킷 캡처 기능은 로컬 환경에서만 사용 가능합니다.")
            
            # 데이터 파일이 있는 경우에만 머신러닝 모델 학습 실행
            preprocessed_data_path = 'data_set/전처리데이터1.csv'
            if os.path.exists(preprocessed_data_path):
                print("\n데이터 파일을 찾았습니다. 머신러닝 모델 학습을 시작합니다...")
                
                # 랜덤 포레스트 모델 학습
                model, accuracy, conf_matrix = train_random_forest(preprocessed_data_path)
                
                # 강화학습 환경과 에이전트 초기화 (모드 적용)
                env = NetworkEnv(max_steps=1000, mode=args.mode)
                state_size = env.observation_space.shape[0]
                action_size = env.action_space.n
                agent = DQNAgent(state_size, action_size, mode=args.mode)
                
                # 강화학습 훈련 실행
                rewards = train_rl_agent(env, agent)
                
                # 훈련 결과 시각화
                plot_training_results(rewards)
                
                # 모델 저장 (모드별로 구분하여 저장)
                save_model(agent, f'dqn_model_{args.mode}.pth')
                
                print("\n모델 학습이 완료되었습니다.")
            else:
                print("\n데이터 파일을 찾을 수 없습니다.")
            return
            
        # 여기서부터 로컬 환경 코드
        
        # 시작 로그
        logger.info("로컬 환경에서 IDS 시스템 실행 시작")
        
        # 관리자 권한 확인 및 필요시 재실행 (Windows 환경에서만)
        if os.name == 'nt' and not args.debug:  # 디버그 모드에서는 관리자 권한 체크 생략
            print("윈도우 환경 감지: 관리자 권한 확인 중...")
            if not is_admin():
                print("관리자 권한이 필요합니다. 관리자 권한으로 재실행합니다...")
                run_as_admin()
                return
            print("관리자 권한으로 실행 중...")
        elif os.name == 'nt' and args.debug:
            print("디버그 모드: 관리자 권한 체크 우회")
            logger.info("디버그 모드에서 관리자 권한 체크 우회됨")
        
        # 화면 초기화
        clear_screen()
        
        # 패킷 캡처 코어 초기화
        print("패킷 캡처 코어 초기화 중...")
        packet_core = PacketCaptureCore()
        
        # 방어 메커니즘 초기화 (선택한 모드 적용)
        print(f"{args.mode} 모드로 방어 메커니즘 초기화 중...")
        defense_manager = create_defense_manager('defense_config.json', mode=args.mode)
        
        # 패킷 캡처 코어에 방어 메커니즘 등록
        if register_to_packet_capture(defense_manager, packet_core):
            print("방어 메커니즘이 패킷 캡처 시스템에 성공적으로 등록되었습니다.")
        else:
            print("방어 메커니즘 등록 실패")
        
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
        
        print(f"\n선택된 인터페이스: {selected_interface}")
        
        # 백그라운드에서 패킷 캡처 시작
        print(f"\n{selected_interface}에서 패킷 캡처를 시작합니다...")
        if packet_core.start_capture(selected_interface, max_packets=args.max_packets):  # 명령행 인수에서 가져온 값 사용
            print("패킷 캡처가 백그라운드에서 시작되었습니다.")
            print("프로그램을 종료하려면 Ctrl+C를 누르세요.")
            print("모드를 전환하려면 'm'을 누르세요.")
            
            # 실시간 패킷 정보 표시 스레드
            def display_packet_info():
                last_packet_count = 0
                print("디버그: 패킷 표시 스레드 시작됨")
                while packet_core.is_running:
                    current_count = packet_core.get_packet_count()
                    
                    if current_count > last_packet_count:
                        try:
                            # 최근 캡처된 패킷 정보 가져오기
                            packet = packet_core.packet_queue.get_nowait()
                            print(f"디버그: 패킷 가져옴, 타입: {type(packet).__name__}")
                            
                            # 패킷 정보 표시
                            print("\n" + "="*50)
                            print(f"캡처된 패킷 수: {current_count}")
                            print(f"시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                            
                            # 패킷 타입 확인 및 처리
                            if isinstance(packet, dict):
                                # 딕셔너리인 경우 get 메서드 사용
                                print(f"출발지: {packet.get('source', 'N/A')}")
                                print(f"목적지: {packet.get('destination', 'N/A')}")
                                print(f"프로토콜: {packet.get('protocol', 'N/A')}")
                                print(f"길이: {packet.get('length', 'N/A')} bytes")
                                print(f"정보: {packet.get('info', 'N/A')}")
                            elif isinstance(packet, str):
                                # 문자열인 경우 그대로 출력
                                print(f"패킷 데이터(문자열): {packet}")
                            else:
                                # 그 외 타입의 경우
                                print(f"패킷 데이터(타입: {type(packet).__name__}): {str(packet)}")
                            
                            print("="*50)
                            
                            last_packet_count = current_count
                        except queue.Empty:
                            # 큐가 비어있는 경우 - 정상적인 상황
                            pass
                        except Exception as e:
                            print(f"패킷 표시 중 오류 발생: {str(e)}")
                            print(f"오류 타입: {type(e).__name__}")
                            import traceback
                            traceback.print_exc()
                    time.sleep(0.1)  # CPU 사용량 감소를 위한 짧은 대기
            
            display_thread = threading.Thread(target=display_packet_info)
            display_thread.daemon = True
            display_thread.start()
            
            # 패킷 캡처 상태 모니터링 스레드
            def monitor_capture_status():
                while packet_core.is_running:
                    print(f"\n캡처 상태: {'실행 중' if packet_core.is_running else '중지됨'}")
                    print(f"캡처된 총 패킷 수: {packet_core.get_packet_count()}")
                    
                    # 방어 메커니즘 상태 표시
                    defense_status = defense_manager.get_status()
                    print(f"방어 메커니즘 상태: {'활성화' if defense_status['is_active'] else '비활성화'}")
                    print(f"운영 모드: {defense_status['mode']}")
                    if defense_status['blocked_ips']:
                        print(f"차단된 IP 주소: {', '.join(defense_status['blocked_ips'])}")
                    
                    time.sleep(5)  # 5초마다 상태 업데이트
            
            monitor_thread = threading.Thread(target=monitor_capture_status)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # 실시간 패킷 처리 및 저장 스레드 (청크 방식으로 최적화)
            def process_and_save_packets():
                packet_buffer = []
                last_save_time = time.time()
                chunk_size = 200  # 더 작은 청크 크기로 설정
                max_buffer_size = 1000  # 최대 버퍼 크기 유지
                
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
                    # 패킷 큐에서 패킷 가져오기
                    try:
                        packet = packet_core.packet_queue.get_nowait()
                        print(f"디버그: 처리 스레드에서 패킷 가져옴, 타입: {type(packet).__name__}")
                        # 패킷이 딕셔너리가 아닌 경우 변환
                        packet = convert_packet_to_dict(packet)
                        packet_buffer.append(packet)
                    except queue.Empty:
                        # 큐가 비어있는 경우 - 정상적인 상황
                        pass
                    except Exception as e:
                        print(f"패킷 처리 중 오류 발생: {str(e)}")
                        print(f"오류 타입: {type(e).__name__}")
                        import traceback
                        traceback.print_exc()
                    
                    current_time = time.time()
                    # 청크 크기에 도달하거나 5분 경과 시 처리
                    if len(packet_buffer) >= chunk_size or (current_time - last_save_time) >= 300:
                        if packet_buffer:
                            # 타임스탬프 생성 (파일명용)
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            filename = f"captured_packets_{timestamp}.csv"
                            
                            # 처리할 청크 크기 결정
                            process_size = min(chunk_size, len(packet_buffer))
                            chunk = packet_buffer[:process_size]
                            
                            # DataFrame으로 변환
                            df_chunk = pd.DataFrame(chunk)
                            
                            # 필요한 컬럼만 선택
                            df_chunk = select_necessary_columns(df_chunk)
                            
                            # 데이터 타입 최적화
                            df_chunk = optimize_dtypes(df_chunk)
                            
                            # 데이터 전처리
                            df_chunk = preprocess_packet_data(df_chunk)
                            
                            # 랜덤포레스트 예측 확률 feature 추가
                            df_chunk = add_rf_predictions(df_chunk)
                            
                            # CSV 파일로 저장 (append 모드)
                            file_exists = os.path.isfile(filename)
                            df_chunk.to_csv(filename, mode='a', header=not file_exists, index=False)
                            print(f"\n패킷 {process_size}개가 {filename}에 저장되었습니다.")
                            
                            # 처리된 청크 제거
                            packet_buffer = packet_buffer[process_size:]
                            
                            # 명시적 메모리 해제
                            del df_chunk
                            
                            # 최대 버퍼 크기 초과 시 오래된 패킷 삭제
                            if len(packet_buffer) > max_buffer_size:
                                print(f"\n버퍼 크기 제한으로 {len(packet_buffer) - max_buffer_size}개 패킷 삭제")
                                packet_buffer = packet_buffer[-max_buffer_size:]
                            
                            # 전체 버퍼가 비었거나 5분 경과 시 타이머 재설정
                            if not packet_buffer or (current_time - last_save_time) >= 300:
                                last_save_time = current_time
                    
                    time.sleep(0.1)  # CPU 사용량 감소를 위한 짧은 대기
            
            process_thread = threading.Thread(target=process_and_save_packets)
            process_thread.daemon = True
            process_thread.start()
            
            # 머신러닝 학습 창 생성
            ml_window = MLTrainingWindow()
            ml_window.root.withdraw()  # 초기에는 숨겨둠
            
            # 데이터 파일 모니터링 및 머신러닝 모델 학습 스레드 (메모리 최적화)
            def monitor_and_train():
                print("모니터링 및 학습 스레드 시작")
                
                # 파일 변경 여부 체크용 변수
                last_modified_time = 0
                last_training_time = 0
                training_interval = 3600  # 학습 간격 (초) - 1시간마다 최대 1번 학습
                
                # 강화학습 환경과 에이전트는 필요할 때만 생성
                env = None
                agent = None
                
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
                            
                            # GUI 업데이트
                            ml_window.gui_queue.put(('deiconify',))
                            ml_window.gui_queue.put(('update_status', "데이터 파일 변경 감지 - 머신러닝 모델 학습 시작"))
                            
                            try:
                                # 메모리 최적화를 위한 청크 단위 파일 처리
                                ml_window.gui_queue.put(('update_status', "랜덤 포레스트 모델 학습 시작"))
                                
                                # 청크 처리로 랜덤 포레스트 모델 학습
                                # 기존 train_random_forest 함수가 chunked_reading을 지원하도록 수정 필요
                                model, accuracy, conf_matrix = train_random_forest(
                                    preprocessed_data_path, 
                                    chunk_size=10000  # 청크 크기 지정
                                )
                                
                                # 메모리 사용량을 줄이기 위해 GUI 업데이트 전 임시 저장
                                accuracy_value = float(accuracy)
                                # 혼동 행렬은 작은 크기로 요약
                                conf_matrix_summary = conf_matrix.sum(axis=1).tolist() if hasattr(conf_matrix, 'sum') else []
                                
                                # GUI 업데이트
                                ml_window.gui_queue.put(('update_metrics', accuracy_value, conf_matrix_summary))
                                ml_window.gui_queue.put(('update_status', "랜덤 포레스트 모델 학습 완료"))
                                
                                # 메모리 관리를 위해 명시적 가비지 컬렉션 호출
                                import gc
                                gc.collect()
                                
                                # 필요할 때만 강화학습 환경과 에이전트 초기화
                                if env is None or agent is None:
                                    env = NetworkEnv(max_steps=1000, mode=args.mode)
                                    state_size = env.observation_space.shape[0]
                                    action_size = env.action_space.n
                                    agent = DQNAgent(state_size, action_size, mode=args.mode)
                                    
                                    # 기존 모델 로드 시도
                                    model_path = f'dqn_model_{args.mode}.pth'
                                    if os.path.exists(model_path):
                                        load_model(agent, model_path)
                                
                                # 강화학습 훈련
                                ml_window.gui_queue.put(('update_status', "강화학습 훈련 시작"))
                                
                                # 에피소드 수를 줄이고 메모리 효율성 향상
                                rewards = train_rl_agent(env, agent, episodes=50)
                                
                                # 강화학습 모델 저장
                                save_model(agent, f'dqn_model_{args.mode}.pth')
                                ml_window.gui_queue.put(('update_status', f"{args.mode} 모드용 강화학습 모델 저장 완료"))
                                
                                # 훈련 결과 시각화 (경량 모드에서만 수행)
                                if args.mode != "lightweight":
                                    plot_training_results(rewards)
                                
                                # 학습 완료 후 타임스탬프 업데이트
                                last_modified_time = current_modified_time
                                last_training_time = current_time
                                
                                # 다시 메모리 정리
                                gc.collect()
                                
                            except Exception as e:
                                ml_window.gui_queue.put(('update_status', f"모델 학습 중 오류 발생: {e}"))
                                # 오류 발생 시에도 타임스탬프는 업데이트하여 반복 학습 방지
                                last_modified_time = current_modified_time
                                last_training_time = current_time
                    
                    # 학습하지 않을 때는 더 긴 간격으로 체크
                    time.sleep(300)  # 5분마다 확인으로 변경
            
            train_thread = threading.Thread(target=monitor_and_train)
            train_thread.daemon = True
            train_thread.start()
            
            # MLTrainingWindow 초기화 시 process_gui_queue 호출
            ml_window.process_gui_queue()
            
            # 모드 전환을 위한 사용자 입력 처리 스레드
            def handle_user_input():
                global args
                while packet_core.is_running:
                    user_input = input("\n명령어를 입력하세요 ('m': 모드 전환, 'q': 종료): ")
                    if user_input.lower() == 'm':
                        # 모드 전환
                        new_mode = 'performance' if args.mode == 'lightweight' else 'lightweight'
                        print(f"\n{args.mode} 모드에서 {new_mode} 모드로 전환 중...")
                        
                        # 방어 메커니즘 모드 전환
                        if defense_manager.switch_mode(new_mode):
                            print(f"방어 메커니즘 모드가 {new_mode}로 전환되었습니다.")
                            
                            # 강화학습 환경/에이전트 모드 전환 (재학습 중이라면)
                            if 'env' in locals() and 'agent' in locals():
                                env.set_mode(new_mode)
                                agent.switch_mode(new_mode)
                                print(f"강화학습 모델이 {new_mode}로 전환되었습니다.")
                                
                            # 전역 모드 설정 업데이트
                            args.mode = new_mode
                        else:
                            print("모드 전환에 실패했습니다.")
                    elif user_input.lower() == 'q':
                        print("\n프로그램을 종료합니다...")
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
        wait_for_enter()
    except Exception as e:
        print(f"\n오류가 발생했습니다: {str(e)}")
        log_exception(e, "프로그램 실행 중 심각한 오류 발생")
        wait_for_enter()

if __name__ == "__main__":
    main() 