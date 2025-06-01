import os
import sys
import ctypes
import socket
import time
import traceback
import logging
from datetime import datetime

# 로깅 설정
logger = logging.getLogger('IDSUtils')

def convert_packet_to_dict(packet):
    """
    다양한 타입의 패킷을 안전하게 딕셔너리로 변환합니다.
    
    Args:
        packet: 변환할 패킷 데이터 (딕셔너리, 문자열, 또는 다른 타입)
        
    Returns:
        dict: 변환된 패킷 딕셔너리
    """
    try:
        # 이미 딕셔너리인 경우
        if isinstance(packet, dict):
            return packet
            
        # 문자열인 경우
        if isinstance(packet, str):
            logger.debug(f"문자열 패킷을 딕셔너리로 변환: {packet[:50]}...")
            return {
                'source': 'unknown',
                'destination': 'unknown',
                'protocol': 'unknown',
                'length': len(packet) if packet else 0,
                'info': packet,
                'raw_data': packet
            }
            
        # 다른 타입인 경우
        logger.debug(f"알 수 없는 타입 패킷 변환: {type(packet).__name__}")
        return {
            'source': 'unknown',
            'destination': 'unknown',
            'protocol': 'unknown',
            'length': 0,
            'info': str(packet),
            'raw_data': str(packet)
        }
    except Exception as e:
        logger.error(f"패킷 변환 중 오류 발생: {str(e)}")
        # 변환 실패 시 기본 딕셔너리 반환
        return {
            'source': 'error',
            'destination': 'error',
            'protocol': 'error',
            'length': 0,
            'info': 'Conversion Error',
            'error': str(e)
        }

def log_exception(e, message="예외 발생"):
    """
    예외를 로그에 기록합니다.
    
    Args:
        e (Exception): 발생한 예외
        message (str): 예외 상황에 대한 설명
    """
    logger.error(f"{message}: {str(e)}")
    logger.debug(traceback.format_exc())
    
def is_colab():
    """
    Google Colab 환경인지 확인
    """
    return os.path.exists('/content')

def is_admin():
    """
    Windows에서 관리자 권한 확인
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """
    관리자 권한으로 프로그램 재실행
    """
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

def clear_screen():
    """
    화면 지우기
    """
    os.system('cls' if os.name == 'nt' else 'clear')

def wait_for_enter():
    """
    Enter 키를 누를 때까지 대기
    """
    print("\n계속하려면 Enter 키를 누르세요...")
    
    if os.name == 'nt':  # Windows
        import msvcrt
        while True:
            if msvcrt.kbhit():
                if msvcrt.getch() == b'\r':  # Enter 키
                    break
    else:  # Linux/Mac
        import termios
        import tty
        # 터미널 설정 저장
        old_settings = termios.tcgetattr(sys.stdin)
        try:
            tty.setcbreak(sys.stdin.fileno())
            while True:
                if sys.stdin.read(1) == '\n':  # Enter 키
                    break
        finally:
            # 터미널 설정 복원
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

def print_scan_status(port, status, start_time):
    """
    스캔 상태를 실시간으로 출력
    """
    elapsed_time = time.time() - start_time
    current_time = datetime.now().strftime("%H:%M:%S")
    
    status_colors = {
        'open': '\033[92m',    # 녹색
        'closed': '\033[91m',  # 빨간색
        'filtered': '\033[93m' # 노란색
    }
    
    color = status_colors.get(status, '\033[0m')
    reset = '\033[0m'
    
    print(f"\r[{current_time}] 포트 {port}: {color}{status}{reset} | 경과 시간: {elapsed_time:.1f}초", end='', flush=True)

def syn_scan(target_ip, ports):
    """
    TCP SYN 스캔을 수행하는 함수
    """
    if is_colab():
        print("Google Colab 환경에서는 포트 스캔 기능을 사용할 수 없습니다.")
        return None

    try:
        from scapy.layers.inet import IP, TCP
        from scapy.sendrecv import sr1, send
    except ImportError:
        print("scapy 라이브러리가 설치되어 있지 않습니다.")
        print("설치하려면: pip install scapy")
        return None

    open_ports = []
    closed_ports = []
    filtered_ports = []
    
    start_time = time.time()
    total_ports = len(ports)
    
    print(f"\n대상 IP: {target_ip}")
    print(f"스캔할 포트 수: {total_ports}")
    print("=" * 50)
    
    for i, port in enumerate(ports, 1):
        # 랜덤 소스 포트 생성
        src_port = random.randint(1024, 65535)
        
        # SYN 패킷 생성
        ip_packet = IP(dst=target_ip)
        tcp_packet = TCP(sport=src_port, dport=port, flags="S")
        packet = ip_packet/tcp_packet
        
        try:
            # 패킷 전송 및 응답 대기
            response = sr1(packet, timeout=1, verbose=0)
            
            if response is None:
                filtered_ports.append(port)
                print_scan_status(port, "filtered", start_time)
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:  # SYN-ACK 응답
                    open_ports.append(port)
                    print_scan_status(port, "open", start_time)
                    # RST 패킷 전송하여 연결 종료
                    rst_packet = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="R")
                    send(rst_packet, verbose=0)
                elif response.getlayer(TCP).flags == 0x14:  # RST-ACK 응답
                    closed_ports.append(port)
                    print_scan_status(port, "closed", start_time)
        except Exception as e:
            print(f"\r포트 {port} 스캔 중 오류 발생: {str(e)}")
            continue
            
        time.sleep(0.1)  # 연속 스캔 방지
    
    print("\n" + "=" * 50)
    print(f"\n스캔 완료! 총 소요 시간: {time.time() - start_time:.1f}초")
    
    return {
        'open': open_ports,
        'closed': closed_ports,
        'filtered': filtered_ports
    } 