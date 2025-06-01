#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
방어 메커니즘 테스트 스크립트

패킷 캡처 모듈과 방어 메커니즘의 통합 기능을 테스트합니다.
"""

import os
import sys
import time
import threading
from datetime import datetime

# 모듈 경로 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
modules_path = os.path.join(current_dir, 'modules')
if os.path.exists(modules_path):
    sys.path.append(current_dir)  # 현재 디렉토리도 추가하여 상대 경로로 모듈 import 가능하게 함
else:
    print("모듈 디렉토리를 찾을 수 없습니다.")
    sys.exit(1)

# 필요한 모듈 임포트
try:
    from modules.packet_capture import PacketCaptureCore
    from modules.defense_mechanism import create_defense_manager, register_to_packet_capture
except ImportError as e:
    print(f"모듈을 찾을 수 없습니다: {e}")
    print(f"현재 sys.path: {sys.path}")
    sys.exit(1)

def main():
    print("방어 메커니즘 테스트 시작...")
    
    # 1. 패킷 캡처 코어 초기화
    packet_core = PacketCaptureCore()
    print("패킷 캡처 코어 초기화 완료")
    
    # 2. 방어 메커니즘 초기화
    defense_manager = create_defense_manager('defense_config.json')
    print("방어 메커니즘 초기화 완료")
    
    # 3. 패킷 캡처 코어에 방어 메커니즘 등록
    if register_to_packet_capture(defense_manager, packet_core):
        print("방어 메커니즘이 패킷 캡처 시스템에 성공적으로 등록되었습니다.")
    else:
        print("방어 메커니즘 등록 실패")
        return
    
    # 4. 테스트 패킷 직접 주입
    print("\n테스트 패킷 주입 시작...")
    
    # 4.1 일반 패킷 주입
    normal_packet = {
        'no': 1,
        'source': '192.168.1.10',
        'destination': '192.168.1.100:80',
        'protocol': '6',  # TCP
        'length': 64,
        'info': 'HTTP GET request'
    }
    
    print("일반 패킷 주입 중...")
    defense_manager.handle_packet(normal_packet)
    time.sleep(1)
    
    # 4.2 의심스러운 패킷 주입 (SYN 플러딩 시뮬레이션)
    suspicious_packet = {
        'no': 2,
        'source': '192.168.1.20',
        'destination': '192.168.1.100:80',
        'protocol': '6',  # TCP
        'length': 60,
        'info': 'TCP SYN packet'
    }
    
    print("의심스러운 패킷 주입 중...")
    defense_manager.handle_packet(suspicious_packet)
    time.sleep(1)
    
    # 4.3 명백한 공격 패킷 주입
    attack_packet = {
        'no': 3,
        'source': '192.168.1.30',
        'destination': '192.168.1.100:22',
        'protocol': '6',  # TCP
        'length': 5500,  # 큰 패킷 크기
        'info': 'TCP SYN packet to port 22'
    }
    
    print("공격 패킷 주입 중...")
    defense_manager.handle_packet(attack_packet)
    time.sleep(2)
    
    # 5. 방어 메커니즘 상태 확인
    defense_status = defense_manager.get_status()
    print("\n방어 메커니즘 상태:")
    print(f"활성화 상태: {'활성화' if defense_status['is_active'] else '비활성화'}")
    print(f"차단된 IP 목록: {defense_status['blocked_ips']}")
    
    # 6. 테스트 종료
    print("\n테스트 완료. 차단된 IP 확인 결과:")
    if '192.168.1.30' in defense_status['blocked_ips']:
        print("✓ 성공: 공격 패킷의 IP가 차단되었습니다.")
    else:
        print("✗ 실패: 공격 패킷의 IP가 차단되지 않았습니다.")
        
    if '192.168.1.10' not in defense_status['blocked_ips']:
        print("✓ 성공: 일반 패킷의 IP는 차단되지 않았습니다.")
    else:
        print("✗ 실패: 일반 패킷의 IP가 차단되었습니다.")
    
    print("\n테스트가 완료되었습니다.")

if __name__ == "__main__":
    main() 