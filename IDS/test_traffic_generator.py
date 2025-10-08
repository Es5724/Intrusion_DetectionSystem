# -*- coding: utf-8 -*-
"""
트래픽 생성기 기능 테스트 스크립트

각 공격 유형이 제대로 작동하는지 확인합니다.
"""

import sys
import os
import threading
import time

# 모듈 경로 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

# 트래픽 생성 함수 임포트
from scripts.components.TrafficGeneratorApp import (
    syn_flood, udp_flood, http_slowloris, tcp_handshake_misuse,
    ssl_traffic, http_request_modification, arp_spoof, icmp_redirect,
    get_default_iface_and_ip, get_default_gateway, is_valid_ip
)

def check_admin():
    """관리자 권한 확인"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def test_network_setup():
    """네트워크 설정 테스트"""
    print("\n" + "="*60)
    print("1️⃣ 네트워크 설정 테스트")
    print("="*60)
    
    # 인터페이스 및 IP 확인
    iface, src_ip = get_default_iface_and_ip()
    print(f"✅ 네트워크 인터페이스: {iface}")
    print(f"✅ 소스 IP: {src_ip}")
    
    # 게이트웨이 확인
    gateway = get_default_gateway()
    print(f"✅ 기본 게이트웨이: {gateway}")
    
    # IP 유효성 검사
    test_ips = ["127.0.0.1", "192.168.1.1", "invalid_ip"]
    for ip in test_ips:
        valid = is_valid_ip(ip)
        status = "✅" if valid else "❌"
        print(f"{status} IP 유효성 검사: {ip} -> {valid}")
    
    return iface is not None and src_ip is not None

def test_attack_function(attack_name, attack_func, args, duration=5):
    """공격 함수 테스트"""
    print(f"\n{'='*60}")
    print(f"테스트: {attack_name}")
    print(f"{'='*60}")
    
    stop_flag = threading.Event()
    
    try:
        # 공격 스레드 시작
        thread = threading.Thread(target=attack_func, args=args, daemon=True)
        thread.start()
        
        # 지정된 시간 동안 실행
        print(f"⏱️ {duration}초 동안 실행 중...")
        time.sleep(duration)
        
        # 중지 신호
        stop_flag.set()
        
        # 스레드 종료 대기
        thread.join(timeout=3)
        
        if thread.is_alive():
            print(f"⚠️ {attack_name} 스레드가 정상 종료되지 않음")
            return False
        else:
            print(f"✅ {attack_name} 정상 종료")
            return True
            
    except Exception as e:
        print(f"❌ {attack_name} 오류: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """메인 테스트 함수"""
    print("\n" + "="*60)
    print("  트래픽 생성기 기능 테스트")
    print("="*60)
    
    # 관리자 권한 확인
    if not check_admin():
        print("\n⚠️ 경고: 관리자 권한이 필요합니다!")
        print("   이 스크립트를 관리자 권한으로 실행하세요.\n")
        return
    
    print("\n✅ 관리자 권한 확인 완료")
    
    # 네트워크 설정 테스트
    if not test_network_setup():
        print("\n❌ 네트워크 설정 테스트 실패")
        return
    
    # 테스트 대상 IP (localhost)
    test_ip = "127.0.0.1"
    print(f"\n📍 테스트 대상 IP: {test_ip}")
    print(f"   (localhost - 안전한 테스트 환경)\n")
    
    # 각 공격 유형 테스트
    test_results = {}
    
    # 1. SYN 플러드
    stop_flag = threading.Event()
    result = test_attack_function(
        "SYN 플러드",
        syn_flood,
        (test_ip, 100, 64, stop_flag, None, None),
        duration=3
    )
    test_results["SYN 플러드"] = result
    
    # 2. UDP 플러드
    stop_flag = threading.Event()
    result = test_attack_function(
        "UDP 플러드",
        udp_flood,
        (test_ip, 100, 64, stop_flag, None, None),
        duration=3
    )
    test_results["UDP 플러드"] = result
    
    # 3. HTTP Slowloris
    stop_flag = threading.Event()
    result = test_attack_function(
        "HTTP Slowloris",
        http_slowloris,
        (test_ip, 50, 64, stop_flag, None),
        duration=3
    )
    test_results["HTTP Slowloris"] = result
    
    # 4. TCP 핸드셰이크 오용
    stop_flag = threading.Event()
    result = test_attack_function(
        "TCP 핸드셰이크 오용",
        tcp_handshake_misuse,
        (test_ip, 50, 64, stop_flag, None),
        duration=3
    )
    test_results["TCP 핸드셰이크 오용"] = result
    
    # 5. SSL/TLS 트래픽
    stop_flag = threading.Event()
    result = test_attack_function(
        "SSL/TLS 트래픽",
        ssl_traffic,
        (test_ip, 50, 64, stop_flag),
        duration=3
    )
    test_results["SSL/TLS 트래픽"] = result
    
    # 6. HTTP 요청 변조
    stop_flag = threading.Event()
    result = test_attack_function(
        "HTTP 요청 변조",
        http_request_modification,
        (test_ip, 50, 64, stop_flag),
        duration=3
    )
    test_results["HTTP 요청 변조"] = result
    
    # 최종 결과
    print("\n" + "="*60)
    print("📊 테스트 결과 요약")
    print("="*60)
    
    passed = 0
    failed = 0
    
    for attack_name, result in test_results.items():
        status = "✅ 통과" if result else "❌ 실패"
        print(f"{status}: {attack_name}")
        if result:
            passed += 1
        else:
            failed += 1
    
    print("="*60)
    print(f"총 {len(test_results)}개 테스트")
    print(f"✅ 통과: {passed}개")
    print(f"❌ 실패: {failed}개")
    print("="*60 + "\n")
    
    if failed == 0:
        print("🎉 모든 테스트 통과!")
    else:
        print(f"⚠️ {failed}개 테스트 실패 - 로그를 확인하세요.")
    
    input("\n아무 키나 눌러 종료...")

if __name__ == "__main__":
    main()
