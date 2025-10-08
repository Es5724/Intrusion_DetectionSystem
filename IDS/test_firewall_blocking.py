# -*- coding: utf-8 -*-
"""
방화벽 IP 차단 테스트 스크립트

실제로 Windows 방화벽 규칙이 추가되고 패킷이 차단되는지 확인합니다.
"""

import subprocess
import time
import sys
import os

def check_admin():
    """관리자 권한 확인"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def show_firewall_rules():
    """현재 IDS 관련 방화벽 규칙 표시"""
    print("\n" + "="*60)
    print("현재 IDS 방화벽 규칙 목록")
    print("="*60)
    
    command = 'netsh advfirewall firewall show rule name=all | findstr "IDS_Block"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    if result.stdout:
        print(result.stdout)
    else:
        print("❌ IDS 관련 방화벽 규칙이 없습니다.")
    
    print("="*60 + "\n")

def test_ip_blocking():
    """IP 차단 기능 테스트"""
    print("\n🔧 방화벽 IP 차단 기능 테스트\n")
    
    # 관리자 권한 확인
    if not check_admin():
        print("⚠️ 경고: 관리자 권한이 필요합니다!")
        print("   이 스크립트를 관리자 권한으로 실행하세요.\n")
        return False
    
    print("✅ 관리자 권한 확인 완료\n")
    
    # 모듈 임포트
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from modules.defense_mechanism import AutoDefenseActions
    
    # DefenseActions 인스턴스 생성
    defense = AutoDefenseActions()
    
    # 테스트용 IP (실제 공격자 IP가 아닌 테스트용)
    test_ip = "192.0.2.100"  # RFC 5737 TEST-NET-1 (실제 사용되지 않는 IP)
    
    print(f"📍 테스트 IP: {test_ip}")
    print(f"   (RFC 5737 TEST-NET-1 - 문서/테스트 전용 IP)\n")
    
    # 1단계: 차단 전 규칙 확인
    print("1️⃣ 차단 전 방화벽 규칙 확인...")
    show_firewall_rules()
    
    # 2단계: IP 차단
    print(f"2️⃣ IP 차단 시도: {test_ip}")
    success = defense.block_ip(test_ip)
    
    if success:
        print(f"   ✅ 차단 성공!\n")
    else:
        print(f"   ❌ 차단 실패!\n")
        return False
    
    # 3단계: 차단 후 규칙 확인
    print("3️⃣ 차단 후 방화벽 규칙 확인...")
    time.sleep(1)
    show_firewall_rules()
    
    # 4단계: 방화벽 규칙 검증
    print("4️⃣ 방화벽 규칙 검증...")
    verified = defense.verify_firewall_rule(test_ip)
    
    if verified:
        print(f"   ✅ 방화벽 규칙 확인됨: {test_ip}\n")
    else:
        print(f"   ❌ 방화벽 규칙을 찾을 수 없음: {test_ip}\n")
        return False
    
    # 5단계: 차단된 IP 목록 확인
    print("5️⃣ 차단된 IP 목록 확인...")
    blocked_ips = defense.get_blocked_ips()
    print(f"   현재 차단된 IP 개수: {len(blocked_ips)}")
    print(f"   차단 목록: {blocked_ips}\n")
    
    # 6단계: 차단 해제
    print(f"6️⃣ IP 차단 해제 시도: {test_ip}")
    unblock_success = defense.unblock_ip(test_ip)
    
    if unblock_success:
        print(f"   ✅ 차단 해제 성공!\n")
    else:
        print(f"   ❌ 차단 해제 실패!\n")
    
    # 7단계: 해제 후 규칙 확인
    print("7️⃣ 해제 후 방화벽 규칙 확인...")
    time.sleep(1)
    show_firewall_rules()
    
    print("\n" + "="*60)
    print("✅ 테스트 완료!")
    print("="*60 + "\n")
    
    return True

def main():
    """메인 함수"""
    print("\n" + "="*60)
    print("  Windows 방화벽 IP 차단 기능 테스트")
    print("="*60)
    
    try:
        test_ip_blocking()
    except Exception as e:
        print(f"\n❌ 테스트 중 오류 발생: {str(e)}")
        import traceback
        traceback.print_exc()
    
    input("\n아무 키나 눌러 종료...")

if __name__ == "__main__":
    main()
