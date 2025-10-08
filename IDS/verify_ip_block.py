# -*- coding: utf-8 -*-
"""
IP 차단 검증 스크립트

차단된 IP가 실제로 서비스에 접근할 수 없는지 확인합니다.
"""

import subprocess
import socket
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

def get_blocked_ips():
    """현재 차단된 IP 목록 가져오기"""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from modules.defense_mechanism import AutoDefenseActions
    
    defense = AutoDefenseActions()
    return defense.get_blocked_ips()

def check_firewall_rule_details(ip_address):
    """방화벽 규칙 상세 정보 확인"""
    rule_name = f"IDS_Block_{ip_address.replace('.', '_')}"
    
    print(f"\n{'='*60}")
    print(f"방화벽 규칙 상세 정보: {ip_address}")
    print(f"{'='*60}")
    
    # 인바운드 규칙 확인
    command_in = f'netsh advfirewall firewall show rule name="{rule_name}_IN" verbose'
    result_in = subprocess.run(command_in, shell=True, capture_output=True, text=True)
    
    if result_in.returncode == 0:
        print("\n✅ 인바운드 규칙 (IN):")
        print(result_in.stdout)
    else:
        print("\n❌ 인바운드 규칙을 찾을 수 없습니다.")
    
    # 아웃바운드 규칙 확인
    command_out = f'netsh advfirewall firewall show rule name="{rule_name}_OUT" verbose'
    result_out = subprocess.run(command_out, shell=True, capture_output=True, text=True)
    
    if result_out.returncode == 0:
        print("\n✅ 아웃바운드 규칙 (OUT):")
        print(result_out.stdout)
    else:
        print("\n❌ 아웃바운드 규칙을 찾을 수 없습니다.")
    
    print(f"{'='*60}\n")
    
    return result_in.returncode == 0 or result_out.returncode == 0

def test_connection_to_blocked_ip(ip_address):
    """차단된 IP로의 연결 테스트"""
    print(f"\n{'='*60}")
    print(f"연결 테스트: {ip_address}")
    print(f"{'='*60}\n")
    
    # 1. Ping 테스트
    print(f"1️⃣ Ping 테스트...")
    ping_command = f'ping -n 2 -w 1000 {ip_address}'
    result = subprocess.run(ping_command, shell=True, capture_output=True, text=True)
    
    if "TTL=" in result.stdout:
        print(f"   ⚠️ Ping 성공 - ICMP는 차단되지 않았습니다.")
        print(f"   (ICMP 차단을 원하면 별도 규칙 필요)")
    else:
        print(f"   ✅ Ping 실패 - 패킷이 차단되었습니다.")
    
    # 2. TCP 연결 테스트 (일반적인 포트들)
    test_ports = [80, 443, 22, 3389, 8080]
    
    print(f"\n2️⃣ TCP 연결 테스트 (타임아웃: 2초)...")
    blocked_count = 0
    
    for port in test_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        
        try:
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                print(f"   ⚠️ 포트 {port}: 연결 성공 (차단 안 됨)")
            else:
                print(f"   ✅ 포트 {port}: 연결 실패 (차단됨)")
                blocked_count += 1
        except socket.timeout:
            print(f"   ✅ 포트 {port}: 타임아웃 (차단됨)")
            blocked_count += 1
        except Exception as e:
            print(f"   ✅ 포트 {port}: 오류 (차단됨) - {str(e)}")
            blocked_count += 1
        finally:
            sock.close()
    
    print(f"\n📊 결과: {blocked_count}/{len(test_ports)} 포트가 차단되었습니다.")
    
    if blocked_count == len(test_ports):
        print("   ✅ 모든 TCP 포트가 차단되었습니다!")
    elif blocked_count > 0:
        print("   ⚠️ 일부 포트가 차단되었습니다.")
    else:
        print("   ❌ 차단이 제대로 작동하지 않습니다!")
    
    print(f"{'='*60}\n")
    
    return blocked_count == len(test_ports)

def explain_packet_capture_vs_firewall():
    """패킷 캡처와 방화벽 차단의 차이 설명"""
    print("\n" + "="*60)
    print("📚 패킷 캡처 vs 방화벽 차단")
    print("="*60)
    print("""
🔍 패킷 캡처 (Scapy/WinPcap):
   - 네트워크 인터페이스 레벨에서 동작
   - 모든 패킷을 "볼 수" 있음 (프로미스큐어스 모드)
   - 방화벽보다 하위 레벨
   
🛡️ Windows 방화벽:
   - OS 커널 레벨에서 동작
   - 패킷을 DROP하여 애플리케이션에 전달하지 않음
   - 패킷 캡처보다 상위 레벨
   
📊 네트워크 스택 순서:
   1. 물리적 네트워크 인터페이스 (패킷 도착)
   2. 패킷 캡처 레이어 (Scapy가 여기서 캡처) ← 차단된 패킷도 보임
   3. Windows 방화벽 (여기서 차단) ← 차단 지점
   4. OS 네트워크 스택
   5. 애플리케이션 (웹서버, SSH 등) ← 차단된 패킷은 도달 안 함
   
✅ 결론:
   - IPS 시스템이 차단된 IP의 패킷을 "캡처"하는 것은 정상입니다.
   - 중요한 것은 해당 패킷이 실제 서비스(웹서버, SSH 등)에
     도달하지 못하는지 확인하는 것입니다.
""")
    print("="*60 + "\n")

def main():
    """메인 함수"""
    print("\n" + "="*60)
    print("  IP 차단 검증 도구")
    print("="*60)
    
    # 관리자 권한 확인
    if not check_admin():
        print("\n⚠️ 경고: 관리자 권한이 필요합니다!")
        print("   이 스크립트를 관리자 권한으로 실행하세요.\n")
        input("아무 키나 눌러 종료...")
        return
    
    print("\n✅ 관리자 권한 확인 완료\n")
    
    # 패킷 캡처 vs 방화벽 설명
    explain_packet_capture_vs_firewall()
    
    # 차단된 IP 목록 가져오기
    print("차단된 IP 목록을 가져오는 중...\n")
    blocked_ips = get_blocked_ips()
    
    if not blocked_ips:
        print("❌ 현재 차단된 IP가 없습니다.\n")
        input("아무 키나 눌러 종료...")
        return
    
    print(f"📋 차단된 IP: {len(blocked_ips)}개\n")
    for i, ip in enumerate(blocked_ips, 1):
        print(f"   {i}. {ip}")
    
    # 테스트할 IP 선택
    print("\n" + "="*60)
    if len(blocked_ips) == 1:
        test_ip = blocked_ips[0]
        print(f"테스트 IP: {test_ip}")
    else:
        print("테스트할 IP를 선택하세요:")
        try:
            choice = int(input(f"번호 입력 (1-{len(blocked_ips)}): "))
            if 1 <= choice <= len(blocked_ips):
                test_ip = blocked_ips[choice - 1]
            else:
                print("잘못된 선택입니다.")
                input("\n아무 키나 눌러 종료...")
                return
        except:
            print("잘못된 입력입니다.")
            input("\n아무 키나 눌러 종료...")
            return
    
    # 방화벽 규칙 상세 정보 확인
    rule_exists = check_firewall_rule_details(test_ip)
    
    if not rule_exists:
        print(f"❌ {test_ip}에 대한 방화벽 규칙을 찾을 수 없습니다!")
        print("   차단이 제대로 적용되지 않았을 수 있습니다.\n")
        input("아무 키나 눌러 종료...")
        return
    
    # 연결 테스트
    print(f"\n⚠️ 주의: {test_ip}가 실제 존재하는 호스트인 경우에만 테스트가 의미있습니다.")
    choice = input("연결 테스트를 진행하시겠습니까? (y/n): ")
    
    if choice.lower() == 'y':
        test_connection_to_blocked_ip(test_ip)
    
    print("\n" + "="*60)
    print("✅ 검증 완료!")
    print("="*60)
    print("""
💡 팁:
   1. IPS 시스템이 차단된 IP의 패킷을 캡처하는 것은 정상입니다.
   2. 중요한 것은 해당 IP가 실제 서비스에 접근할 수 없는지입니다.
   3. 다른 PC에서 차단된 IP로 접속을 시도해보세요.
   4. 웹서버, SSH 등의 서비스가 응답하지 않으면 차단이 성공한 것입니다.
""")
    print("="*60 + "\n")
    
    input("아무 키나 눌러 종료...")

if __name__ == "__main__":
    main()
