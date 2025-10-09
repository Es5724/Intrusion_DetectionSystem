#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
IPS 시스템 진단 스크립트

다른 환경에서 실행 시 문제를 자동으로 진단하고 해결 방안을 제시합니다.
"""

import os
import sys
import platform
import subprocess

def print_section(title):
    """섹션 제목 출력"""
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)

def check_python_version():
    """Python 버전 확인"""
    print_section("1. Python 버전 확인")
    version = sys.version_info
    print(f"✓ Python {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8 이상이 필요합니다!")
        print("   https://python.org 에서 최신 버전을 다운로드하세요.")
        return False
    else:
        print("✅ Python 버전 요구사항 충족")
        return True

def check_admin_privileges():
    """관리자 권한 확인"""
    print_section("2. 관리자 권한 확인")
    
    try:
        if platform.system() == 'Windows':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        else:
            is_admin = os.getuid() == 0
        
        if is_admin:
            print("✅ 관리자 권한으로 실행 중")
            return True
        else:
            print("⚠️ 관리자 권한이 없습니다!")
            print("   Windows: 프로그램을 우클릭 → '관리자 권한으로 실행'")
            print("   Linux/Mac: sudo python IDS/IPSAgent_RL.py")
            return False
    except Exception as e:
        print(f"⚠️ 권한 확인 실패: {e}")
        return False

def check_required_packages():
    """필수 패키지 설치 확인"""
    print_section("3. 필수 패키지 확인")
    
    required_packages = {
        'numpy': 'numpy',
        'pandas': 'pandas',
        'sklearn': 'scikit-learn',
        'torch': 'torch',
        'joblib': 'joblib',
        'scapy': 'scapy',
        'colorama': 'colorama',
        'psutil': 'psutil'
    }
    
    missing_packages = []
    
    for module_name, package_name in required_packages.items():
        try:
            __import__(module_name)
            print(f"✅ {package_name}")
        except ImportError:
            print(f"❌ {package_name} - 설치 필요!")
            missing_packages.append(package_name)
    
    if missing_packages:
        print("\n📦 누락된 패키지 설치 명령:")
        print(f"   pip install {' '.join(missing_packages)}")
        return False
    else:
        print("\n✅ 모든 필수 패키지가 설치되어 있습니다")
        return True

def check_npcap_installation():
    """Npcap 설치 확인 (Windows 전용)"""
    print_section("4. 패킷 캡처 드라이버 확인")
    
    if platform.system() != 'Windows':
        print("ℹ️  Linux/Mac은 libpcap이 필요합니다")
        # libpcap 확인
        try:
            result = subprocess.run(['ldconfig', '-p'], capture_output=True, text=True)
            if 'libpcap' in result.stdout:
                print("✅ libpcap 설치됨")
                return True
            else:
                print("❌ libpcap이 설치되지 않았습니다")
                print("   Ubuntu/Debian: sudo apt-get install libpcap-dev")
                print("   CentOS/RHEL: sudo yum install libpcap-devel")
                print("   macOS: brew install libpcap")
                return False
        except:
            print("⚠️ libpcap 확인 불가 (직접 확인 필요)")
            return None
    
    # Windows - Npcap 확인
    npcap_paths = [
        r"C:\Windows\System32\Npcap",
        r"C:\Program Files\Npcap",
        r"C:\Windows\System32\wpcap.dll"
    ]
    
    npcap_found = False
    for path in npcap_paths:
        if os.path.exists(path):
            print(f"✅ Npcap 발견: {path}")
            npcap_found = True
            break
    
    if not npcap_found:
        print("❌ Npcap이 설치되지 않았습니다!")
        print("   다운로드: https://npcap.com/#download")
        print("   ⚠️ 설치 시 'WinPcap API 호환 모드' 체크 필수!")
        return False
    
    return True

def check_network_interfaces():
    """네트워크 인터페이스 확인"""
    print_section("5. 네트워크 인터페이스 확인")
    
    try:
        import psutil
        interfaces = psutil.net_if_addrs()
        active_interfaces = []
        
        for interface_name, addrs in interfaces.items():
            if interface_name.lower() in ['lo', 'loopback']:
                continue
            
            for addr in addrs:
                if addr.family == 2:  # AF_INET (IPv4)
                    active_interfaces.append((interface_name, addr.address))
                    print(f"✅ {interface_name}: {addr.address}")
        
        if not active_interfaces:
            print("❌ 활성 네트워크 인터페이스를 찾을 수 없습니다!")
            return False
        else:
            print(f"\n✅ {len(active_interfaces)}개의 네트워크 인터페이스 발견")
            return True
            
    except ImportError:
        print("⚠️ psutil이 설치되지 않아 인터페이스 확인 불가")
        print("   pip install psutil")
        return None
    except Exception as e:
        print(f"⚠️ 인터페이스 확인 중 오류: {e}")
        return None

def check_required_files():
    """필수 파일 및 디렉토리 확인"""
    print_section("6. 필수 파일 및 디렉토리 확인")
    
    required_dirs = [
        'logs',
        'processed_data',
        'scan_results',
        'IDS/modules',
        'IDS/config'
    ]
    
    required_files = [
        'IDS/IPSAgent_RL.py',
        'IDS/defense_config.json',
        'IDS/modules/packet_capture.py',
        'IDS/modules/defense_mechanism.py',
        'IDS/modules/utils.py'
    ]
    
    all_good = True
    
    # 디렉토리 확인
    print("📁 디렉토리:")
    for dir_path in required_dirs:
        if os.path.exists(dir_path):
            print(f"  ✅ {dir_path}")
        else:
            print(f"  ❌ {dir_path} - 생성 필요!")
            all_good = False
            try:
                os.makedirs(dir_path, exist_ok=True)
                print(f"     → 자동 생성 완료")
            except Exception as e:
                print(f"     → 생성 실패: {e}")
    
    # 파일 확인
    print("\n📄 필수 파일:")
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"  ✅ {file_path}")
        else:
            print(f"  ❌ {file_path} - 누락!")
            all_good = False
    
    # 모델 파일 확인 (선택적)
    print("\n🤖 머신러닝 모델 (선택적):")
    model_files = [
        'IDS/kisti_random_forest_model.pkl',
        'IDS/ips_random_forest_model.pkl',
        'random_forest_model.pkl'
    ]
    
    model_found = False
    for model_file in model_files:
        if os.path.exists(model_file):
            print(f"  ✅ {model_file}")
            model_found = True
            break
    
    if not model_found:
        print("  ⚠️ 모델 파일 없음 - 첫 실행 시 자동 학습")
    
    return all_good

def check_firewall_settings():
    """방화벽 설정 확인"""
    print_section("7. 방화벽 설정 확인")
    
    if platform.system() == 'Windows':
        try:
            # Windows 방화벽 상태 확인
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'currentprofile'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                print("✅ Windows 방화벽 접근 가능")
                
                # IDS 규칙 확인
                result2 = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                ids_rules = result2.stdout.count('IDS_Block')
                if ids_rules > 0:
                    print(f"ℹ️  기존 IDS 차단 규칙 {ids_rules}개 발견")
                
                return True
            else:
                print("⚠️ 방화벽 접근 권한 없음 - 관리자 권한 필요")
                return False
                
        except subprocess.TimeoutExpired:
            print("⚠️ 방화벽 명령 타임아웃")
            return False
        except Exception as e:
            print(f"⚠️ 방화벽 확인 중 오류: {e}")
            return False
    else:
        print("ℹ️  Linux/Mac - iptables/pf 수동 확인 필요")
        return None

def check_port_availability():
    """포트 사용 가능 여부 확인"""
    print_section("8. 포트 사용 가능 여부")
    
    import socket
    
    # 웹 API 서버 포트 (선택적)
    web_port = 5000
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('0.0.0.0', web_port))
        sock.close()
        print(f"✅ 포트 {web_port} 사용 가능 (웹 API용)")
        return True
    except OSError:
        print(f"⚠️ 포트 {web_port} 이미 사용 중")
        print(f"   --web-port 옵션으로 다른 포트 지정 가능")
        return False
    except Exception as e:
        print(f"⚠️ 포트 확인 중 오류: {e}")
        return None

def run_quick_test():
    """간단한 패킷 캡처 테스트"""
    print_section("9. 패킷 캡처 간단 테스트")
    
    try:
        from scapy.all import sniff, conf
        
        print("🔍 Scapy 패킷 캡처 테스트 중...")
        print(f"   기본 인터페이스: {conf.iface}")
        
        # 1초 동안 패킷 캡처 시도
        packets = sniff(timeout=1, count=10, iface=conf.iface)
        
        if len(packets) > 0:
            print(f"✅ 패킷 캡처 성공! ({len(packets)}개 캡처됨)")
            return True
        else:
            print("⚠️ 패킷이 캡처되지 않았습니다")
            print("   가능한 원인:")
            print("   - 네트워크 트래픽이 없음")
            print("   - 인터페이스 설정 오류")
            print("   - 권한 부족")
            return False
            
    except PermissionError:
        print("❌ 권한 오류! 관리자 권한으로 실행하세요")
        return False
    except Exception as e:
        print(f"❌ 패킷 캡처 테스트 실패: {e}")
        print("   Npcap/libpcap 설치를 확인하세요")
        return False

def check_log_files():
    """로그 파일 확인"""
    print_section("10. 로그 파일 확인")
    
    log_files = [
        'logs/ips_debug.log',
        'logs/defense_actions.log'
    ]
    
    for log_file in log_files:
        if os.path.exists(log_file):
            size = os.path.getsize(log_file)
            print(f"✅ {log_file} ({size} bytes)")
            
            # 최근 에러 확인
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    errors = [line for line in lines[-50:] if 'ERROR' in line or 'CRITICAL' in line]
                    
                    if errors:
                        print(f"   ⚠️ 최근 에러 {len(errors)}개 발견:")
                        for error in errors[-3:]:  # 최근 3개만 표시
                            print(f"      {error.strip()[:80]}")
            except Exception as e:
                print(f"   ⚠️ 로그 읽기 실패: {e}")
        else:
            print(f"ℹ️  {log_file} - 아직 생성되지 않음")
    
    return True

def generate_fix_script():
    """문제 해결 스크립트 생성"""
    print_section("자동 수정 스크립트 생성")
    
    fix_script = """@echo off
echo ====================================
echo IPS 시스템 자동 수정 스크립트
echo ====================================

REM 필수 디렉토리 생성
mkdir logs 2>nul
mkdir processed_data 2>nul
mkdir scan_results 2>nul
mkdir IDS\\logs 2>nul
mkdir IDS\\processed_data 2>nul

echo ✅ 디렉토리 생성 완료

REM Python 패키지 설치
echo.
echo 📦 필수 패키지 설치 중...
pip install -r requirements.txt

echo.
echo ✅ 자동 수정 완료!
echo.
echo 다음 명령으로 시스템을 실행하세요:
echo    python IDS/IPSAgent_RL.py
echo.
pause
"""
    
    try:
        with open('fix_system.bat', 'w', encoding='utf-8') as f:
            f.write(fix_script)
        print("✅ fix_system.bat 생성 완료")
        print("   이 스크립트를 관리자 권한으로 실행하여 문제를 자동으로 수정할 수 있습니다")
        return True
    except Exception as e:
        print(f"⚠️ 스크립트 생성 실패: {e}")
        return False

def main():
    """메인 진단 함수"""
    print("\n")
    print("╔" + "="*58 + "╗")
    print("║" + " "*15 + "IPS 시스템 진단 도구" + " "*22 + "║")
    print("╚" + "="*58 + "╝")
    
    results = []
    
    # 진단 항목 실행
    results.append(("Python 버전", check_python_version()))
    results.append(("관리자 권한", check_admin_privileges()))
    results.append(("필수 패키지", check_required_packages()))
    results.append(("패킷 캡처 드라이버", check_npcap_installation()))
    results.append(("네트워크 인터페이스", check_network_interfaces()))
    results.append(("필수 파일", check_required_files()))
    results.append(("방화벽 설정", check_firewall_settings()))
    results.append(("포트 사용 가능", check_port_availability()))
    
    # 패킷 캡처 테스트 (선택적)
    print("\n")
    response = input("패킷 캡처 간단 테스트를 실행하시겠습니까? (y/n): ")
    if response.lower() in ['y', 'yes']:
        results.append(("패킷 캡처 테스트", run_quick_test()))
    
    results.append(("로그 파일", check_log_files()))
    
    # 결과 요약
    print_section("진단 결과 요약")
    
    passed = sum(1 for _, result in results if result is True)
    failed = sum(1 for _, result in results if result is False)
    skipped = sum(1 for _, result in results if result is None)
    
    print(f"\n✅ 통과: {passed}개")
    print(f"❌ 실패: {failed}개")
    print(f"⚠️ 확인 불가: {skipped}개")
    
    # 실패한 항목 표시
    if failed > 0:
        print("\n❌ 해결 필요한 항목:")
        for name, result in results:
            if result is False:
                print(f"   - {name}")
        
        print("\n💡 해결 방법:")
        print("   1. fix_system.bat를 관리자 권한으로 실행 (자동 수정)")
        print("   2. 위의 각 섹션에서 제시된 해결 방법 확인")
        print("   3. INSTALLATION_GUIDE.md 참조")
        
        # 자동 수정 스크립트 생성
        print("\n")
        response = input("자동 수정 스크립트를 생성하시겠습니까? (y/n): ")
        if response.lower() in ['y', 'yes']:
            generate_fix_script()
    else:
        print("\n🎉 모든 진단 항목 통과!")
        print("   시스템을 실행할 준비가 되었습니다.")
        print("\n실행 명령:")
        print("   python IDS/IPSAgent_RL.py")
    
    print("\n" + "="*60)
    print("진단 완료!")
    print("="*60 + "\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n진단이 중단되었습니다.")
    except Exception as e:
        print(f"\n\n진단 중 오류 발생: {e}")
        import traceback
        traceback.print_exc()

