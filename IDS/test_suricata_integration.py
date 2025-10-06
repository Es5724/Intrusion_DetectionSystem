#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Suricata 통합 테스트 스크립트

퍼포먼스 모드에서 Suricata 엔진이 제대로 통합되어 있는지 확인합니다.
"""
import os
import sys
import time

# 프로젝트 루트 경로 추가
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'IDS'))
sys.path.insert(0, os.path.join(project_root, 'IDS', 'modules'))

print("="*70)
print("Suricata 통합 상태 테스트")
print("="*70)

# 1. 모듈 임포트 테스트
print("\n[1단계] 모듈 임포트 테스트")
print("-"*70)

try:
    from modules import SURICATA_SUPPORT
    print(f"✓ SURICATA_SUPPORT 플래그: {SURICATA_SUPPORT}")
    
    if SURICATA_SUPPORT:
        from modules.suricata_manager import SuricataManager
        print("✓ SuricataManager 클래스 임포트 성공")
    else:
        print("✗ Suricata 지원 모듈이 없습니다.")
        print("  원인: suricata_manager.py 모듈을 찾을 수 없음")
except ImportError as e:
    print(f"✗ 모듈 임포트 실패: {e}")
    SURICATA_SUPPORT = False

# 2. Suricata 바이너리 확인
print("\n[2단계] Suricata 실행 파일 확인")
print("-"*70)

if SURICATA_SUPPORT:
    try:
        suricata_manager = SuricataManager()
        suricata_path = suricata_manager.suricata_path
        
        if suricata_path:
            print(f"✓ Suricata 실행 파일 찾음: {suricata_path}")
            
            # 버전 확인 시도
            import subprocess
            try:
                result = subprocess.run(
                    [suricata_path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    version_line = result.stdout.split('\n')[0]
                    print(f"  버전: {version_line}")
                else:
                    print("  경고: 버전 확인 실패")
            except Exception as ve:
                print(f"  경고: 버전 확인 중 오류 - {ve}")
        else:
            print("✗ Suricata 실행 파일을 찾을 수 없습니다.")
            print("  원인: PATH에 suricata가 없거나 설치되지 않음")
    except Exception as e:
        print(f"✗ Suricata 바이너리 확인 실패: {e}")
else:
    print("✗ Suricata 지원 모듈이 없어 건너뜁니다.")

# 3. DefenseManager 통합 테스트
print("\n[3단계] DefenseManager 통합 테스트")
print("-"*70)

try:
    from modules.defense_mechanism import DefenseManager
    
    # Lightweight 모드 테스트
    print("\n[3-1] Lightweight 모드:")
    defense_lightweight = DefenseManager(mode="lightweight")
    print(f"  - 초기화 모드: {defense_lightweight.mode}")
    print(f"  - Suricata 활성화: {defense_lightweight.suricata_enabled}")
    
    if defense_lightweight.suricata_enabled:
        print("  ✗ 경고: Lightweight 모드에서 Suricata가 활성화되어 있습니다!")
    else:
        print("  ✓ 정상: Lightweight 모드에서는 Suricata 비활성화")
    
    # Performance 모드 테스트
    print("\n[3-2] Performance 모드:")
    defense_performance = DefenseManager(mode="performance")
    print(f"  - 초기화 모드: {defense_performance.mode}")
    print(f"  - Suricata 활성화: {defense_performance.suricata_enabled}")
    
    if defense_performance.mode == "performance" and SURICATA_SUPPORT:
        if defense_performance.suricata_enabled:
            print("  ✓ 정상: Performance 모드에서 Suricata 활성화됨")
            print(f"  - Suricata Manager 객체: {defense_performance.suricata_manager}")
        else:
            print("  ✗ 경고: Performance 모드이지만 Suricata가 활성화되지 않음")
            print("  원인: Suricata 초기화 중 오류 발생 가능")
    elif defense_performance.mode == "lightweight":
        print("  ⚠️ Performance 모드 요청했으나 Lightweight로 전환됨")
        print("  원인: Suricata 지원 불가 또는 초기화 실패")
    
    # 상태 정보 출력
    print("\n[3-3] DefenseManager 상태 정보:")
    status = defense_performance.get_status()
    for key, value in status.items():
        if key == 'suricata_enabled':
            print(f"  - {key}: {value}")
        elif key == 'suricata_stats':
            print(f"  - {key}: {value}")
    
except Exception as e:
    print(f"✗ DefenseManager 통합 테스트 실패: {e}")
    import traceback
    traceback.print_exc()

# 4. AutoDefenseActions 통합 테스트
print("\n[4단계] AutoDefenseActions 통합 테스트")
print("-"*70)

try:
    from modules.defense_mechanism import AutoDefenseActions
    
    # Lightweight 모드
    print("\n[4-1] Lightweight 모드:")
    auto_defense_lightweight = AutoDefenseActions(mode="lightweight")
    print(f"  - Suricata 활성화: {auto_defense_lightweight.suricata_enabled}")
    
    # Performance 모드
    print("\n[4-2] Performance 모드:")
    auto_defense_performance = AutoDefenseActions(mode="performance")
    print(f"  - Suricata 활성화: {auto_defense_performance.suricata_enabled}")
    
    if SURICATA_SUPPORT and auto_defense_performance.suricata_enabled:
        print("  ✓ 정상: AutoDefenseActions에서 Suricata 활성화됨")
        print(f"  - Suricata 객체: {auto_defense_performance.suricata}")
    elif SURICATA_SUPPORT:
        print("  ✗ 경고: Suricata 지원되지만 활성화되지 않음")
    else:
        print("  ⚠️ Suricata 지원 모듈 없음")
    
except Exception as e:
    print(f"✗ AutoDefenseActions 통합 테스트 실패: {e}")
    import traceback
    traceback.print_exc()

# 5. 종합 결과 요약
print("\n" + "="*70)
print("종합 결과 요약")
print("="*70)

if SURICATA_SUPPORT:
    print("✓ Suricata 모듈 지원: 가능")
    
    try:
        manager = SuricataManager()
        if manager.suricata_path:
            print("✓ Suricata 실행 파일: 발견됨")
        else:
            print("✗ Suricata 실행 파일: 없음")
    except:
        print("✗ Suricata Manager 초기화: 실패")
    
    try:
        defense = DefenseManager(mode="performance")
        if defense.suricata_enabled:
            print("✓ Performance 모드 통합: 정상 작동")
        else:
            print("✗ Performance 모드 통합: Suricata 비활성화됨")
    except:
        print("✗ Performance 모드 통합: 초기화 실패")
else:
    print("✗ Suricata 모듈 지원: 불가능")
    print("  해결방법:")
    print("  1. suricata_manager.py 파일이 IDS/modules/ 경로에 있는지 확인")
    print("  2. Suricata를 시스템에 설치 (apt install suricata / yum install suricata)")
    print("  3. Windows의 경우 Suricata 바이너리를 PATH에 추가")

print("\n" + "="*70)
print("테스트 완료!")
print("="*70)

# 6. 실제 패킷 분석 시뮬레이션 (선택적)
print("\n[추가 테스트] 패킷 분석 시뮬레이션 테스트")
print("-"*70)

if SURICATA_SUPPORT:
    try:
        defense = DefenseManager(mode="performance")
        
        # 테스트 패킷 데이터
        test_packet = {
            'timestamp': time.time(),
            'source': '192.168.1.100:54321',
            'destination': '10.0.0.1:80',
            'protocol': 'TCP',
            'length': 1024,
            'flags': ['SYN'],
            'ttl': 64
        }
        
        print("\n테스트 패킷 정보:")
        print(f"  - 소스: {test_packet['source']}")
        print(f"  - 목적지: {test_packet['destination']}")
        print(f"  - 프로토콜: {test_packet['protocol']}")
        
        # 패킷 분석 시도
        print("\n패킷 분석 시도 중...")
        result = defense.analyze_packet(test_packet)
        
        if result:
            print(f"✓ 패킷 분석 성공")
            print(f"  - 분석 결과: {result}")
            
            if defense.suricata_enabled:
                print("  - Suricata 분석: 활성화됨")
            else:
                print("  - Suricata 분석: 비활성화됨 (RF 모델만 사용)")
        else:
            print("✗ 패킷 분석 실패")
            
    except Exception as e:
        print(f"✗ 패킷 분석 테스트 실패: {e}")
        import traceback
        traceback.print_exc()
else:
    print("✗ Suricata 지원 불가로 패킷 분석 테스트를 건너뜁니다.")

print("\n" + "="*70)
print("모든 테스트 종료")
print("="*70)

