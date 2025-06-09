#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
포트 스캔 탐지 및 취약점 분석 시스템 데모

이 스크립트는 새로 구현된 포트 스캔 탐지 시스템의 핵심 기능을 보여줍니다.
"""

import os
import sys
import time
from datetime import datetime

# 현재 디렉토리를 Python 경로에 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)
sys.path.append(os.path.join(current_dir, 'modules'))

def demo_port_scan_detection():
    """포트 스캔 탐지 데모"""
    print("🔍 포트 스캔 탐지 시스템 데모")
    print("=" * 50)
    
    try:
        from modules.port_scan_detector import PortScanDetector
        
        # 포트 스캔 탐지기 초기화
        detector = PortScanDetector()
        print("✅ 포트 스캔 탐지기 초기화 완료")
        
        # 시뮬레이션: 빠른 포트 스캔 패턴
        print("\n📡 포트 스캔 시뮬레이션 (빠른 스캔)")
        attacker_ip = "10.0.0.100"
        
        # 연속으로 여러 포트에 SYN 패킷 전송하는 패턴 시뮬레이션
        for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]:
            packet = {
                'source': attacker_ip,
                'destination': f'192.168.1.1:{port}',
                'protocol': '6',  # TCP
                'info': f'TCP 12345 → {port} [SYN] Seq=0 Win=8192 Len=0'
            }
            
            is_scan, risk_score, scan_type = detector.analyze_packet(packet)
            
            if is_scan:
                print(f"🚨 포트 스캔 탐지!")
                print(f"   출발지: {attacker_ip}")
                print(f"   위험도: {risk_score:.2f}")
                print(f"   스캔 패턴: {scan_type}")
                break
            else:
                print(f"   패킷 분석: 포트 {port} (스캔 미탐지)")
                time.sleep(0.1)  # 짧은 간격으로 스캔
        
        # 스캔 통계 출력
        stats = detector.get_scan_statistics(attacker_ip)
        if stats:
            print(f"\n📊 스캔 통계:")
            print(f"   총 스캔된 포트: {stats['total_ports_scanned']}")
            print(f"   스캔 타입 분포: {stats['scan_types']}")
            print(f"   최근 활동: {stats['recent_activity']}")
        
        detector.shutdown()
        
    except ImportError as e:
        print(f"❌ 모듈 로드 실패: {e}")

def demo_vulnerability_analysis():
    """취약점 분석 데모"""
    print("\n🛡️ 취약점 분석 시스템 데모")
    print("=" * 50)
    
    try:
        from modules.port_scan_detector import VulnerabilityScanner
        
        scanner = VulnerabilityScanner()
        print("✅ 취약점 스캐너 초기화 완료")
        
        # 시뮬레이션: 다양한 위험도의 열린 포트들
        target_system = "192.168.1.10"
        open_ports = [
            22,    # SSH (medium)
            23,    # Telnet (critical)
            80,    # HTTP (low)
            443,   # HTTPS (low)
            3306,  # MySQL (high)
            4444,  # Backdoor (critical)
        ]
        
        print(f"\n🎯 분석 대상: {target_system}")
        print(f"   열린 포트: {open_ports}")
        
        # 취약점 분석 수행
        analysis = scanner.analyze_open_ports(open_ports, target_system)
        
        print(f"\n📋 분석 결과:")
        print(f"   전체 위험도: {analysis['overall_risk'].upper()}")
        print(f"   총 열린 포트: {analysis['total_open_ports']}개")
        
        # 위험도별 통계
        risk_summary = analysis['risk_summary']
        print(f"   위험도 분포:")
        print(f"      치명적: {risk_summary['critical']}개")
        print(f"      높음: {risk_summary['high']}개")  
        print(f"      중간: {risk_summary['medium']}개")
        print(f"      낮음: {risk_summary['low']}개")
        
        print(f"\n🏥 발견된 취약점:")
        if analysis['vulnerabilities']:
            for vuln in analysis['vulnerabilities']:
                print(f"   - {vuln['description']}")
        else:
            print("   치명적 취약점 없음")
        
        print(f"\n💡 주요 권장사항:")
        for i, rec in enumerate(analysis['recommendations'][:3], 1):
            print(f"   {i}. {rec}")
        
    except ImportError as e:
        print(f"❌ 모듈 로드 실패: {e}")

def demo_security_hardening():
    """보안 강화 데모"""
    print("\n🔒 보안 강화 시스템 데모")
    print("=" * 50)
    
    try:
        from modules.port_scan_detector import SecurityHardening
        
        hardening = SecurityHardening()
        print("✅ 보안 강화 시스템 초기화 완료")
        
        # 시뮬레이션: 높은 위험 포트 스캔 탐지
        threat_scenario = {
            'source_ip': '10.0.0.100',
            'risk_level': 'high',
            'scan_type': 'syn_scan',
            'confidence': 0.85
        }
        
        print(f"\n⚠️ 위협 시나리오:")
        print(f"   출발지 IP: {threat_scenario['source_ip']}")
        print(f"   위험 수준: {threat_scenario['risk_level']}")
        print(f"   스캔 타입: {threat_scenario['scan_type']}")
        print(f"   신뢰도: {threat_scenario['confidence']:.2f}")
        
        # 자동 대응 조치 적용
        print(f"\n🚨 자동 대응 조치:")
        actions = hardening.apply_emergency_response(threat_scenario)
        for i, action in enumerate(actions, 1):
            print(f"   {i}. {action}")
        
    except ImportError as e:
        print(f"❌ 모듈 로드 실패: {e}")

def demo_integrated_defense():
    """통합 방어 시스템 데모"""
    print("\n🛡️ 통합 방어 시스템 데모")
    print("=" * 50)
    
    try:
        from modules.defense_mechanism import DefenseManager
        
        # 경량 모드로 방어 관리자 초기화
        print("🚀 방어 관리자 초기화 중...")
        defense_manager = DefenseManager(mode="lightweight")
        print("✅ 방어 관리자 초기화 완료")
        
        # 시뮬레이션: 실시간 포트 스캔 탐지
        print("\n📡 실시간 포트 스캔 탐지 시뮬레이션")
        
        # 정상 트래픽
        normal_packet = {
            'source': '192.168.1.200',
            'destination': '192.168.1.1:80',
            'protocol': '6',
            'info': 'TCP 54321 → 80 [ACK] Seq=100 Ack=1 Win=8192 Len=512'
        }
        
        print("   정상 패킷 처리 중...")
        defense_manager.handle_packet(normal_packet)
        
        # 악의적 포트 스캔 트래픽
        print("   포트 스캔 패킷 처리 중...")
        for port in [22, 23, 3306, 4444]:  # 위험한 포트들
            scan_packet = {
                'source': '10.0.0.50',
                'destination': f'192.168.1.1:{port}',
                'protocol': '6',
                'info': f'TCP 12345 → {port} [SYN] Seq=0 Win=8192 Len=0'
            }
            defense_manager.handle_packet(scan_packet)
            time.sleep(0.1)
        
        # 스캔 통계 확인
        print(f"\n📊 탐지 결과:")
        stats = defense_manager.get_port_scan_statistics('10.0.0.50')
        if stats:
            print(f"   스캔된 포트 수: {stats.get('total_ports_scanned', 0)}")
            print(f"   스캔 타입: {stats.get('scan_types', {})}")
        else:
            print("   스캔 통계 없음")
        
        # 방어 관리자 종료
        defense_manager.shutdown()
        print("✅ 방어 관리자 정상 종료")
        
    except ImportError as e:
        print(f"❌ 모듈 로드 실패: {e}")
    except Exception as e:
        print(f"❌ 시스템 오류: {e}")

def main():
    """메인 데모 함수"""
    print("🚀 포트 스캔 탐지 및 취약점 분석 시스템 데모")
    print(f"시작 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    try:
        # 순차적으로 각 기능 데모
        demo_port_scan_detection()
        demo_vulnerability_analysis()
        demo_security_hardening()
        demo_integrated_defense()
        
        print("\n" + "=" * 60)
        print("🎉 모든 데모 완료!")
        print("\n📋 구현된 주요 기능:")
        print("   ✅ 실시간 포트 스캔 탐지")
        print("   ✅ 시간 기반 패턴 분석")
        print("   ✅ 취약점 위험도 평가")
        print("   ✅ 자동 보안 대응")
        print("   ✅ 통합 방어 시스템")
        
        print("\n💡 사용법:")
        print("   1. DefenseManager()로 통합 시스템 초기화")
        print("   2. register_to_packet_capture()로 실시간 탐지 활성화")
        print("   3. perform_port_scan()으로 능동적 스캔 및 분석")
        
    except Exception as e:
        print(f"\n❌ 데모 실행 중 오류: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 