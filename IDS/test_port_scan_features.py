#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
포트 스캔 및 취약점 분석 기능 테스트 스크립트

이 스크립트는 새로 구현된 포트 스캔 탐지, 취약점 분석, 보안 강화 기능을 테스트합니다.
"""

import os
import sys
import time
import json
from datetime import datetime

# 현재 디렉토리를 Python 경로에 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)
sys.path.append(os.path.join(current_dir, 'modules'))

try:
    from modules.port_scan_detector import PortScanDetector, VulnerabilityScanner, SecurityHardening
    from modules.defense_mechanism import DefenseManager
    print("✅ 포트 스캔 관련 모듈 임포트 성공")
except ImportError as e:
    print(f"❌ 모듈 임포트 실패: {e}")
    sys.exit(1)

def test_port_scan_detector():
    """포트 스캔 탐지기 테스트"""
    print("\n" + "="*60)
    print("포트 스캔 탐지기 테스트")
    print("="*60)
    
    # 포트 스캔 탐지기 초기화
    detector = PortScanDetector()
    
    # 시뮬레이션 패킷 생성 (SYN 스캔 패턴)
    test_packets = []
    for i in range(15):  # 빠른 스캔 시뮬레이션
        packet = {
            'source': '192.168.1.100',
            'destination': f'192.168.1.1:{80 + i}',
            'protocol': '6',  # TCP
            'info': 'TCP 12345 → 80 [SYN] Seq=0 Win=8192 Len=0'
        }
        test_packets.append(packet)
    
    # 패킷 분석
    print("패킷 분석 중...")
    for i, packet in enumerate(test_packets):
        is_scan, risk_score, scan_type = detector.analyze_packet(packet)
        
        if is_scan:
            print(f"✅ 포트 스캔 탐지! 패킷 #{i+1}")
            print(f"   위험도: {risk_score:.2f}")
            print(f"   스캔 타입: {scan_type}")
            break
        elif i % 5 == 0:
            print(f"패킷 #{i+1} 분석 중... (스캔 미탐지)")
    
    # 통계 조회
    stats = detector.get_scan_statistics('192.168.1.100')
    if stats:
        print(f"\n스캔 통계:")
        print(f"- 총 스캔된 포트: {stats['total_ports_scanned']}")
        print(f"- 스캔 타입: {stats['scan_types']}")
        print(f"- 최근 활동: {stats['recent_activity']}")
    
    detector.shutdown()
    print("포트 스캔 탐지기 테스트 완료 ✅")

def test_vulnerability_scanner():
    """취약점 스캐너 테스트"""
    print("\n" + "="*60)
    print("취약점 스캐너 테스트")
    print("="*60)
    
    scanner = VulnerabilityScanner()
    
    # 테스트용 열린 포트 목록 (일부는 위험한 포트)
    test_open_ports = [22, 23, 80, 443, 3306, 4444, 31337]
    target_ip = "192.168.1.1"
    
    print(f"분석 대상: {target_ip}")
    print(f"열린 포트: {test_open_ports}")
    
    # 취약점 분석 수행
    analysis = scanner.analyze_open_ports(test_open_ports, target_ip)
    
    print(f"\n분석 결과:")
    print(f"- 전체 위험도: {analysis['overall_risk'].upper()}")
    print(f"- 총 열린 포트: {analysis['total_open_ports']}개")
    
    # 위험도별 통계
    risk_summary = analysis['risk_summary']
    print(f"- 위험도 분포: 치명적({risk_summary['critical']}), 높음({risk_summary['high']}), 중간({risk_summary['medium']}), 낮음({risk_summary['low']})")
    
    print("\n발견된 서비스:")
    for service in analysis['services_found']:
        print(f"  포트 {service['port']}: {service['service']} (위험도: {service['risk_level']})")
    
    if analysis['vulnerabilities']:
        print("\n주요 취약점:")
        for vuln in analysis['vulnerabilities']:
            print(f"  - {vuln['description']}")
    
    print("\n권장사항:")
    for rec in analysis['recommendations'][:5]:  # 상위 5개만 표시
        print(f"  - {rec}")
    
    # 보고서 생성
    report = scanner.generate_security_report([analysis])
    print(f"\n보안 보고서 생성됨 (길이: {len(report)} 문자)")
    
    print("취약점 스캐너 테스트 완료 ✅")

def test_security_hardening():
    """보안 강화 시스템 테스트"""
    print("\n" + "="*60)
    print("보안 강화 시스템 테스트")
    print("="*60)
    
    hardening = SecurityHardening()
    
    # 위협 정보 시뮬레이션
    threat_info = {
        'source_ip': '192.168.1.100',
        'risk_level': 'high',
        'scan_type': 'syn_scan',
        'confidence': 0.85
    }
    
    print(f"위협 정보: {threat_info}")
    
    # 긴급 대응 조치 적용
    actions = hardening.apply_emergency_response(threat_info)
    
    print(f"\n적용된 대응 조치:")
    for action in actions:
        print(f"  - {action}")
    
    # 취약점 분석 결과를 바탕으로 권장사항 생성
    vulnerability_analysis = {
        'overall_risk': 'high',
        'services_found': [
            {'port': 22, 'service': 'SSH', 'risk_level': 'medium'},
            {'port': 4444, 'service': 'Backdoor', 'risk_level': 'critical'}
        ],
        'recommendations': ['불필요한 서비스 중지', '방화벽 설정 강화']
    }
    
    recommendations = hardening.generate_hardening_recommendations(vulnerability_analysis)
    
    print(f"\n보안 강화 권장사항:")
    for rec in recommendations:
        print(f"  - {rec}")
    
    print("보안 강화 시스템 테스트 완료 ✅")

def test_integrated_defense_manager():
    """통합 방어 관리자 테스트"""
    print("\n" + "="*60)
    print("통합 방어 관리자 테스트")
    print("="*60)
    
    try:
        # 방어 관리자 초기화
        defense_manager = DefenseManager(mode="lightweight")
        
        print("✅ 방어 관리자 초기화 성공")
        
        # 포트 스캔 수행 (localhost 대상)
        print("\n로컬 포트 스캔 수행 중...")
        target_ip = "127.0.0.1"
        test_ports = [22, 80, 135, 443, 445, 3389, 4444]
        
        scan_result = defense_manager.perform_port_scan(target_ip, test_ports)
        
        if 'error' in scan_result:
            print(f"❌ 스캔 실패: {scan_result['error']}")
        else:
            print(f"✅ 스캔 완료")
            print(f"  대상: {scan_result['target_ip']}")
            
            if 'scan_result' in scan_result:
                sr = scan_result['scan_result']
                print(f"  열린 포트: {len(sr.get('open', []))}개")
                print(f"  닫힌 포트: {len(sr.get('closed', []))}개")
                print(f"  필터링된 포트: {len(sr.get('filtered', []))}개")
            
            if 'vulnerability_analysis' in scan_result and scan_result['vulnerability_analysis']:
                va = scan_result['vulnerability_analysis']
                print(f"  전체 위험도: {va.get('overall_risk', 'unknown')}")
            
            if 'security_recommendations' in scan_result:
                print(f"  보안 권장사항: {len(scan_result['security_recommendations'])}개")
        
        # 보안 보고서 생성
        print("\n보안 보고서 생성 중...")
        report = defense_manager.generate_security_report()
        print(f"보고서 생성됨 (길이: {len(report)} 문자)")
        
        # 방어 관리자 종료
        defense_manager.shutdown()
        print("✅ 방어 관리자 정상 종료")
        
    except Exception as e:
        print(f"❌ 통합 테스트 실패: {e}")
        import traceback
        traceback.print_exc()

def test_packet_simulation():
    """패킷 시뮬레이션을 통한 실시간 탐지 테스트"""
    print("\n" + "="*60)
    print("실시간 포트 스캔 탐지 시뮬레이션")
    print("="*60)
    
    try:
        # 방어 관리자 초기화
        defense_manager = DefenseManager(mode="lightweight")
        
        # 포트 스캔 패킷 시뮬레이션
        print("포트 스캔 패킷 시뮬레이션 중...")
        
        # 정상 패킷 몇 개
        normal_packets = [
            {
                'source': '192.168.1.200',
                'destination': '192.168.1.1:80',
                'protocol': '6',
                'info': 'TCP 54321 → 80 [ACK] Seq=100 Ack=1 Win=8192 Len=512'
            }
        ]
        
        # 포트 스캔 패킷들 (빠른 연속 스캔)
        scan_packets = []
        for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 4444]:
            packet = {
                'source': '10.0.0.50',
                'destination': f'192.168.1.1:{port}',
                'protocol': '6',
                'info': f'TCP 12345 → {port} [SYN] Seq=0 Win=8192 Len=0'
            }
            scan_packets.append(packet)
        
        # 정상 패킷 처리
        print("정상 패킷 처리 중...")
        for packet in normal_packets:
            defense_manager.handle_packet(packet)
        
        # 포트 스캔 패킷 처리 (빠른 속도로)
        print("포트 스캔 패킷 처리 중...")
        for i, packet in enumerate(scan_packets):
            defense_manager.handle_packet(packet)
            if i % 3 == 0:  # 일부만 딜레이
                time.sleep(0.1)
        
        # 스캔 통계 확인
        stats = defense_manager.get_port_scan_statistics('10.0.0.50')
        if stats:
            print(f"\n탐지된 스캔 통계:")
            print(f"- 스캔된 포트 수: {stats.get('total_ports_scanned', 0)}")
            print(f"- 스캔 타입: {stats.get('scan_types', {})}")
            print(f"- 최근 활동: {stats.get('recent_activity', {})}")
        else:
            print("스캔 통계 없음 (탐지되지 않았거나 시스템 오류)")
        
        defense_manager.shutdown()
        print("✅ 실시간 탐지 시뮬레이션 완료")
        
    except Exception as e:
        print(f"❌ 시뮬레이션 실패: {e}")
        import traceback
        traceback.print_exc()

def main():
    """메인 테스트 함수"""
    print("🚀 포트 스캔 및 취약점 분석 시스템 테스트 시작")
    print(f"테스트 시작 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # 개별 모듈 테스트
        test_port_scan_detector()
        test_vulnerability_scanner() 
        test_security_hardening()
        
        # 통합 테스트
        test_integrated_defense_manager()
        test_packet_simulation()
        
        print("\n" + "="*60)
        print("🎉 모든 테스트 완료!")
        print("="*60)
        print("\n주요 기능:")
        print("✅ 포트 스캔 탐지 (시간 기반 패턴 분석)")
        print("✅ 취약점 분석 (포트별 위험도 평가)")
        print("✅ 보안 강화 권장사항")
        print("✅ 실시간 위협 대응")
        print("✅ 통합 보고서 생성")
        
        print("\n사용법:")
        print("1. DefenseManager를 초기화하여 자동 포트 스캔 탐지 활성화")
        print("2. perform_port_scan()으로 능동적 포트 스캔 및 취약점 분석")
        print("3. generate_security_report()로 보안 보고서 생성")
        
    except Exception as e:
        print(f"\n❌ 테스트 중 오류 발생: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 