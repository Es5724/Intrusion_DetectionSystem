# -*- coding: utf-8 -*-
"""
개선된 IPS Agent 탐지 능력 테스트

트래픽 생성기의 8가지 공격 패턴이 제대로 탐지되는지 확인합니다.
"""

import sys
import os

# 모듈 경로 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from modules.defense_mechanism import AutoDefenseActions

def test_attack_detection():
    """각 공격 유형에 대한 탐지 테스트"""
    
    print("\n" + "="*70)
    print("  개선된 IPS Agent 탐지 능력 테스트")
    print("="*70 + "\n")
    
    # AutoDefenseActions 인스턴스 생성
    defense = AutoDefenseActions()
    
    # 테스트 케이스 정의
    test_cases = [
        # 1. SYN 플러드
        {
            'name': 'SYN 플러드',
            'packet': {
                'source': '192.168.1.100:12345',
                'destination': '192.168.1.1:80',
                'protocol': 'tcp',
                'info': 'TCP SYN',
                'length': 64
            },
            'expected_threat': True,
            'min_confidence': 0.90
        },
        
        # 2. UDP 플러드
        {
            'name': 'UDP 플러드',
            'packet': {
                'source': '192.168.1.100:12345',
                'destination': '192.168.1.1:53',
                'protocol': 'udp',
                'info': 'UDP',
                'length': 512
            },
            'expected_threat': True,
            'min_confidence': 0.70
        },
        
        # 3. HTTP Slowloris
        {
            'name': 'HTTP Slowloris',
            'packet': {
                'source': '192.168.1.100:12345',
                'destination': '192.168.1.1:80',
                'protocol': 'tcp',
                'info': 'GET / HTTP/1.1\r\nHost: target\r\nX-Header-1: XXXX',
                'raw_data': 'GET / HTTP/1.1\r\nHost: target\r\nX-Header-1: XXXX\r\nConnection: keep-alive',
                'length': 200
            },
            'expected_threat': True,
            'min_confidence': 0.85
        },
        
        # 4. TCP 핸드셰이크 오용
        {
            'name': 'TCP 핸드셰이크 오용 (RST)',
            'packet': {
                'source': '192.168.1.100:12345',
                'destination': '192.168.1.1:443',
                'protocol': 'tcp',
                'info': 'TCP RST',
                'length': 64
            },
            'expected_threat': True,
            'min_confidence': 0.85
        },
        
        # 5. SSL/TLS 트래픽 공격
        {
            'name': 'SSL/TLS 포트 공격',
            'packet': {
                'source': '192.168.1.100:12345',
                'destination': '192.168.1.1:443',
                'protocol': 'tcp',
                'info': 'TCP SYN',
                'length': 64
            },
            'expected_threat': True,
            'min_confidence': 0.80
        },
        
        # 6. HTTP 요청 변조 - SQL Injection
        {
            'name': 'SQL Injection',
            'packet': {
                'source': '192.168.1.100:12345',
                'destination': '192.168.1.1:80',
                'protocol': 'tcp',
                'info': "GET /?id=1' OR '1'='1 HTTP/1.1",
                'raw_data': "GET /?id=1' OR '1'='1 HTTP/1.1\r\nHost: target\r\n\r\n",
                'length': 100
            },
            'expected_threat': True,
            'min_confidence': 0.90
        },
        
        # 7. HTTP 요청 변조 - XSS
        {
            'name': 'XSS (Cross-Site Scripting)',
            'packet': {
                'source': '192.168.1.100:12345',
                'destination': '192.168.1.1:80',
                'protocol': 'tcp',
                'info': 'GET /<script>alert(1)</script> HTTP/1.1',
                'raw_data': 'GET /<script>alert(1)</script> HTTP/1.1\r\nHost: target\r\n\r\n',
                'length': 100
            },
            'expected_threat': True,
            'min_confidence': 0.90
        },
        
        # 8. HTTP 요청 변조 - Path Traversal
        {
            'name': 'Path Traversal',
            'packet': {
                'source': '192.168.1.100:12345',
                'destination': '192.168.1.1:80',
                'protocol': 'tcp',
                'info': 'GET /../../../etc/passwd HTTP/1.1',
                'raw_data': 'GET /../../../etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n',
                'length': 100
            },
            'expected_threat': True,
            'min_confidence': 0.90
        },
        
        # 9. ARP 스푸핑
        {
            'name': 'ARP 스푸핑',
            'packet': {
                'source': '192.168.1.100',
                'destination': '192.168.1.1',
                'protocol': 'ARP',
                'info': 'ARP Reply',
                'length': 64
            },
            'expected_threat': True,
            'min_confidence': 0.80
        },
        
        # 10. ICMP 리다이렉트
        {
            'name': 'ICMP 리다이렉트',
            'packet': {
                'source': '192.168.1.254',
                'destination': '192.168.1.100',
                'protocol': 'icmp',
                'icmp_type': 5,
                'info': 'ICMP Redirect',
                'length': 64
            },
            'expected_threat': True,
            'min_confidence': 0.90
        },
        
        # 11. 정상 트래픽 (HTTP GET)
        {
            'name': '정상 HTTP 요청',
            'packet': {
                'source': '192.168.1.100:12345',
                'destination': '192.168.1.1:80',
                'protocol': 'tcp',
                'info': 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',
                'raw_data': 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',
                'length': 100
            },
            'expected_threat': False,
            'min_confidence': 0.0
        },
    ]
    
    # 테스트 실행
    passed = 0
    failed = 0
    
    for i, test_case in enumerate(test_cases, 1):
        name = test_case['name']
        packet = test_case['packet']
        expected_threat = test_case['expected_threat']
        min_confidence = test_case['min_confidence']
        
        print(f"{i}. {name}")
        print(f"   패킷: {packet['source']} -> {packet['destination']}")
        
        # 탐지 수행
        prediction, confidence = defense.analyze_packet(packet)
        
        # 결과 판정
        is_threat = prediction == 1
        
        if expected_threat:
            # 위협으로 탐지되어야 함
            if is_threat and confidence >= min_confidence:
                print(f"   ✅ 통과: 위협 탐지됨 (신뢰도: {confidence:.2f})")
                passed += 1
            else:
                print(f"   ❌ 실패: 탐지 안 됨 또는 신뢰도 부족 (예측: {prediction}, 신뢰도: {confidence:.2f}, 최소: {min_confidence:.2f})")
                failed += 1
        else:
            # 정상으로 판단되어야 함
            if not is_threat:
                print(f"   ✅ 통과: 정상 트래픽으로 판단 (신뢰도: {confidence:.2f})")
                passed += 1
            else:
                print(f"   ❌ 실패: 오탐지 (예측: {prediction}, 신뢰도: {confidence:.2f})")
                failed += 1
        
        print()
    
    # 최종 결과
    print("="*70)
    print(f"📊 테스트 결과")
    print("="*70)
    print(f"총 테스트: {len(test_cases)}개")
    print(f"✅ 통과: {passed}개")
    print(f"❌ 실패: {failed}개")
    print(f"성공률: {passed/len(test_cases)*100:.1f}%")
    print("="*70 + "\n")
    
    if failed == 0:
        print("🎉 모든 테스트 통과! IPS Agent가 모든 공격을 탐지할 수 있습니다!")
    else:
        print(f"⚠️ {failed}개 테스트 실패 - 추가 개선이 필요합니다.")
    
    return passed, failed

def main():
    """메인 함수"""
    try:
        passed, failed = test_attack_detection()
        
        if failed == 0:
            print("\n✅ 이제 트래픽 생성기로 실제 공격 테스트를 진행할 수 있습니다!")
            print("\n실행 방법:")
            print("1. 별도 PowerShell 창: python IPSAgent_RL.py --mode performance")
            print("2. 별도 PowerShell 창: python IPS_Training_Data_Generator.py")
            print("3. 트래픽 생성기에서 공격 선택 및 실행\n")
        
    except Exception as e:
        print(f"\n❌ 테스트 중 오류 발생: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
