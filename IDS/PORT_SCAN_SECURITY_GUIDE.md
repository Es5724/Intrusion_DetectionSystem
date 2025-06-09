# 포트 스캔 탐지 및 취약점 분석 시스템 가이드

## 개요

이 시스템은 네트워크 보안을 강화하기 위해 다음과 같은 고급 기능을 제공합니다:

- **실시간 포트 스캔 탐지**: 시간 기반 패턴 분석으로 다양한 스캔 기법 탐지
- **취약점 분석**: 열린 포트의 위험도 평가 및 보안 권장사항 제시
- **자동 보안 대응**: 위협 수준에 따른 단계별 자동 대응
- **보안 강화 권장사항**: 시스템별 맞춤형 보안 개선 방안

## 주요 구성 요소

### 1. PortScanDetector (포트 스캔 탐지기)

**기능:**
- 실시간 패킷 분석을 통한 포트 스캔 패턴 탐지
- 시간 윈도우 기반 스캔 빈도 분석
- 다양한 스캔 기법 분류 (SYN, FIN, NULL, Xmas 등)

**탐지 임계값:**
- 빠른 스캔: 10초 내 10개 포트
- 일반 스캔: 1분 내 50개 포트  
- 느린 스캔: 5분 내 100개 포트
- 스텔스 스캔: 30분 내 200개 포트

**사용 예시:**
```python
from modules.port_scan_detector import PortScanDetector

detector = PortScanDetector()
is_scan, risk_score, scan_type = detector.analyze_packet(packet_info)

if is_scan:
    print(f"포트 스캔 탐지! 위험도: {risk_score:.2f}, 타입: {scan_type}")
```

### 2. VulnerabilityScanner (취약점 스캐너)

**기능:**
- 열린 포트의 서비스 식별 및 위험도 분류
- 포트별 보안 권장사항 제시
- CVE 기반 취약점 데이터베이스 연동
- 종합 보안 보고서 생성

**위험도 분류:**
- **치명적 (Critical)**: 백도어 포트 (4444, 31337 등)
- **높음 (High)**: 데이터베이스, 원격 접속 포트
- **중간 (Medium)**: 웹 서비스, 이메일 포트
- **낮음 (Low)**: 표준 HTTP/HTTPS 포트

**사용 예시:**
```python
from modules.port_scan_detector import VulnerabilityScanner

scanner = VulnerabilityScanner()
analysis = scanner.analyze_open_ports([22, 80, 3306], "192.168.1.1")
print(f"전체 위험도: {analysis['overall_risk']}")
```

### 3. SecurityHardening (보안 강화 시스템)

**기능:**
- 위협 수준별 자동 대응 조치
- 방화벽 규칙 자동 생성
- 시스템 보안 설정 권장사항
- 긴급 대응 프로토콜 실행

**대응 조치:**
- **높은 위협**: IP 즉시 차단, 긴급 알림
- **중간 위협**: 모니터링 강화, 연결 제한
- **낮은 위협**: 로그 기록, 관리자 알림

## 통합 사용법

### 1. 기본 설정

```python
from modules.defense_mechanism import DefenseManager

# 방어 관리자 초기화 (포트 스캔 탐지 포함)
defense_manager = DefenseManager(mode="lightweight")
```

### 2. 실시간 포트 스캔 탐지

패킷 캡처와 연동하여 자동으로 포트 스캔을 탐지합니다:

```python
# 패킷 캡처 시스템에 등록
defense_manager.register_to_packet_capture(packet_capture_core)

# 이후 자동으로 포트 스캔 탐지 및 대응
```

### 3. 능동적 포트 스캔 및 취약점 분석

```python
# 대상 시스템 포트 스캔
target_ip = "192.168.1.100"
ports_to_scan = [21, 22, 23, 80, 443, 3306, 3389, 4444]

result = defense_manager.perform_port_scan(target_ip, ports_to_scan)

if 'error' not in result:
    print(f"스캔 완료: {result['target_ip']}")
    print(f"열린 포트: {result['scan_result']['open']}")
    print(f"전체 위험도: {result['vulnerability_analysis']['overall_risk']}")
    print(f"권장사항: {result['security_recommendations']}")
```

### 4. 스캔 통계 조회

```python
# 특정 IP의 스캔 통계 조회
stats = defense_manager.get_port_scan_statistics("suspicious_ip")

if stats:
    print(f"총 스캔된 포트: {stats['total_ports_scanned']}")
    print(f"스캔 타입: {stats['scan_types']}")
    print(f"최근 활동: {stats['recent_activity']}")
```

### 5. 보안 보고서 생성

```python
# 종합 보안 보고서 생성
report = defense_manager.generate_security_report()
print(report)

# 또는 특정 스캔 결과들로 보고서 생성
scan_results = [result1, result2, result3]
detailed_report = defense_manager.generate_security_report(scan_results)
```

## 설정 파일 (defense_config.json)

```json
{
    "port_scan_detection": {
        "detection_enabled": true,
        "cleanup_interval": 300,
        "max_history_age": 3600,
        "alert_thresholds": {
            "critical": 0.9,
            "high": 0.8,
            "medium": 0.6,
            "low": 0.4
        }
    },
    "auto_response": {
        "enabled": true,
        "block_high_risk_ips": true,
        "emergency_response": true
    }
}
```

## 테스트 실행

포트 스캔 및 취약점 분석 기능을 테스트하려면:

```bash
cd IDS
python test_port_scan_features.py
```

이 테스트는 다음을 검증합니다:
- 포트 스캔 탐지 정확도
- 취약점 분석 기능
- 보안 강화 권장사항
- 실시간 탐지 성능

## 실제 사용 시나리오

### 시나리오 1: 네트워크 모니터링

```python
# 1. 방어 시스템 시작
defense_manager = DefenseManager()

# 2. 패킷 캡처와 연동
defense_manager.register_to_packet_capture(packet_capture)

# 3. 실시간 모니터링 중...
# 포트 스캔이 탐지되면 자동으로:
# - 위협 알림 생성
# - 자동 IP 차단 (고위험 시)
# - 보안 이벤트 로그 기록
```

### 시나리오 2: 주기적 보안 감사

```python
# 네트워크 내 주요 시스템들 스캔
important_systems = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
all_results = []

for system in important_systems:
    result = defense_manager.perform_port_scan(
        system, 
        [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 4444]
    )
    all_results.append(result)

# 종합 보안 보고서 생성
security_report = defense_manager.generate_security_report(all_results)

# 보고서 저장
with open(f"security_audit_{datetime.now().strftime('%Y%m%d')}.txt", "w") as f:
    f.write(security_report)
```

### 시나리오 3: 침입 대응

```python
# 의심스러운 활동 탐지 시
suspicious_ip = "10.0.0.50"

# 1. 해당 IP의 스캔 통계 확인
stats = defense_manager.get_port_scan_statistics(suspicious_ip)

if stats['total_ports_scanned'] > 50:
    print(f"경고: {suspicious_ip}에서 대량 포트 스캔 탐지!")
    
    # 2. 긴급 대응 조치
    threat_info = {
        'source_ip': suspicious_ip,
        'risk_level': 'high',
        'scan_type': 'mass_scan'
    }
    
    actions = defense_manager.security_hardening.apply_emergency_response(threat_info)
    print(f"적용된 대응 조치: {actions}")
```

## 성능 최적화

### 메모리 사용량 최적화
- 스캔 히스토리는 1시간 후 자동 정리
- 최대 1000개 타임스탬프만 유지
- 5분마다 오래된 데이터 정리

### CPU 사용량 최적화
- 패킷 분석은 별도 스레드에서 처리
- 배치 처리로 I/O 최적화
- 임계값 기반 조기 탐지

## 보안 고려사항

1. **오탐 방지**: 정상적인 네트워크 스캔과 악의적 스캔 구분
2. **화이트리스트**: 승인된 보안 도구의 스캔 제외
3. **로그 보안**: 민감한 정보가 포함된 로그의 안전한 저장
4. **권한 관리**: 관리자 권한이 필요한 기능들의 적절한 권한 검증

## 문제 해결

### 일반적인 문제들

**Q: 포트 스캔이 탐지되지 않습니다.**
A: 탐지 임계값 확인, 시간 윈도우 설정 점검

**Q: 너무 많은 오탐이 발생합니다.**
A: 임계값 조정, 화이트리스트 설정 고려

**Q: 성능이 느립니다.**
A: 경량 모드 사용, 정리 주기 단축, 메모리 사용량 확인

### 디버깅

```python
import logging
logging.getLogger("PortScanDetector").setLevel(logging.DEBUG)

# 상세한 디버그 정보 확인
detector = PortScanDetector()
# ... 테스트 실행
```

## 향후 개선 계획

1. **기계학습 기반 탐지**: 더 정확한 스캔 패턴 분류
2. **클라우드 연동**: 위협 인텔리전스 데이터 활용
3. **분산 탐지**: 다중 센서 네트워크 지원
4. **자동 학습**: 네트워크 환경에 따른 임계값 자동 조정 