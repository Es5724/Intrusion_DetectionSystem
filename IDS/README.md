# 침입 탐지 시스템 (IDS) - 데이터 생성 및 전처리 도구

네트워크 패킷 캡처, 트래픽 생성, 데이터 전처리를 위한 통합 애플리케이션입니다.

## 주요 기능

### 1. 패킷 캡처
- 실시간 네트워크 패킷 캡처
- PCAP/PCAPNG 파일 로드 지원
- 패킷 필터링 및 분석

### 2. 트래픽 생성
- 다양한 공격 시뮬레이션
  - SYN Flood
  - UDP Flood
  - HTTP Slowloris
  - TCP Handshake Misuse
  - ARP Spoofing
  - ICMP Redirect
- IP 스푸핑 지원
- 패킷 크기 및 수량 조절 가능

### 3. 데이터 전처리
- CSV 및 PCAP 파일 처리
- 데이터 정규화 및 인코딩
- 머신러닝을 위한 특징 추출

## 설치 방법

### 1. 필수 요구사항
- Python 3.8 이상
- Windows: Npcap 설치 필요
- Linux/Mac: libpcap 설치 필요

### 2. 패키지 설치
```bash
pip install -r requirements.txt
```

### 3. Npcap 설치 (Windows)
1. [Npcap 공식 사이트](https://npcap.com/)에서 다운로드
2. 설치 시 "WinPcap API-compatible Mode" 옵션 선택

### 4. libpcap 설치 (Linux/Mac)
```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# macOS
brew install libpcap
```

## 실행 방법

### 관리자 권한으로 실행 (필수)
```bash
# Windows
관리자 권한으로 명령 프롬프트 실행 후:
python IDS/data_preparation.py

# Linux/Mac
sudo python IDS/data_preparation.py
```

## 사용 방법

### 1. 메인 화면
- 패킷 캡처, 트래픽 생성, 데이터 전처리 중 선택

### 2. 패킷 캡처
1. 네트워크 인터페이스 선택
2. 최대 패킷 수 설정
3. "캡처 시작" 클릭
4. 캡처된 패킷은 실시간으로 테이블에 표시

### 3. 트래픽 생성
1. 대상 IP 주소 입력
2. 공격 유형 선택 (체크박스)
3. 패킷 수 및 크기 설정
4. "트래픽 생성" 클릭

### 4. 데이터 전처리
1. "데이터 파일 업로드" 클릭
2. CSV 또는 PCAP 파일 선택
3. "데이터 전처리" 클릭
4. 전처리된 데이터를 CSV로 저장

## 주의사항

- **법적 책임**: 이 도구는 교육 및 연구 목적으로만 사용하세요
- **네트워크 부하**: 트래픽 생성 시 네트워크에 부하를 줄 수 있습니다
- **관리자 권한**: 패킷 캡처 및 전송을 위해 관리자 권한이 필요합니다

## 문제 해결

### 1. "Npcap이 설치되지 않았습니다" 오류
- Npcap을 설치하고 시스템을 재시작하세요

### 2. "관리자 권한이 필요합니다" 오류
- 프로그램을 관리자 권한으로 실행하세요

### 3. 패킷이 캡처되지 않음
- 올바른 네트워크 인터페이스를 선택했는지 확인
- 방화벽 설정 확인

## 라이선스

이 프로젝트는 교육 목적으로 제작되었습니다. 