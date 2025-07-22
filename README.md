# IDS Agent - 침입 탐지 시스템 (Intrusion Detection System 이름 미정)

<div align="center">
  <img src="https://img.shields.io/badge/Language-Python-blue" alt="Language">
  <img src="https://img.shields.io/badge/Framework-PyTorch-orange" alt="Framework">
  <img src="https://img.shields.io/badge/AI-Reinforcement%20Learning-brightgreen" alt="AI">
  <img src="https://img.shields.io/badge/CLI-Enhanced-purple" alt="CLI">
</div>

## 목차

1. [프로젝트 개요](#프로젝트-개요)
2. [프로그램 시작 및 사용법](#프로그램-시작-및-사용법)
3. [사용개발환경](#사용개발환경)
4. [실습 및 테스트 환경](#실습-및-테스트-환경)
5. [프로젝트 구조](#프로젝트-구조)
6. [사용된 모듈](#사용된-모듈)
7. [AI 에이전트 작동 방식](#ai-에이전트-작동-방식)
8. [하이브리드 접근 방식의 특징](#하이브리드-접근-방식의-특징)
9. [주요 시스템 구성 요소](#주요-시스템-구성-요소)
10. [강화학습 관련 클래스 및 메서드](#강화학습-관련-클래스-및-메서드)
11. [모듈 간 통합 및 데이터 흐름](#모듈-간-통합-및-데이터-흐름)
12. [전체 시스템 아키텍처](#전체-시스템-아키텍처)
13. [메모리 최적화 전략](#메모리-최적화-전략)
14. [운영 모드](#운영-모드)
15. [향후 개발 계획](#향후-개발-계획)

## 프로젝트 개요

실시간으로 네트워크 보안 취약점을 탐지하고 자동으로 대응하는 AI 기반 침입 탐지 시스템입니다.   
랜덤 포레스트와 강화학습의 장점을 결합한 하이브리드 접근 방식을 통해 높은 정확도와 적응성을 제공합니다.

### 시스템 핵심 기능

본 시스템은 다음 핵심 기능들이 유기적으로 연결되어 동작합니다:

1. **실시간 패킷 캡처** - 네트워크 인터페이스에서 실시간 패킷 수집 및 큐 관리
2. **데이터 전처리** - 머신러닝 모델에 적합한 데이터 변환 및 특성 추출  
3. **하이브리드 AI 모델** - 랜덤 포레스트와 강화학습(DQN) 통합
4. **실시간 방어 메커니즘** - IP 차단, 트래픽 제어, 자동 대응
5. **위협 알림 시스템** - 위험도별 알림 및 실시간 대시보드
6. **멀티스레드 처리** - 5개 백그라운드 스레드를 통한 동시 처리

## 프로그램 시작 및 사용법

### 설치 요구사항

- **Python**: 3.8 이상 (권장 3.9+)
- **운영체제**: Windows 10+, Linux (Ubuntu 18.04+), macOS 10.15+
- **권한**: Windows에서는 관리자 권한 필요
- **네트워크**: Npcap (Windows) 또는 libpcap (Linux/Mac) 설치 필요
- **고급 기능**: 고성능 모드를 위한 Suricata 엔진 (선택사항)
- **메모리**: 200MB 이상 RAM  (고성능 모드는 1GB 권장)

### 의존성 설치

```bash
# pip 업그레이드
python -m pip install --upgrade pip

# 필수 패키지 설치
pip install colorama pandas numpy scikit-learn torch joblib scapy matplotlib seaborn tqdm psutil

# 또는 requirements.txt 사용
pip install -r requirements.txt
```

### 환경별 추가 설정

#### Windows
- **Npcap 설치**: [공식 웹사이트](https://npcap.com/#download)에서 다운로드
- **관리자 권한**: 프로그램 실행 시 자동으로 관리자 권한 요청

#### Linux/Mac
```bash
# libpcap 설치
sudo apt-get install libpcap-dev  # Ubuntu/Debian
sudo yum install libpcap-devel     # CentOS/RHEL
brew install libpcap               # macOS

# 권한 설정 (선택사항)
sudo setcap cap_net_raw+ep /usr/bin/python3
```

### 실행 방법

#### 자동 설치 및 실행

**Windows 사용자**
```bash
# 관리자 권한으로 명령 프롬프트 실행 후
setup_and_run.bat
```

**Linux/Unix/macOS 사용자**
```bash
# 실행 권한 부여 (최초 1회)
chmod +x setup_and_run.sh

# 실행
sudo ./setup_and_run.sh
```

#### 수동 실행

**기본 실행**
```bash
# 1. 의존성 패키지 설치
pip install -r requirements.txt

# 2. IDS Agent 실행
cd IDS
python IDSAgent_RL.py
```

**명령줄 옵션**
```bash
python IDSAgent_RL.py --mode lightweight    # 경량 모드
python IDSAgent_RL.py --mode performance    # 고성능 모드
python IDSAgent_RL.py --no-menu             # 메뉴 없이 기본 모드로 실행
python IDSAgent_RL.py --max-packets 1000    # 최대 패킷 수 제한
python IDSAgent_RL.py --debug               # 디버그 모드 실행
```

### CLI 인터페이스

#### 시작 화면

프로그램을 실행하면 ASCII 로고와 함께 컬러풀한 인터페이스가 시작됩니다:

```
================================================================================
    ██╗██████╗ ███████╗     █████╗  ██████╗ ███████╗███╗   ██╗████████╗
    ██║██╔══██╗██╔════╝    ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
    ██║██║  ██║███████╗    ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   
    ██║██║  ██║╚════██║    ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   
    ██║██████╔╝███████║    ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   
    ╚═╝╚═════╝ ╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   

           지능형 침입 탐지 시스템 (IDS Agent)
                    강화학습 & 머신러닝 기반
================================================================================
```

#### 모드 선택 메뉴

사용자 친화적인 모드 선택 인터페이스가 제공됩니다:

**1. 경량 모드 (Lightweight Mode)**
- 추천: 일반 사용자, 제한된 시스템 자원 환경
- 빠른 실행 속도
- 낮은 메모리 사용량
- 기본 특성 7개 사용
- 모든 환경에서 실행 가능

**2. 고성능 모드 (Performance Mode)**
- 추천: 전문가, 고사양 시스템 환경
- 수리카타(Suricata) 엔진 통합
- 확장 특성 12개 사용
- 더 높은 정확도의 탐지
- 더 많은 시스템 자원 필요

#### 실행 중 명령어 인터페이스

프로그램 실행 중 다음과 같은 명령어를 사용할 수 있습니다:

| 명령어 | 단축키 | 설명 |
|--------|--------|------|
| `help` | `h` | 도움말 표시 |
| `status` | `s` | 시스템 상태 확인 |
| `packets` | `p` | 패킷 통계 표시 |
| `defense` | `d` | 방어 메커니즘 상태 |
| `ml` | - | 머신러닝 모델 상태 |
| `threats` | `t` | 위협 탐지 상세 통계 |
| `mode` | `m` | 운영 모드 전환 |
| `quit` | `q` | 프로그램 종료 |

#### 실시간 대시보드

시스템은 3초마다 업데이트되는 실시간 대시보드를 제공합니다:

- **시스템 상태**: 가동시간, 운영모드, 인터페이스 정보
- **패킷 캡처 통계**: 총 캡처 수, 초당 패킷 수, 최고 처리량
- **프로토콜 분석**: TCP, UDP, ICMP 등 프로토콜별 통계
- **위협 탐지 현황**: 위험도별 탐지 결과
- **방어 조치 현황**: 차단된 IP, 모니터링 대상
- **AI/ML 엔진 상태**: 예측 수행, 모델 정확도, 업데이트 횟수

#### 컬러 시스템

터미널에서 다음과 같은 컬러 체계를 사용합니다:

- **빨간색**: 오류 메시지, 위험 상태
- **초록색**: 성공 메시지, 정상 상태
- **파란색**: 정보 메시지, 고성능 모드
- **노란색**: 경고 메시지, 경량 모드
- **보라색**: 머신러닝 관련 정보
- **청록색**: 헤더, 타이틀

## 사용개발환경

### 프론트엔드
- **IDE**: WebStorm
- **언어**: JavaScript, CSS
- **프레임워크**: React (웹 시각화 대시보드)

### 백엔드 
- **IDE**: PyCharm
- **언어**: Python
- **프레임워크**: Flask (API 서버)

### IDS 프로그램
- **언어**: Python
- **주요 라이브러리**: Scapy, PyTorch, scikit-learn

### 기타 개발도구
- **Google Colab**: 머신러닝 모델 실험 및 훈련
- **VS Code**: 코드 편집 및 디버깅
- **OpenAI Gym**: 강화학습 환경 구축
- **VMware**: 가상환경

## 실습 및 테스트 환경

### 가상머신 설치 및 상태 확인

#### 테스트용 가상화 플랫폼

**가상화 플랫폼**

| 가상화 플랫폼 | Windows Host | Linux Host | macOS Host |
|---------------|--------------|------------|------------|
| **VMware Workstation** | 지원 | 지원 | 지원 |

**테스트 사용 OS**

| 운영체제 | IDS 시스템 | 침입 테스트 | 용도 |
|----------|------------|-------------|------|
| **Ubuntu 20.04 LTS** | 최적화 | 지원 | IDS 메인 시스템 |
| **Kali Linux** | 지원 | 최적화 | 침입 테스트 도구 |
| **Windows 11** | 지원 | 지원 | 호스트/게스트 겸용 |

**권장 환경**: Ubuntu VM (IDS 시스템용) + Kali Linux VM (침입 테스트용)

#### 가상머신 환경 확인 명령어
1. **가상머신 이름 확인**: `uname -a`
2. **게스트 OS 확인**: `Ubuntu: GNU/Linux [$ uname -o]`
3. **리눅스 배포판 확인**: `Ubuntu [$ uname -r]`

### 테스트베드 주소 정의

| 구분 | SENDER (공격자) | TARGET (방어자) |
|------|----------------|----------------|
| **역할** | 침입 테스트 도구 | IDS 모니터링 대상 |
| **IP 주소** | 실제 호스트 IP, VM IP (Kali, Ubuntu, CentOS), 루프백 주소, 클래스 내 인접 PC IP | 실제 시스템 IP, VM IP (Kali, Ubuntu, CentOS), 루프백 주소, 클래스 내 인접 PC IP |
| **하드웨어** | 실제 터미널 | 실제 터미널 |
| **네트워크 장비** | 허브, 라우터, 게이트웨이 | |
| **운영체제** | Real Host(Windows), VM(Kali, Ubuntu, CentOS) | Real Host(Windows), VM(Kali, Ubuntu, CentOS) |
| **소프트웨어** | **TrafficGeneratorApp.py** (SYN 플러드, UDP 플러드, ARP 스푸핑, ICMP 리다이렉트, HTTP Slowloris), Kali Linux| **IDSAgent_RL.py** (실시간 패킷 캡처, 머신러닝 탐지, 강화학습 방어, 자동 차단 시스템) |

### 실제 테스트 시나리오

#### 기본 테스트 구성
```bash
# SENDER (공격자 VM)
python IDS/scripts/components/TrafficGeneratorApp.py
# 또는 데이터 준비 앱에서 "트래픽 생성" 선택

# TARGET (방어자 VM)  
python IDS/IDSAgent_RL.py
# 또는 데이터 준비 앱에서 "패킷 캡처" 선택
```

#### 네트워크 격리 테스트
- **Host-Only 모드**: 가상머신 간 격리된 네트워크 환경
- **NAT 모드**: 외부 네트워크 접근이 필요한 경우
- **Bridge 모드**: 실제 네트워크와 동일한 환경

#### 테스트 검증 항목
1. **공격 탐지율**: 다양한 공격 패턴에 대한 탐지 성능
2. **오탐률**: 정상 트래픽을 공격으로 잘못 판단하는 비율  
3. **응답 시간**: 공격 탐지부터 방어 조치까지의 시간
4. **자원 사용률**: CPU, 메모리, 네트워크 대역폭 사용량

## 프로젝트 구조

현재 실제 구조에 따른 프로젝트 디렉토리 구성:

```
Intrusion_DetectionSystem/
├── README.md                        # 프로젝트 설명서
├── requirements.txt                 # Python 의존성 목록
├── random_forest_model.pkl         # 사전 훈련된 ML 모델
├── security_alerts.json            # 보안 알림 설정
├── blocked_ips_history.json        # 차단된 IP 이력
├── setup_and_run.sh               # Linux/Mac 설치 및 실행 스크립트
├── setup_and_run.bat              # Windows 설치 및 실행 스크립트
├── ini.iss                        # 설치 패키지 설정
├── .gitignore                     # Git 제외 파일 목록
│
├── IDS/                           # 핵심 IDS 시스템
│   ├── IDSAgent_RL.py             # 메인 통합 에이전트 (CLI 모드)
│   ├── IDS_Training_Data_Generator.py  # 데이터 준비 인터페이스 (GUI)
│   ├── run_AI_agent.bat          # Windows 실행 스크립트
│   ├── REQUIRED_FILES_LIST.md    # 필수 파일 목록
│   ├── defense_config.json       # 방어 설정 파일
│   ├── suricata.log              # 수리카타 로그
│   │
│   ├── modules/                   # 핵심 기능 모듈 (15개 모듈)
│   │   ├── __init__.py
│   │   ├── packet_capture.py      # 기본 패킷 캡처 시스템
│   │   ├── optimized_packet_capture.py        # 고성능 멀티프로세싱 캡처
│   │   ├── optimized_packet_capture_simple.py # 간소화된 최적화 캡처 (현재 사용)
│   │   ├── reinforcement_learning.py # 강화학습 환경 및 DQN 에이전트
│   │   ├── ml_models.py           # 랜덤 포레스트 머신러닝 모델
│   │   ├── defense_mechanism.py   # 실시간 방어 메커니즘 (54KB)
│   │   ├── threat_alert_system.py # 위협 알림 시스템
│   │   ├── suricata_manager.py    # 수리카타 엔진 통합 관리
│   │   ├── experience_replay_buffer.py # 우선순위 경험 재생 버퍼
│   │   ├── model_optimization.py  # 모델 최적화 도구
│   │   ├── memory_optimization.py # 메모리 최적화 (객체 풀링)
│   │   ├── lazy_loading.py        # 지연 로딩 시스템
│   │   ├── port_scan_detector.py  # 포트 스캔 탐지기 (26KB)
│   │   └── utils.py               # 유틸리티 함수
│   │
│   ├── scripts/
│   │   └── components/            # 스크립트 컴포넌트 (7개 파일)
│   │       ├── TrafficGeneratorApp.py # 트래픽 생성기 (공격 시뮬레이션, 57KB)
│   │       ├── packet_generator_base.py # 패킷 생성 기본 클래스
│   │       ├── network_interface_manager.py # 네트워크 인터페이스 관리
│   │       ├── network_diagnosis.py # 네트워크 진단 도구
│   │       ├── network_diagnosis_results.json # 진단 결과 저장
│   │       ├── packet_collector.py # 패킷 수집 GUI
│   │       └── DataPreprocessingApp.py # 데이터 전처리 앱
│   │
│   └── logs/                      # IDS 로그 파일 저장소
│       ├── ids_debug.log          # 디버그 로그
│       └── defense_actions.log    # 방어 조치 로그
│
├── docs/                          # 문서 및 설계서 (2개 문서)
│   ├── implementation_strategy.md
│   └── 네트워크_시뮬레이션_설계서.md
│
└── logs/                          # 전역 로그 디렉토리
    ├── ids_debug.log             # 시스템 디버그 로그
    └── defense_actions.log       # 방어 조치 이력
```

### 주요 실행 파일

| 파일명 | 역할 | 모드 | 설명 |
|--------|------|------|------|
| **IDSAgent_RL.py** | 메인 IDS 시스템 | CLI | 실시간 침입 탐지 및 방어 (실제 운영용) |
| **IDS_Training_Data_Generator.py** | 데이터 준비 통합 GUI | GUI | 패킷 캡처, 트래픽 생성, 데이터 전처리 통합 인터페이스 (개발/테스트용) |

### 패킷 캡처 시스템 구조

**우선순위 기반 패킷 캡처:**
1. `optimized_packet_capture_simple.py` (현재 사용)
2. `optimized_packet_capture.py` (백업)
3. `packet_capture.py` (기본)

### 네트워크 진단 시스템

**새로 추가된 진단 도구들:**
- `network_interface_manager.py` - 네트워크 인터페이스 자동 탐지 및 관리
- `network_diagnosis.py` - 패킷 전송 문제 종합 진단
- `packet_generator_base.py` - 공격 패킷 생성 기본 클래스

### 메모리 최적화 시스템

**최적화 모듈:**
- `memory_optimization.py` - 객체 풀링 (패킷/DataFrame 재사용)
- `lazy_loading.py` - 지연 로딩 (125-195MB 메모리 절약)
- `experience_replay_buffer.py` - 우선순위 기반 학습 버퍼

### IDS 에이전트 핵심 구조

**IDSAgent_RL.py**는 모든 모듈을 통합한 메인 실행 파일로 다음과 같은 구조를 가집니다:

- **멀티스레드 아키텍처**: 5개의 백그라운드 스레드 동시 실행
  - 실시간 대시보드 표시 스레드
  - 패킷 처리 및 저장 스레드  
  - 시스템 모니터링 스레드
  - 머신러닝 모델 학습 스레드
  - 사용자 입력 처리 스레드

- **운영 모드**: Lightweight(경량) / Performance(고성능) 동적 전환
- **실시간 위협 분석**: 방어 모듈 기반 패킷 위협 수준 분석
- **자동 대응 시스템**: IP 차단, 모니터링, 알림 등 단계별 대응

## 사용된 모듈

### 데이터 분석 모듈
- **pandas**: 데이터 조작 및 분석을 위한 Python 라이브러리로, DataFrame과 Series 자료구조 제공. 패킷 데이터 로드, CSV 파일 처리, 결측치 처리, 범주형 데이터 인코딩 및 데이터 전처리 파이프라인 구축에 활용 (메모리 최적화로 인해 현재는 제한적 사용)
- **numpy**: 다차원 배열 객체와 수학 함수를 제공하는 과학적 컴퓨팅 라이브러리. 패킷 데이터 벡터화, 수치형 특성 정규화, 머신러닝 모델 입력 데이터 변환 및 행렬 연산에 사용

### 머신러닝 관련 모듈
- **scikit-learn**: 다양한 머신러닝 알고리즘과 평가 도구를 제공하는 Python 라이브러리. 네트워크 패킷 분류를 위한 랜덤 포레스트 모델 구현, 특성 선택, 성능 평가 및 교차 검증에 활용
- **joblib**: Python 객체의 직렬화와 병렬 처리를 지원하는 라이브러리. 훈련된 랜덤 포레스트 모델을 파일로 저장하고 필요할 때 로드하는 데 사용

### 강화학습 관련 모듈
- **PyTorch**: 유연한 딥러닝 프레임워크로 동적 계산 그래프 구축 지원. 이 프로젝트에서는 DQN(Deep Q-Network) 구현, 신경망 모델 설계 및 학습에 활용
- **Gym**: 강화학습 환경 구축. 강화학습 알고리즘 개발 및 비교를 위한 표준화된 환경 인터페이스 제공. 네트워크 환경 모델링, 상태-행동-보상 체계 구현 및 에이전트 훈련에 사용

### 네트워크 및 패킷 캡처 관련 모듈
- **Scapy**: 패킷 캡처, 분석, 생성 및 전송 기능. 패킷 조작 및 네트워크 도구를 제공하는 강력한 Python 라이브러리. 네트워크 패킷 캡처, 실시간 모니터링, 패킷 분석 및 커스텀 트래픽 생성에 활용



### 기타 필수 모듈
- **colorama**: 터미널 컬러 출력 지원 (크로스 플랫폼)
- **tqdm**: 진행률 표시 바
- **psutil**: 시스템 리소스 모니터링
- **matplotlib/seaborn**: 데이터 시각화

## AI 에이전트 작동 방식

```mermaid
flowchart TD
    A("데이터 수집") --> B("데이터 전처리")
    B --> C("모델 학습")
    C --> D("강화학습 통합")
    D --> E("실시간 탐지")
    E --> F("모델 업데이트")
    F -.-> A
    
    classDef main fill:#f96,color:#fff,stroke:#333,stroke-width:1px;
    class A,B,C,D,E,F main;
```

### 통합 에이전트 작동 흐름

**IDSAgent_RL.py**는 다음과 같은 순서로 작동합니다:

1. **초기화 단계**
   - 운영 모드 선택 (Lightweight/Performance)
   - 관리자 권한 확인 (Windows)
   - 패킷 캡처 코어 초기화
   - 방어 메커니즘 초기화

2. **패킷 수집 단계**
   - 네트워크 인터페이스 자동 탐지
   - 실시간 패킷 캡처 시작
   - 큐 기반 패킷 버퍼링

3. **멀티스레드 처리 시작**
   - 실시간 대시보드 스레드
   - 패킷 처리 및 저장 스레드
   - 모니터링 스레드
   - 머신러닝 학습 스레드
   - 사용자 입력 처리 스레드

4. **실시간 분석 및 대응**
   - 패킷 전처리 및 특성 추출
   - 랜덤 포레스트 1차 분류
   - DQN 에이전트 행동 결정
   - 방어 메커니즘 자동 실행

## 하이브리드 접근 방식의 특징

본 시스템은 랜덤 포레스트와 강화학습을 결합한 하이브리드 접근 방식을 사용합니다:

```mermaid
flowchart TD
    A("패킷 데이터") --> B("랜덤 포레스트 1차 분류")
    B --> C("분류 결과를 특성으로 추가")
    C --> D("강화학습 환경 상태로 활용")
    D --> E("DQN 에이전트")
    E --> F("최적의 대응 조치 선택")
    
    classDef primary fill:#f96,color:#fff,stroke:#333,stroke-width:2px;
    classDef secondary fill:#f2f2f2,color:#000,stroke:#333,stroke-width:1px;
    
    class B,E primary;
    class A,C,D,F secondary;
```

### 하이브리드 모델의 동작 원리

1. **랜덤 포레스트 1차 분류**: 패킷 데이터를 랜덤 포레스트로 1차적으로 분류하여 기본적인 악성/정상 구분
2. **특성 확장**: 랜덤 포레스트의 예측 확률값을 새로운 특성으로 추가하여 데이터 품질 향상
3. **강화학습 통합**: 확장된 특성을 강화학습 환경의 상태(state)로 활용
4. **동적 의사결정**: DQN 에이전트가 환경 상태를 기반으로 최적의 대응 조치 선택

### 시스템 장점

- **높은 정확도**: 랜덤 포레스트의 검증된 분류 성능과 강화학습의 적응성 결합
- **실시간 대응**: 패킷별 즉시 분석 및 대응 조치 실행
- **지속적 학습**: 새로운 위협 패턴에 대한 자동 적응 및 성능 향상
- **유연한 정책**: 환경 변화에 따른 방어 전략 동적 조정
- **확장성**: 모듈식 설계로 새로운 탐지 기법 쉽게 추가 가능

### 위협 분석 프로세스

IDSAgent_RL.py의 `analyze_threat_level` 함수는 다음과 같이 작동합니다:

1. **우선순위 1**: 방어 메커니즘 관리자의 ML 기반 분석
   - AutoDefenseActions의 analyze_packet 메서드 활용
   - 예측 결과와 신뢰도를 기반으로 위협 수준 결정
   - 신뢰도 0.9 이상 → 'high', 0.8 이상 → 'medium', 0.7 이상 → 'low'

2. **백업 분석**: 휴리스틱 기반 분석 (방어 모듈 오류 시)
   - 패킷 크기, 프로토콜, 소스/목적지 분석
   - 의심스러운 포트 및 플래그 패턴 확인
   - 점수 기반 위협 수준 산출

## 주요 시스템 구성 요소

### 핵심 모듈별 상세 기능

#### 1. 패킷 캡처 시스템 (packet_capture.py)
- **역할**: 네트워크 인터페이스에서 실시간 패킷 캡처
- **기술**: Scapy, Npcap/WinPcap 활용
- **주요 기능**:
  - 실시간 패킷 수집 및 큐 관리
  - 기본 패킷 정보 추출 (IP, 포트, 프로토콜, 플래그)
  - 방어 모듈 콜백 연동
  - 네트워크 인터페이스 자동 탐지

#### 2. 최적화된 패킷 캡처 (optimized_packet_capture.py)
- **역할**: 멀티프로세싱 기반 고성능 패킷 처리
- **특징**: 워커 프로세스를 통한 병렬 처리, 메모리 효율성 향상
- **우선순위**: IDSAgent_RL.py에서 최우선으로 사용

#### 3. 머신러닝 시스템 (ml_models.py)
- **모델**: RandomForest Classifier
- **역할**: 기본적인 악성/정상 트래픽 분류
- **특성**: 정적 패턴 학습 및 예측 확률 제공
- **통합**: MLTrainingWindow GUI를 통한 학습 관리

#### 4. 강화학습 시스템 (reinforcement_learning.py)
- **모델**: Deep Q-Network (DQN)
- **역할**: 동적 환경 적응 및 행동 결정
- **액션**: 허용(0), 차단(1), 모니터링(2)
- **상태**: 패킷 특성 + RF 예측 확률
- **개선**: Experience Replay Buffer 및 Prioritized Replay 지원

#### 5. 방어 메커니즘 (defense_mechanism.py)
- **역할**: 실시간 위협 대응 및 자동 차단
- **기능**: IP 차단, 트래픽 제어, 자동 방어
- **통합**: 수리카타, 포트스캔 탐지, 위협 알림 시스템
- **모드 지원**: Lightweight/Performance 모드별 최적화

#### 6. 위협 알림 시스템 (threat_alert_system.py)
- **역할**: 위협 감지 시 관리자 알림
- **기능**: 팝업 알림, 대시보드, 위험도별 알림 전략
- **통합**: 실시간 대시보드와 연동

### Experience Replay Buffer (experience_replay_buffer.py)

강화학습의 안정성과 효율성을 위한 경험 재생 시스템:

- **Prioritized Experience Replay**: 중요한 경험을 우선적으로 학습
- **Adaptive Sampling**: 악성/정상 트래픽 비율 자동 조정
- **Memory Management**: 메모리 효율적인 버퍼 관리
- **Statistics Tracking**: 학습 진행상황 및 성능 지표 추적

## 강화학습 관련 클래스 및 메서드

### NetworkEnv 클래스

NetworkEnv 클래스는 강화학습을 위한 네트워크 환경을 구현합니다.

**주요 특징**:
- **액션 공간**: 허용(0), 차단(1), 모니터링(2)
- **관찰 공간**: 모드별 특성 수 (경량모드: 7개, 고성능모드: 12개)
- **랜덤 포레스트 통합**: 모델의 예측 확률을 상태에 통합
- **보상 시스템**: 패킷의 안전성을 판단하여 보상 계산
- **모드 지원**: 운영 모드에 따른 특성 수 자동 조정

### DQNAgent 클래스

DQNAgent 클래스는 심층 Q 네트워크를 구현하여 패킷에 대한 최적의 대응 정책을 학습합니다.

**주요 특징**:
- **신경망 모델**: PyTorch 기반 Deep Q-Network
- **Experience Replay**: 경험 재생을 통한 학습 안정화
- **Target Network**: 타겟 네트워크를 통한 학습 안정성 향상
- **Epsilon-Greedy**: 탐험과 활용의 균형
- **Prioritized Replay**: 중요한 경험 우선 학습
- **Mode Switching**: 런타임 모드 전환 지원

**학습 프로세스**:
1. 환경에서 상태 관찰
2. 현재 정책에 따라 액션 선택 (탐험 또는 활용)
3. 액션 실행 및 보상 수집
4. 새로운 상태로 전이
5. 경험 메모리에 저장
6. 경험 리플레이를 통한 모델 업데이트

## 모듈 간 통합 및 데이터 흐름

### 시스템 데이터 플로우

본 시스템의 데이터 처리 흐름은 다음과 같습니다:

```mermaid
graph TB
    %% 입력
    Network[네트워크<br/>패킷 입력]
    User[사용자<br/>명령어]
    
    %% 메인 프로그램
    MainAgent[IDSAgent_RL.py<br/>메인 컨트롤러]
    
    %% 핵심 처리 모듈
    PacketCapture[패킷 캡처]
    Defense[방어 시스템]
    ML[머신러닝<br/>RF + DQN]
    
    %% 데이터 저장
    Queue[실시간 큐]
    DataFiles[저장된 데이터]
    
    %% 출력
    Dashboard[실시간 대시보드]
    Alerts[위협 알림]
    Logs[로그 파일]
    
    %% 주요 데이터 흐름
    Network -->|실시간 패킷| PacketCapture
    PacketCapture -->|패킷 데이터| Queue
    Queue -->|분석 요청| MainAgent
    
    %% 메인 에이전트의 역할
    MainAgent -->|패킷 분석| Defense
    MainAgent -->|학습 데이터| ML
    MainAgent -->|통계 생성| Dashboard
    
    %% 분석 결과 흐름
    Defense -->|위협 수준| MainAgent
    ML -->|예측 결과| MainAgent
    MainAgent -->|위협 탐지| Alerts
    
    %% 데이터 저장 및 학습
    MainAgent -->|패킷 저장| DataFiles
    DataFiles -->|재학습| ML
    ML -->|모델 업데이트| Defense
    
    %% 사용자 상호작용
    User -->|명령어| MainAgent
    MainAgent -->|상태 정보| Dashboard
    Dashboard -->|화면 출력| User
    
    %% 로그 시스템
    MainAgent -->|시스템 로그| Logs
    Defense -->|방어 로그| Logs
    
    %% 백그라운드 처리
    subgraph "백그라운드 처리"
        BG[실시간 모니터링<br/>패킷 저장<br/>모델 학습<br/>사용자 입력]
    end
    
    MainAgent -.->|멀티스레드| BG
    BG -.->|결과 반영| MainAgent
    
    %% 스타일 정의
    classDef main fill:#ff6b6b,stroke:#d63031,stroke-width:3px,color:#fff
    classDef process fill:#74b9ff,stroke:#0984e3,stroke-width:2px,color:#fff
    classDef data fill:#a29bfe,stroke:#6c5ce7,stroke-width:2px,color:#fff
    classDef output fill:#55a3ff,stroke:#2d3436,stroke-width:2px,color:#fff
    classDef input fill:#fdcb6e,stroke:#e17055,stroke-width:2px,color:#000
    classDef background fill:#00cec9,stroke:#00b894,stroke-width:2px,color:#fff
    
    %% 클래스 적용
    class MainAgent main
    class PacketCapture,Defense,ML process
    class Queue,DataFiles data
    class Dashboard,Alerts,Logs output
    class Network,User input
    class BG background
```

## 전체 시스템 아키텍처

### 핵심 처리 흐름

IDSAgent_RL.py는 다음과 같은 5개의 백그라운드 스레드를 통해 동시 처리를 수행합니다:

1. **실시간 대시보드 스레드** (`display_realtime_stats`)
   - 3초마다 화면 업데이트
   - 패킷 통계, 위협 분석, 방어 상태 표시
   - 프로토콜별 분석 결과 실시간 출력

2. **패킷 처리 및 저장 스레드** (`process_and_save_packets`)
   - 200개 청크 단위로 패킷 처리
   - 전처리 및 랜덤 포레스트 예측 수행
   - CSV 파일로 자동 저장

3. **시스템 모니터링 스레드** (`monitor_capture_status`)
   - 10분마다 상세 로그 기록
   - 방어 메커니즘 상태 모니터링
   - 차단된 IP 관리

4. **머신러닝 학습 스레드** (`monitor_and_train`)
   - 데이터 파일 변경 감지
   - 1시간 간격으로 모델 재학습
   - Experience Replay Buffer 관리

5. **사용자 입력 처리 스레드** (`handle_user_input`)
   - 실시간 명령어 처리
   - 모드 전환, 상태 확인 등
   - 백그라운드에서 조용히 대기

### 통합 아키텍처 특징

- **모듈식 설계**: 각 모듈이 독립적으로 동작하며 인터페이스를 통해 연동
- **멀티스레드 안전성**: Queue 기반 스레드 간 통신
- **실시간 처리**: 패킷 단위 즉시 분석 및 대응
- **메모리 효율성**: 청크 기반 처리 및 명시적 메모리 관리
- **확장성**: 새로운 모듈 추가 및 기능 확장 용이

## 메모리 최적화 전략

효율적인 패킷 처리를 위한 메모리 최적화 기법:

###  **지연 로딩 (Lazy Loading)** 
- **강화학습 모듈 지연 로딩**: 100-150MB 절약
  - PyTorch, 강화학습 환경/에이전트는 실제 사용 시에만 로딩
  - `lazy_importer.get_module('reinforcement_learning')` 방식 적용
- **머신러닝 모델 지연 로딩**: 15-25MB 절약
  - scikit-learn 모델들, 훈련 함수들 지연 로딩
  - `lazy_model_loader.register_model()` 방식으로 모델 파일 관리
- **시각화 모듈 지연 로딩**: 10-20MB 절약
  - matplotlib, seaborn은 백엔드 설정 후 지연 로딩
  - GUI 컴포넌트들도 실제 표시 시에만 생성
- **총 메모리 절약량**: **125-195MB**

###  **객체 풀링 (Object Pooling)** 
- **패킷 객체 풀링**: 패킷 딕셔너리 재사용으로 GC 부하 80% 감소
- **통계 딕셔너리 풀링**: 프로토콜 통계 객체 재사용
- **DataFrame 풀링**: NumPy 배열 재사용으로 DataFrame 생성 비용 90% 절약
- **배치 프로세서 풀링**: 대용량 데이터 처리 객체 재사용
- **재사용률**: 평균 85%+ 달성

###  **청크 기반 처리**
- **최적화된 청크 크기**: 200개 → **50개** 단위로 처리
- **메모리 사용량**: ~50KB로 추가 75% 감소
- **처리 빈도**: 2분 → **2분** 간격으로 더 빈번한 처리
- **버퍼 크기 제한**: 1,000개 → **500개**로 최적화

###  **데이터 타입 최적화**
- int64 → int32 변환 (메모리 50% 절약)
- TTL 값은 uint8 사용 (255까지만 필요)
- 필요한 6개 컬럼만 선택적 로드

###  **강화된 메모리 관리** 
- **적극적 가비지 컬렉션**: 1분마다 + 5분마다 수행
- **명시적 메모리 해제**: `del` 키워드 적극 활용
- **scapy 출력 제어**: `scapy.config.conf.verb = 0`으로 메모리 절약
- **matplotlib 백엔드**: 'Agg' 모드로 GUI 메모리 절약

###  **큐 크기 제한**
- 패킷 큐 최대 10,000개로 제한 (~2MB)
- FIFO 방식으로 오래된 패킷 자동 제거
- 메모리 사용량 실시간 모니터링

###  **우선순위 Experience Replay Buffer** 
- **Prioritized Experience Replay**: 중요한 경험 우선 학습
- numpy 배열 기반 고정 크기 버퍼 (~600KB)
- 악성 패킷 경험 30% 최소 보존률 적용
- 우선순위 기반 샘플링으로 학습 효율성 향상

###  **메모리 사용량 실측 결과**
| 모드 | 기존 메모리 | 최적화 후 | 절약량 | 절약률 |
|------|------------|----------|---------|--------|
| **경량 모드** | 270MB | **~100MB** | 170MB | **63%** |
| **고성능 모드** | 370MB | **~150MB** | 220MB | **59%** |

###  **임베디드 환경 적합성**
- **메모리 요구사항**: 100MB 이하로 임베디드 시스템 실행 가능
- **싱글보드 컴퓨터**: 라즈베리파이 등에서 원활한 동작
- **산업용 제어 패널**: 512MB-4GB 환경에서 안정적 운영

## 운영 모드

시스템은 두 가지 운영 모드를 지원하며, 실행 중 동적 전환이 가능합니다:

### 1. 경량 모드 (Lightweight)
- **특성 수**: 7개 기본 특성 사용
- **리소스**: 낮은 CPU/메모리 사용 (~160-270MB)
- **정확도**: 기본 수준의 탐지 성능
- **대상**: 모든 환경에서 실행 가능
- **탐지 방식**: 내장 휴리스틱 + 랜덤 포레스트

### 2. 고성능 모드 (Performance)
- **특성 수**: 12개 확장 특성 사용
- **리소스**: 보통 CPU/메모리 사용 (~180-370MB)
- **정확도**: 향상된 탐지 정확도
- **대상**: 일반적인 데스크톱/서버 환경
- **탐지 방식**: 수리카타 통합 + 규칙 기반 심층 분석

### 모드 전환 방법

**실행 중 전환**:
```bash
# 명령어 프롬프트에서
명령어 > m
```

**명령줄에서 지정**:
```bash
python IDSAgent_RL.py --mode performance
```

### 위험도별 대응 전략(임의임계값)

| 위험도 | 임계값 | 대응 조치 | 알림 방식 |
|--------|--------|-----------|-----------|
| **치명적** | 0.95+ | 즉시 IP 차단, 관리자 이메일 발송, 긴급 로그 기록 | 즉시 팝업 알림 |
| **높음** | 0.85+ | 즉시 차단 + 알림, 상세 로그 기록 | 즉시 팝업 알림 |
| **중간** | 0.70+ | 5분간 5회 누적 시에만 알림, 임시 차단 (자동 해제) | 조건부 알림 |
| **낮음** | 0.50+ | 모니터링만 수행, 기본 로그 기록 | 알림 없음 |

## 향후 개발 계획


- **성능 최적화**: 핵심 병목 구간(패킷 캡처/분석) C언어 변경 고려 (Cython 활용),  메모리 추가 최적화
- **헤드리스 모드 구현**: 시스템 서비스로 백그라운드 동작 구현 
- **CLI 개선**: 실시간 대시보드 및 모니터링 인터페이스 고도화
- **알림 시스템 확장**: CLI, 웹 대시보드 등의 알림 확장
- **다중 환경 적응**: 다양한 네트워크 환경에서의 적응성 향상
- **시각화 시스템**: 학습 및 차단 트래픽 데이터 실시간 시각화
- **AI 모델 개선 및 확장**:
  - Double DQN으로 개선 고려 
  - 그래프 신경망(GNN)을 통한 네트워크 토폴로지 분석 고려
- **강화학습 고도화**: PPO(Proximal Policy Optimization) 알고리즘 구현 고려
- **자동화 확장**:  적응형 임계값 조정 메커니즘
- **호환성 및 배포**: Docker 컨테이너화, pip설치가능 패키지 생성 ,linux 최적화
- **코드 리펙토링** : 중복 제거 및 각 모듈 개선
- **모델 학습 및 테스트**
- **위험도 임계값 수정**
- **로그 저장 경로 설정**


