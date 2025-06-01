# 반응형 취약점 차단 AI 에이전트

<div align="center">
  <img src="https://img.shields.io/badge/Language-Python-blue" alt="Language">
  <img src="https://img.shields.io/badge/Language-C-yellow" alt="Language">
  <img src="https://img.shields.io/badge/Framework-PyTorch-orange" alt="Framework">
  <img src="https://img.shields.io/badge/AI-Reinforcement%20Learning-brightgreen" alt="AI">
</div>

## 0. 📑목차

1. [프로젝트 개요](#1-프로젝트-개요)
2. [팀원 정보](#2-팀원-정보)
3. [프로젝트 구조](#️3-프로젝트-구조)
4. [사용된 모듈](#️4-사용된-모듈)
5. [AI 에이전트 작동 방식](#-ai-에이전트-작동-방식)
6. [하이브리드 접근 방식의 특징](#-하이브리드-접근-방식의-특징)
7. [주요 시스템 구성 요소](#-주요-시스템-구성-요소)
8. [강화학습 관련 클래스 및 메서드](#-강화학습-관련-클래스-및-메서드)
9. [모듈 간 통합 및 데이터 흐름](#-모듈-간-통합-및-데이터-흐름)
10. [전체 시스템 아키텍처](#️-전체-시스템-아키텍처)
11. [프로그램 작동법](#-프로그램-작동법)
12. [메모리 최적화 전략](#-메모리-최적화-전략)
13. [운영 모드](#-운영-모드)
14. [향후 개발 계획](#-향후-개발-계획)

## 1. 📌프로젝트 개요



실시간으로 네트워크 보안 취약점을 탐지하고 자동으로 대응하는 AI 기반 침입 탐지 시스템입니다.   
랜덤 포레스트와 강화학습의 장점을 결합한 하이브리드 접근 방식을 통해 기존 방식보다 높은 정확도와 적응성을 제공 합니다..

## 2. 👥팀원 정보

- **안상수[팀장]**: 시스템 설계, 메인프로그래밍
- **신명재[팀원]**: 데이터 학습, 문서작업, 피드백 및 시각화 웹앱 제작
- **민인영[팀원]**: 데이터 학습, 이미지 시각화, 피드백 및 시각화 웹앱 제작
- **최준형[팀원]**: 데이터 학습, 피드백 및 시각화 웹앱 제작

## 3. 🏗️프로젝트 구조

```
📁 Intrusion_DetectionSystem/
│
├── 📄 IDSAgent_RL.py                    # 메인 에이전트 (시스템 핵심)
│
├── 📁 scripts/                          # 실행 스크립트
│   ├── 📄 data_preparation.py           # 데이터 준비 인터페이스
│   │
│   └── 📁 components/                   # UI 컴포넌트
│       ├── 📄 packet_collector.py       # 패킷 수집 모듈
│       ├── 📄 TrafficGeneratorApp.py    # 트래픽 생성기
│       └── 📄 DataPreprocessingApp.py   # 데이터 전처리 앱
│
└── 📁 modules/                          # 핵심 기능 모듈
    ├── 📄 reinforcement_learning.py     # 강화학습 구현
    ├── 📄 ml_models.py                  # 머신러닝 모델
    ├── 📄 packet_capture.py             # 패킷 캡처 기능
    ├── 📄 defense_mechanism.py          # 방어 메커니즘 모듈
    ├── 📄 suricata_manager.py           # 수리카타 통합 관리 모듈
    └── 📄 utils.py                      # 유틸리티 함수
```

### IDS 구현 구조
```
📁 IDS/
├── IDSAgent_RL.py          # 메인 에이전트 파일
├── 📁 modules/
│   ├── defense_mechanism.py # 방어 메커니즘 모듈
│   ├── suricata_manager.py  # 수리카타 통합 관리 모듈
│   ├── utils.py             # 유틸리티 함수
│   ├── packet_capture.py    # 패킷 캡처 모듈 
│   ├── reinforcement_learning.py # 강화학습 모듈
│   └── ml_models.py         # 머신러닝 모델 모듈
├── 📁 logs/                    # 로그 디렉토리
├── 📁 data_set/                # 학습 데이터 세트
├── 📁 config/                  # 설정 파일
└── 📁 rules/                   # 수리카타 규칙 파일
```

## 4. 🛠️사용된 모듈

### 데이터 분석 모듈
- **pandas(메모리 사용 최적화로 인한 미사용 예정)**
    - 데이터 조작 및 분석을 위한 Python 라이브러리로, DataFrame과 Series 자료구조 제공
    - 패킷 데이터 로드, CSV 파일 처리, 결측치 처리, 범주형 데이터 인코딩 및 데이터 전처리 파이프라인 구축에 활용
- **numpy**
    - 다차원 배열 객체와 수학 함수를 제공하는 과학적 컴퓨팅 라이브러리
    - 패킷 데이터 벡터화, 수치형 특성 정규화, 머신러닝 모델 입력 데이터 변환 및 행렬 연산을 사용

### 머신러닝 관련 모듈
- **scikit-learn**
    - 다양한 머신러닝 알고리즘과 평가 도구를 제공하는 Python 라이브러리
    - 네트워크 패킷 분류를 위한 랜덤 포레스트 모델 구현, 특성 선택, 성능 평가 및 교차 검증에 활용
- **joblib**
    - Python 객체의 직렬화와 병렬 처리를 지원하는 라이브러리
    - 훈련된 랜덤 포레스트 모델을 파일로 저장하고 필요할 때 로드하는 데 사용

### 강화학습 관련 모듈
- **PyTorch**
    - 유연한 딥러닝 프레임워크로 동적 계산 그래프 구축 지원
    - 이 프로젝트에서는 DQN(Deep Q-Network) 구현, 신경망 모델 설계 및 학습에 활용
- **Gym**: 강화학습 환경 구축
    - 강화학습 알고리즘 개발 및 비교를 위한 표준화된 환경 인터페이스 제공
    - 네트워크 환경 모델링, 상태-행동-보상 체계 구현 및 에이전트 훈련에 사용

### 네트워크 및 패킷 캡처 관련 모듈
- **Scapy**: 패킷 캡처, 분석, 생성 및 전송 기능
    - 패킷 조작 및 네트워크 도구를 제공하는 강력한 Python 라이브러리
    - 네트워크 패킷 캡처, 실시간 모니터링, 패킷 분석 및 커스텀 트래픽 생성에 활용

### GUI 관련 모듈
- **PyQt6**: GUI 구현을 위한 Qt 프레임워크의 Python 바인딩
    - Qt 프레임워크의 Python 바인딩으로 크로스 플랫폼 GUI 개발 지원
    - 데이터 시각화 인터페이스, 전처리 도구 UI 및 사용자 대시보드 구현에 사용

## 🔄 AI 에이전트 작동 방식

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

## 🌟 하이브리드 접근 방식의 특징

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

1. **랜덤 포레스트 1차 분류**: 패킷 데이터를 랜덤 포레스트로 1차적으로 분류
2. **랜덤 포레스트 예측 결과 활용**: 분류 결과를 특성(feature)으로 추가
3. **강화학습 환경 통합**: 랜덤 포레스트 예측 결과를 강화학습의 상태(state)로 활용
4. **실시간 대응 의사결정**: DQN 에이전트가 최적의 대응 조치 선택

**장점:**
- 랜덤 포레스트의 높은 분류 정확도 활용
- 강화학습을 통한 동적 환경 적응
- 실시간 의사결정 및 자동화된 대응
- 지속적인 학습을 통한 성능 향상

### 시스템 아키텍처

이 시스템은 랜덤 포레스트 알고리즘과 강화학습(RL)을 결합한 하이브리드 침입 탐지 시스템입니다. 주요 구성 요소:

1. **패킷 캡처 모듈**: 네트워크 인터페이스에서 실시간 패킷 캡처
2. **랜덤 포레스트 모델**: 패킷 분석 및 침입 탐지 수행
3. **강화학습 에이전트**: 탐지된 위협에 대한 최적 대응 결정
4. **방어 메커니즘**: 위협 수준에 따른 자동 대응 조치
5. **수리카타 통합**: 고성능 모드에서 외부 IDS 엔진 활용

## 💻 주요 시스템 구성 요소

### IDSAgent_RL 통합 에이전트 (IDSAgent_RL.py)

`IDSAgent_RL.py`는 이 프로젝트의 핵심 파일로, 랜덤 포레스트와 강화학습을 통합하여 네트워크 침입 탐지 및 자동 대응 기능을 제공합니다.

**주요 기능:**
- **통합 인터페이스**: 모든 침입 탐지 및 대응 기능을 단일 인터페이스에서 제공
- **강화학습 통합**: 랜덤 포레스트 예측 결과를 강화학습의 상태로 활용
- **실시간 모니터링**: 네트워크 패킷 실시간 캡처 및 분석
- **자동 대응**: 탐지된 위협에 대한 자동화된 대응 조치 수행

**실행 흐름:**
1. 프로그램 시작 및 환경 초기화
2. 네트워크 인터페이스 선택
3. 패킷 캡처 시작
4. 실시간 모니터링
5. 데이터 저장 및 처리
6. 모델 학습 및 적용
7. 위협 탐지 및 대응

### 자동 방어 기능

시스템은 위협 수준에 따라 다음과 같은 자동 방어 조치를 취합니다:

1. **높은 위협 (신뢰도 0.9 이상)**
   - IP 주소 영구 차단
   - 관리자에게 긴급 알림 발송
   - 추가 보안 조치 실행

2. **중간 위협 (신뢰도 0.8 이상)**
   - IP 주소 임시 차단 (30분)
   - 관리자에게 표준 알림 발송

3. **낮은 위협 (신뢰도 0.7 이상)**
   - 해당 트래픽 모니터링 강화
   - 기록 및 로깅 강화

### 데이터 준비 및 처리 모듈 (data_preparation.py)

`data_preparation.py`는 데이터 수집, 생성 및 전처리에 필요한 GUI 인터페이스를 제공합니다.

**MainApplication 클래스:**
- 중앙 위젯 및 스택 위젯을 통한 화면 전환 기능
- 메인 화면, 패킷 캡처, 트래픽 생성, 데이터 전처리 등 기능별 인터페이스

### DataPreprocessingApp 클래스

DataPreprocessingApp은 네트워크 패킷 데이터의 전처리와 분석을 위한 사용자 인터페이스를 제공합니다.

**주요 기능:**
- CSV 또는 PCAP 형식의 데이터 파일 로드
- 테이블 형태로 데이터 시각화
- 자동 전처리 기능 (결측치 처리, 정규화, 인코딩)
- 전처리된 데이터의 CSV 형식 저장

**전처리 파이프라인:**
1. 데이터 로드: CSV 또는 PCAP 파일에서 데이터 로드
2. 기본 정보 추출: 소스 IP, 목적지 IP, 프로토콜, 패킷 길이 등 추출
3. 결측치 처리: 결측값을 0으로 대체
4. 데이터 정규화: 수치형 데이터를 표준화
5. 범주형 데이터 인코딩: 프로토콜과 같은 범주형 데이터를 원-핫 인코딩으로 변환
6. 파일 저장: 전처리된 데이터를 CSV 파일로 저장

### TrafficGeneratorApp 클래스

TrafficGeneratorApp은 다양한 유형의 네트워크 트래픽을 생성하고 전송하는 기능을 제공합니다.

**주요 기능:**
- 대상 IP 지정 및 패킷 크기 선택
- 다양한 공격 유형 선택 (SYN 플러드, UDP 플러드, ICMP 플러드 등)
- 생성할 패킷 수 설정
- 트래픽 생성 및 전송

## 🧠 강화학습 관련 클래스 및 메서드

### NetworkEnv 클래스

NetworkEnv 클래스는 강화학습을 위한 네트워크 환경을 구현합니다.

**주요 특징:**
- **액션 공간**: 허용(0), 차단(1), 모니터링(2)
- **관찰 공간**: 7개의 특성 [src_ip, dst_ip, protocol, length, ttl, flags, rf_prob]
- **랜덤 포레스트 통합**: 모델의 예측 확률을 상태에 통합
- **보상 시스템**: 패킷의 안전성을 판단하여 보상 계산

### DQNAgent 클래스

DQNAgent 클래스는 심층 Q 네트워크를 구현하여 패킷에 대한 최적의 대응 정책을 학습합니다.

**주요 특징:**
- 신경망 모델 구축
- 경험 리플레이를 사용한 학습 안정화
- 타겟 네트워크를 통한 학습 안정성 향상
- 엡실론-그리디 탐험 전략 적용

**학습 프로세스:**
1. 환경에서 상태 관찰
2. 현재 정책에 따라 액션 선택 (탐험 또는 활용)
3. 액션 실행 및 보상 수집
4. 새로운 상태로 전이
5. 경험 메모리에 저장
6. 경험 리플레이를 통한 모델 업데이트

## 🔄 모듈 간 통합 및 데이터 흐름(수정 예정)

본 시스템의 데이터 흐름 및 모듈 간 통합은 다음과 같은 과정으로 이루어집니다:

```mermaid
flowchart LR
    subgraph 데이터수집["1. 데이터 수집 단계"]
        packet["packet_collector.py"]
        traffic["TrafficGeneratorApp.py"]
        packet --> traffic
    end

    subgraph 전처리["2. 데이터 전처리 단계"]
        preprocess["DataPreprocessingApp.py"]
        feature["특성 추출 및 가공"]
        preprocess --> feature
    end

    subgraph 모델학습["3. 모델 학습 단계"]
        ml["ml_models.py"]
        evaluation["성능 평가 및 시각화"]
        ml --> evaluation
    end

    subgraph 강화학습["4. 강화학습 통합 단계"]
        env["NetworkEnv"]
        dqn["DQNAgent"]
        env --> dqn
    end

    subgraph 실시간적용["5. 실시간 적용 단계"]
        agent["IDSAgent_RL.py"]
        response["위협 탐지 및 자동 대응"]
        agent --> response
    end

    데이터수집 --> 전처리
    전처리 --> 모델학습
    모델학습 --> 강화학습
    강화학습 --> 실시간적용
    
    classDef nodeText fill:#f2f2f2,stroke:#333,stroke-width:1px,color:black;
    class packet,traffic,preprocess,feature,ml,evaluation,env,dqn,agent,response nodeText;
    
    classDef subgraphText fill:transparent,color:black;
    class 데이터수집,전처리,모델학습,강화학습,실시간적용 subgraphText;
```

1. **데이터 수집 단계**:
   - `packet_collector.py`를 통해 네트워크 패킷 캡처
   - `TrafficGeneratorApp.py`를 통한 인공 트래픽 생성

2. **데이터 전처리 단계**:
   - `DataPreprocessingApp.py`를 통해 데이터 정제 및 변환
   - 랜덤 포레스트 분류를 위한 특성 추출 및 가공

3. **모델 학습 단계**:
   - `ml_models.py`에서 랜덤 포레스트 모델 학습
   - 학습된 모델의 성능 평가 및 시각화

4. **강화학습 통합 단계**:
   - `reinforcement_learning.py`의 NetworkEnv 환경에서 랜덤 포레스트 예측 결과 활용
   - DQNAgent를 통한 행동 정책 학습

5. **실시간 적용 단계**:
   - `IDSAgent_RL.py`에서 학습된 모델을 실시간 패킷에 적용
   - 잠재적 위협 탐지 및 자동 대응

## 🏗️ 전체 시스템 아키텍처

이 프로젝트의 전체 아키텍처는 데이터 수집, 전처리, 학습 및 실시간 적용의 통합된 파이프라인을 형성합니다:

```mermaid
flowchart TD
    %% 메인 에이전트
    main["IDSAgent_RL.py<br/>메인 에이전트"]
    
    %% 첫 번째 레벨 - 핵심 기능
    mode["모드 선택<br/>(Lightweight/Performance)"]
    capture["패킷 캡처 시작"]
    defense_init["방어 메커니즘 활성화"]
    utils["utils.py<br/>유틸리티"]
    
    %% 두 번째 레벨 - 데이터 수집
    packet_capture["packet_capture.py<br/>PacketCaptureCore"]
    data_prep["data_preparation.py<br/>통합 데이터 준비 UI"]
    
    %% 세 번째 레벨 - GUI 컴포넌트
    packet_collector["packet_collector.py<br/>패킷 수집 GUI"]
    traffic_gen["TrafficGeneratorApp.py<br/>트래픽 생성기"]
    preprocess_app["DataPreprocessingApp.py<br/>데이터 전처리"]
    
    %% 네 번째 레벨 - 머신러닝
    ml_models["ml_models.py<br/>MLTrainingWindow"]
    rf_model["랜덤 포레스트<br/>모델 학습"]
    rf_predict["예측 확률<br/>Feature 추가"]
    
    %% 다섯 번째 레벨 - 강화학습
    rl_env["NetworkEnv<br/>환경 구성"]
    dqn_agent["DQNAgent<br/>심층 Q-네트워크"]
    rl_train["train_rl_agent<br/>에이전트 학습"]
    
    %% 여섯 번째 레벨 - 방어 메커니즘
    defense_mech["defense_mechanism.py<br/>DefenseManager"]
    suricata["suricata_manager.py<br/>Suricata 통합"]
    actions["자동 대응<br/>(차단/모니터링/허용)"]
    
    %% 일곱 번째 레벨 - 실시간 처리
    capture_thread["패킷 캡처 스레드"]
    process_thread["패킷 처리 스레드"]
    monitor_thread["모니터링 스레드"]
    train_thread["학습 스레드"]
    
    %% 메인 연결 (수직 구조)
    main --> mode
    main --> capture
    main --> defense_init
    main --> utils
    
    %% 데이터 수집 연결
    capture --> packet_capture
    capture --> data_prep
    
    %% GUI 컴포넌트 연결
    data_prep --> packet_collector
    data_prep --> traffic_gen
    data_prep --> preprocess_app
    packet_capture --> packet_collector
    
    %% 머신러닝 연결
    packet_collector --> ml_models
    preprocess_app --> ml_models
    ml_models --> rf_model
    rf_model --> rf_predict
    
    %% 강화학습 연결
    rf_predict --> rl_env
    rl_env --> dqn_agent
    dqn_agent --> rl_train
    
    %% 방어 메커니즘 연결
    mode --> defense_mech
    defense_init --> defense_mech
    rl_train --> defense_mech
    suricata --> defense_mech
    defense_mech --> actions
    
    %% 실시간 처리 연결
    packet_capture --> capture_thread
    capture_thread --> process_thread
    process_thread --> monitor_thread
    monitor_thread --> train_thread
    
    %% 데이터 플로우 (점선)
    process_thread -.-> ml_models
    rf_predict -.-> rl_env
    rl_train -.-> defense_mech
    
    %% 스타일 정의
    classDef mainNode fill:#ff6b6b,stroke:#333,stroke-width:3px,color:white,font-weight:bold;
    classDef coreNode fill:#4ecdc4,stroke:#333,stroke-width:2px,color:white;
    classDef dataNode fill:#95e1d3,stroke:#333,stroke-width:2px,color:#333;
    classDef mlNode fill:#ffd93d,stroke:#333,stroke-width:2px,color:#333;
    classDef rlNode fill:#6bcf7f,stroke:#333,stroke-width:2px,color:#333;
    classDef defenseNode fill:#ff8b94,stroke:#333,stroke-width:2px,color:white;
    classDef threadNode fill:#c44569,stroke:#333,stroke-width:2px,color:white;
    classDef utilNode fill:#aa96da,stroke:#333,stroke-width:2px,color:white;
    
    class main mainNode;
    class mode,capture,defense_init coreNode;
    class packet_capture,data_prep,packet_collector,traffic_gen,preprocess_app dataNode;
    class ml_models,rf_model,rf_predict mlNode;
    class rl_env,dqn_agent,rl_train rlNode;
    class defense_mech,suricata,actions defenseNode;
    class capture_thread,process_thread,monitor_thread,train_thread threadNode;
    class utils utilNode;
```

이러한 통합 아키텍처를 통해 데이터 흐름이 원활하게 이루어지며, 각 모듈의 기능이 유기적으로 연결됩니다. 특히 랜덤 포레스트와 강화학습의 통합은 이 시스템의 핵심 특징으로, 두 알고리즘의 장점을 결합하여 더 높은 탐지 성능과 적응성을 제공합니다.

## 📋 프로그램 작동법

### 설치 요구사항

- Python 3.7 이상
- Windows/Linux/MacOS 지원 (Windows에서는 관리자 권한 필요)
- Npcap (Windows) 또는 libpcap (Linux/Mac) 설치 필요
- 고성능 모드의 경우 Suricata 엔진 설치 필요

### 실행 방법(개발 중)

```bash
# 기본 실행 (메뉴에서 모드 선택)
python IDSAgent_RL.py

# 경량 모드로 직접 실행
python IDSAgent_RL.py --mode lightweight

# 고성능 모드로 직접 실행
python IDSAgent_RL.py --mode performance

# 최대 패킷 수 제한 (테스트용)
python IDSAgent_RL.py --max-packets 1000

# 디버그 모드 실행
python IDSAgent_RL.py --debug
```

### 데이터 준비 애플리케이션 (DataPreprocessingApp)

1. **데이터 파일 업로드**:
   - 'data_preparation.py'를 실행하여 메인 메뉴에 접근
   - '데이터 전처리' 버튼을 클릭하여 DataPreprocessingApp 실행
   - '데이터 파일 업로드' 버튼으로 CSV 또는 PCAP 파일 선택
   - 데이터는 자동으로 테이블에 로드되어 표시됨

2. **데이터 전처리**:
   - '데이터 전처리' 버튼 클릭
   - 결측치 처리, 정규화, 인코딩 등의 과정이 자동 수행됨
   - 전처리 결과 표시 및 저장 옵션 제공
   - 저장 위치 선택 후 CSV 형식으로 저장

### 침입 탐지 에이전트 (IDSAgent_RL)

1. **환경 확인**: Google Colab 환경과 로컬 환경에서 다르게 작동
2. **관리자 권한 실행**: Windows 환경에서는 관리자 권한으로 실행
3. **패킷 캡처**: 네트워크 인터페이스 선택 및 캡처 시작
4. **실시간 모니터링**: 패킷 캡처 상태와 정보를 실시간으로 모니터링
5. **데이터 저장 및 전처리**: 패킷 데이터 주기적 저장 및 전처리
6. **머신러닝 모델 학습**: 전처리된 데이터로 모델 학습 및 평가

### 트래픽 생성 (TrafficGeneratorApp)

1. **공격성 패킷 생성**:
   - 'data_preparation.py'에서 '트래픽 생성' 버튼 클릭
   - 공격 대상 IP 입력
   - 패킷 크기 및 유형 선택
   - 생성할 패킷 수 설정
   - '생성 시작' 버튼으로 트래픽 생성 및 전송

## 🔍 메모리 최적화 전략

대용량 패킷 처리를 위한 메모리 최적화 기법:

1. **청크 기반 처리**: 패킷을 1000개에서 200개 단위로 나누어 처리
2. **데이터 타입 최적화**: 
   - int64 → int32 
   - 불필요한 object 타입 최소화
3. **선택적 컬럼 처리**: 필요한 컬럼만 선택적으로 메모리에 로드
4. **명시적 메모리 관리**: 
   - 사용 완료된 데이터프레임 명시적 삭제
   - 주기적 가비지 컬렉션 호출
5. **버퍼 크기 제한**: 최대 버퍼 크기를 제한하여 메모리 누수 방지

6. **C와 파이썬의 하이브리드 방식으로 구동(고려중)**
    - 패킷 캡쳐/분석 부분만 C로 구현하여


## 🚀 운영 모드

시스템은 두 가지 운영 모드를 지원합니다:

### 1. 경량 모드 (Lightweight)
- 적은 시스템 자원 사용
- 기본 특성 7개만 사용
- 모든 환경에서 실행 가능
- 내장 휴리스틱 기반 탐지

### 2. 고성능 모드 (Performance)
- 수리카타(Suricata) 엔진 통합
- 확장 특성 12개 사용
- 더 높은 정확도의 탐지 제공
- 더 많은 시스템 자원 필요
- 규칙 기반 심층 분석 지원

## 🔮 향후 개발 계획

- PPO(Proximal Policy Optimization) 알고리즘 구현 고려
- 다양한 네트워크 환경에서의 적응성 향상
- 핵심 병목 구간(패킷 캡쳐/분석) 사용언어 C로 변경 고려(cython,메모리 및 cpu 사용량 최적화)
- 백그라운드 실행(핵심 개발 완료 후 실행 예정)
- 분산 학습 시스템 구축(클라우드 연동 고려)
- 실시간 대응 메커니즘 고도화
- 사용자 피드백 기반 성능 개선 
- 학습 및 차단 트래픽 데이터 시각화화