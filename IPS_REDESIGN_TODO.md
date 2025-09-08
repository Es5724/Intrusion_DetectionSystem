# IPS 시스템 재설계 TODO 리스트

## 1주차: 기본 구조 정리 ✅ **완료**

### ✅ 완료된 작업
- [x] **IDS → IPS 완전 변경**
  - [x] IPSAgent_RL.py 파일명 및 내용 변경
  - [x] IPS_Training_Data_Generator.py 파일명 변경
  - [x] README.md 제목 및 개요 변경
  - [x] 로그 파일명 변경 (ips_debug.log)
  - [x] 시스템 메시지 및 대시보드 텍스트
  - [x] 모듈 패키지 설명 변경

- [x] **파이프라인 구조 재설계 완료**
  - [x] 현재 구조 문제점 문서화 (IPS_PIPELINE_DESIGN.md)
  - [x] 새로운 2단계 구조 설계 완료
  - [x] RF-RL 인터페이스 정의
  - [x] 데이터 흐름 다이어그램 작성

- [x] **CIC-IDS-2017 데이터 분석 완료**
  - [x] 데이터셋 적합성 평가 (완벽 적합)
  - [x] 클래스 분포 확인 (87% 정상 : 13% 공격)
  - [x] 공격 유형 분석 (14개 유형)
  - [x] 시간 기반 분리 전략 수립

## 2주차: 핵심 기능 구현 🔄 **진행 중**

### ✅ 완료된 작업 (2주차)
- [x] **CIC-IDS-2017 데이터 통합 및 전처리**
  - [x] 8개 CSV 파일 통합 (553,318개 샘플)
  - [x] 레이블 변환 (Label → is_malicious + attack_type)
  - [x] 컬럼명 공백 문제 해결
  - [x] JSON 직렬화 타입 오류 해결

- [x] **Train/Test 분리 시스템**
  - [x] 시간 기반 분리 로직 구현
  - [x] 데이터 누수 방지 검증 (70/10/20 분리)
  - [x] 클래스 분포 검증 완료

- [x] **중복 패킷 제거**
  - [x] 플로우 해시 기반 중복 탐지
  - [x] 완전 중복 행 제거
  - [x] 품질 기반 필터링 (초단시간 플로우 제거)

- [x] **클래스 불균형 처리**
  - [x] 가중치 손실 함수 계산 (0: 0.55, 1: 5.39)
  - [x] 클래스별 가중치 저장
  - [x] 불균형 비율 분석 (10:1)

### 🔄 진행 중인 작업
- [ ] **RF 평가지표 구현 및 모델 학습**
  - [x] PR-AUC, MCC, Balanced Accuracy 구현
  - [x] Detection Latency 측정 로직
  - [x] Calibration 평가 (Brier score, Reliability curve)
  - [x] 모델 저장 로직 (1개 파일로 통합)
  - [ ] **실제 RF 모델 학습 실행** ← 현재 단계
  - [ ] 성능 지표 확인 및 검증

## 3주차: RL 대응정책 전환

### 🚨 Critical Priority
- [ ] **시스템 버전 분리 설계**
  - [ ] Standard 버전: RF + RL (경량 시스템용)
  - [ ] Advanced 버전: Suricata + RF + RL (고성능 시스템용)
  - [ ] 버전별 기능 매트릭스 정의
  - [ ] 공통 인터페이스 설계

- [ ] **RL 역할 변경: 탐지 → 대응정책**
  - [ ] 새로운 액션 스페이스 정의
    - 허용, 차단, 레이트리밋, 추가검사, 격리
  - [ ] 새로운 상태 공간 설계 (버전별)
    - Standard: RF 예측 결과 + 시스템 상태
    - Advanced: Suricata + RF 통합 결과 + 시스템 상태
  - [ ] 보상 함수 재설계
    - TP 차단: +R, FP 차단: -α, 지연: -γ

### 🔧 파이프라인 구현 (버전별)

#### **Standard 버전 (RF + RL)**
- [ ] **2단계 파이프라인**
  - [ ] 1단계: RF 감지기 - 악성 확률 산출
  - [ ] 2단계: RL 정책 - 대응 액션 결정
  - [ ] RF-RL 인터페이스 구현

#### **Advanced 버전 (Suricata + RF + RL)**  
- [ ] **3단계 파이프라인**
  - [ ] 1단계: Suricata 시그니처 기반 1차 탐지
  - [ ] 2단계: RF 통합 분석 (Suricata 결과 + 패킷 특성)
  - [ ] 3단계: RL 정책 - 통합 결과 기반 대응
  - [ ] Suricata-RF 통합 인터페이스 구현
  - [ ] 계층적 탐지 시스템 구현

### 🔄 수리카타 엔진 관련 변경사항
- [ ] **수리카타 역할 재정의**
  - [ ] 기존: RL 특성 중 하나 → 새로운: 1차 탐지기
  - [ ] 시그니처 기반 빠른 스크리닝 역할
  - [ ] RF 모델 입력 특성으로 활용
  - [ ] 알려진 공격 vs 미지 공격 구분 기준

- [ ] **수리카타-RF 통합 시스템**
  - [ ] 수리카타 결과를 RF 특성으로 통합
  - [ ] 계층적 신뢰도 계산 (시그니처 + ML)
  - [ ] 탐지기별 강점 영역 분리
  - [ ] 합의 기반 최종 판단 로직

- [ ] **Advanced 모드 전용 기능**
  - [ ] 수리카타 규칙 동적 업데이트
  - [ ] 시그니처 성능 모니터링
  - [ ] 수리카타-RF 성능 비교 분석
  - [ ] 탐지기별 기여도 분석

### 🔬 High Priority
- [ ] **OPE 평가 시스템**
  - [ ] 기본 OPE 구현 (IPS/DR)
  - [ ] Doubly Robust 추정
  - [ ] 로그 정책 대비 기대보상 추정

## 4주차: 고급 기능 및 최적화

### 📊 Medium Priority
- [ ] **고급 피처 엔지니어링**
  - [ ] 스케일링 제거
  - [ ] NaN/Inf 정리 로직
  - [ ] 고상관 피처 제거
  - [ ] 누수 피처 탐지
  - [ ] 세션화 (슬라이딩 윈도 집계)

- [ ] **보수적 RL 구현**
  - [ ] Conservative Q-Learning (CQL)
  - [ ] 오프라인 RL 기법 적용
  - [ ] 안전성 보장 메커니즘

### 📈 추가 개선사항
- [ ] **일반화 평가**
  - [ ] Cross-dataset 테스트
  - [ ] Leave-One-Attack-Out 검증
  - [ ] 미지 공격 일반화 능력

- [ ] **임계치 최적화**
  - [ ] 운영 기준 FPR 설정
  - [ ] 비용 기반 최적화
  - [ ] ROC/PR 곡선 분석

## 시스템 버전 분리 계획

### 📊 Standard 버전 (RF + RL)
```
대상 환경: 경량 시스템, 임베디드, 리소스 제한 환경
구성 요소:
├── 패킷 캡처 시스템
├── RF 위협 탐지기
├── RL 대응 정책
└── 기본 방어 메커니즘

특징:
├── 빠른 처리 속도
├── 낮은 메모리 사용량
├── 미지 공격 탐지 특화
└── 단순한 배포 및 관리
```

### 🚀 Advanced 버전 (Suricata + RF + RL)
```
대상 환경: 고성능 서버, 엔터프라이즈, 중앙 관제 시스템
구성 요소:
├── Suricata 엔진 (1차 탐지)
├── RF 통합 분석기 (2차 검증)
├── RL 대응 정책 (최적화)
└── 고급 방어 메커니즘

특징:
├── 최고 탐지 정확도
├── 알려진 공격 즉시 탐지
├── 미지 공격 고도 분석
├── 상세한 포렌식 정보
└── 고급 대응 정책
```

### 🔄 공통 인터페이스 설계
```
공통 API:
├── detect_threat(packet) → ThreatInfo
├── decide_response(threat_info, context) → ResponseAction
├── execute_action(action) → ActionResult
└── evaluate_performance() → Metrics

버전별 차이:
├── Standard: RF 기반 ThreatInfo
├── Advanced: Suricata + RF 통합 ThreatInfo
└── 동일한 RL 대응 정책 (상태공간만 다름)
```

## 위험 요소 및 주의사항

### ⚠️ 데이터 누수 방지
- 같은 플로우/세션이 train/test에 동시 존재 금지
- 시간 기반 분리로 미래 정보 누수 방지
- 교차 검증시 시간 순서 유지

### ⚠️ 평가 함정 방지
- AUC만으로 모델 선택 금지
- 클래스 재가중치 평가시 원본 분포로 최종 검증
- 온라인 탐색 가정 배제

### ⚠️ 운영 안정성
- 보수적 RL로 안전성 확보
- Fallback 정책 유지
- 점진적 배포 전략

### ⚠️ 버전 관리 복잡성
- 두 버전 간 코드 동기화
- 공통 모듈 vs 버전별 모듈 분리
- 테스트 매트릭스 증가
- 성능 비교 및 벤치마킹

## 모델 학습 환경 설계

### 🏗️ 학습 인프라 구축
- [ ] **개발/학습 전용 환경 구성**
  - [ ] 고성능 학습 서버 설정
  - [ ] 격리된 네트워크 환경
  - [ ] 대용량 데이터 저장소
  - [ ] 모델 버전 관리 시스템

- [ ] **RF 오프라인 학습 시스템**
  - [ ] 정적 데이터셋 기반 학습
  - [ ] 시간 기반 train/test 분리
  - [ ] 교차 검증 프레임워크
  - [ ] 외부 데이터셋 검증 (KDD, CIC-IDS)

- [ ] **RL 오프라인 학습 시스템**
  - [ ] 방어 로그 기반 학습 데이터 생성
  - [ ] 시뮬레이션 환경 구축
  - [ ] OPE 기반 안전한 정책 학습
  - [ ] A/B 테스트 환경

### 📊 학습 데이터 관리
- [ ] **RF 학습 데이터셋**
  - [ ] 공격/정상 레이블 생성 (protocol_6 → is_malicious)
  - [ ] 클래스 불균형 해결
  - [ ] 데이터 품질 검증
  - [ ] 시간성 정보 보존

- [ ] **RL 학습 데이터셋**  
  - [ ] 방어 조치 로그 수집
  - [ ] 대응 효과성 라벨링
  - [ ] 시스템 상태 정보 통합
  - [ ] 보상 설계 및 계산

### 🔄 학습 파이프라인 자동화
- [ ] **CI/CD 기반 모델 학습**
  - [ ] 자동 데이터 수집 및 전처리
  - [ ] 스케줄링 기반 재학습
  - [ ] 모델 성능 자동 검증
  - [ ] 안전한 모델 배포

## 성공 지표

### 📊 Standard 버전 (RF + RL) 성능
```
RF 탐지 성능:
├── PR-AUC > 0.80
├── MCC > 0.65
├── Detection Latency < 150ms
├── Calibration Error < 0.15

RL 대응 성능:
├── 누적 보상 > 기존 규칙 기반 정책
├── FP 차단 비용 < 기존 대비 60%
├── 대응 지연 시간 < 300ms
├── 시스템 자원 < 200MB

시스템 통합:
├── 메모리 사용량 < 250MB
├── 처리 지연 < 1.5초
├── 24시간 안정 운영
```

### 🚀 Advanced 버전 (Suricata + RF + RL) 성능
```
통합 탐지 성능:
├── PR-AUC > 0.90 (Suricata + RF 시너지)
├── MCC > 0.80
├── Detection Latency < 100ms (Suricata 빠른 처리)
├── Calibration Error < 0.10

고급 대응 성능:
├── 누적 보상 > 기존 대비 150%
├── FP 차단 비용 < 기존 대비 40%
├── 대응 지연 시간 < 200ms
├── 알려진 공격 탐지율 > 95%

시스템 통합:
├── 메모리 사용량 < 400MB
├── 처리 지연 < 1초
├── 99.9% 가용률
├── 포렌식 정보 완전성
```

### 📈 버전 간 비교 지표
```
성능 비교:
├── 탐지 정확도: Advanced > Standard
├── 처리 속도: Standard > Advanced  
├── 자원 사용: Standard < Advanced
├── 배포 복잡도: Standard < Advanced
├── 유지보수: Standard < Advanced

선택 기준:
├── 임베디드/IoT: Standard 버전
├── 엔터프라이즈: Advanced 버전
├── 하이브리드: 환경별 동적 선택
└── 개발/테스트: Standard 버전 우선
```

## 구현 순서 및 우선순위

### 🥇 Phase 1: Standard 버전 구현 (3-4주)
```
우선 구현 이유:
├── 복잡도 낮음 (Suricata 의존성 없음)
├── 빠른 검증 가능
├── 핵심 아키텍처 검증
├── 대부분 환경에서 사용 가능
└── Advanced 버전의 기반

구현 순서:
1. RF 탐지기 개선
2. RL 대응정책 전환
3. 통합 테스트 및 검증
4. 성능 최적화
```

### 🥈 Phase 2: Advanced 버전 확장 (2-3주)
```
Standard 버전 기반 확장:
├── Suricata 엔진 통합
├── 3단계 파이프라인 구현
├── 계층적 탐지 시스템
├── 고급 대응 정책
└── 포렌식 정보 강화

확장 방식:
├── 기존 코드 재사용 최대화
├── 플러그인 방식 Suricata 추가
├── 설정 기반 버전 선택
└── 공통 인터페이스 유지
```

### 🔄 버전 선택 메커니즘
```python
# 런타임 버전 선택 로직
def select_ips_version():
    # 1. 시스템 자원 확인
    memory_gb = psutil.virtual_memory().total / (1024**3)
    cpu_cores = psutil.cpu_count()
    
    # 2. Suricata 설치 여부 확인
    suricata_available = check_suricata_installation()
    
    # 3. 사용자 설정 확인
    user_preference = config.get('preferred_version', 'auto')
    
    # 4. 자동 선택 로직
    if user_preference == 'standard':
        return 'standard'
    elif user_preference == 'advanced' and suricata_available:
        return 'advanced'
    elif memory_gb >= 4 and cpu_cores >= 4 and suricata_available:
        return 'advanced'  # 자동 선택
    else:
        return 'standard'  # 기본값
```
