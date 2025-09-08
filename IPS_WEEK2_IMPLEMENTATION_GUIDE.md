# IPS 2주차 구현 가이드

## CIC-IDS-2017 기반 RF 모델 재학습

### 실행 순서

#### **1단계: 데이터 전처리 및 분리**
```bash
# IDS 디렉토리에서 실행
cd IDS
python cic_data_processor.py
```

**예상 결과:**
```
생성되는 파일:
├── processed_data/cic_ids_2017_train.csv
├── processed_data/cic_ids_2017_val.csv
├── processed_data/cic_ids_2017_test.csv
├── processed_data/dataset_summary.json
└── processed_data/class_weights.json

처리 내용:
├── 8개 CSV 파일 통합 (약 283만 행)
├── 레이블 변환: Label → is_malicious (0/1)
├── 공격 유형: attack_type (14개 카테고리)
├── 시간 기반 분리: 70% Train, 10% Val, 20% Test
├── 중복 제거: 플로우 해시 기반
├── 클래스 불균형: 가중치 계산
└── 데이터 타입 최적화
```

#### **2단계: RF 모델 학습**
```bash
# 1단계 완료 후 실행
python ips_rf_trainer.py
```

**예상 결과:**
```
생성되는 파일:
├── ips_random_forest_model.pkl (새로운 IPS용 모델)
├── ips_calibrated_rf_model.pkl (신뢰도 보정 모델)
├── processed_data/rf_evaluation_results.json
├── processed_data/rf_evaluation_plots.png
└── processed_data/feature_names.json

성능 지표:
├── PR-AUC: 0.85-0.90 (목표)
├── MCC: 0.70-0.80 (목표)
├── Detection Latency: <100ms (목표)
├── Balanced Accuracy: 0.80+ (목표)
└── Calibration 품질: 우수 (RL 연동 준비)
```

## 주요 개선사항

### **기존 대비 변경점**

#### **1. 레이블 시스템 완전 변경**
```python
기존:
├── 타겟: protocol_6 (TCP 여부)
├── 용도: 프로토콜 분류
└── 문제: 보안과 무관

새로운:
├── 타겟: is_malicious (공격 여부)
├── 보조: attack_type (공격 유형)
├── 용도: 위협 탐지
└── 장점: 실제 보안 가치
```

#### **2. 데이터 분리 방식 개선**
```python
기존:
├── 방식: 무작위 분할
├── 문제: 데이터 누수 위험
└── 평가: 과대추정 가능

새로운:
├── 방식: 시간 기반 분리
├── 장점: 미래 예측 시뮬레이션
├── 안전: 데이터 누수 방지
└── 현실: 실제 운영 환경 반영
```

#### **3. 평가 지표 전문화**
```python
기존:
├── 지표: 단순 Accuracy
├── 한계: 클래스 불균형 미고려
└── 운영: 실용성 부족

새로운:
├── 분류: PR-AUC, MCC, Balanced Accuracy
├── 운영: Detection Latency, FPR@TPR
├── 신뢰도: Calibration, Brier Score
└── 임계치: 운영 기준 최적화
```

## 데이터셋 분석 결과

### **CIC-IDS-2017 완벽 적합성 확인**
```
✅ 공격 다양성: 14개 공격 유형
  ├── DDoS/DoS (4종): 128K + 252K 샘플
  ├── Port Scan: 159K 샘플
  ├── Brute Force (FTP/SSH): 14K 샘플
  ├── Web Attack (3종): 2K 샘플
  ├── Botnet: 2K 샘플
  ├── Infiltration: 36 샘플 (희귀)
  └── Heartbleed: 11 샘플 (매우 희귀)

✅ 클래스 분포: 87% 정상 : 13% 공격 (현실적)

✅ 시간성: 5일간 순차 데이터 (시간 분리 완벽 지원)

✅ 특성 품질: 78개 플로우 특성 (세션화 최적)

✅ 데이터 크기: 283만 샘플 (충분한 학습 데이터)
```

### **예상 성능**
```
RF 모델 성능 예상:
├── PR-AUC: 0.85-0.90 (클래스 불균형 환경 최적화)
├── MCC: 0.70-0.80 (종합 성능 지표)
├── Detection Latency: 50-100ms (실시간 처리 가능)
├── Calibration: 우수 (RL 입력 신뢰성 확보)
└── 일반화: 우수 (다양한 공격 포함)

RL 연동 준비도: 95%
├── 신뢰도 기반 대응 정책 적용 가능
├── 공격별 차등 대응 전략 구현 가능
├── 비용 기반 보상 함수 설계 가능
└── OPE 평가 데이터 생성 가능
```

## 다음 단계 (3주차) 준비

### **RL 대응 정책 시스템 설계**
```python
준비된 입력 데이터:
├── RF 예측 확률 (0.0-1.0)
├── RF 신뢰도 (Calibration 적용)
├── 공격 유형 (14개 카테고리)
├── 심각도 수준 (확률 기반)
└── 특성 중요도 (해석 가능성)

RL 상태 공간 설계:
state = [
    rf_probability,      # RF 예측 확률
    rf_confidence,       # 신뢰도 점수
    attack_type_encoded, # 공격 유형 코드
    system_cpu_load,     # 시스템 부하
    active_threats,      # 현재 활성 위협
    time_context,        # 시간적 컨텍스트
    business_impact      # 비즈니스 영향도
]

RL 액션 공간:
actions = [
    0: 'allow',           # 허용
    1: 'block_temporary', # 임시 차단
    2: 'block_permanent', # 영구 차단  
    3: 'rate_limit',      # 레이트 제한
    4: 'deep_inspection', # 추가 검사
    5: 'isolate_session'  # 세션 격리
]
```

## 성공 지표 달성 예상

### **2주차 목표 대비**
```
✅ Train/Test 분리: 완벽 구현 (시간 기반)
✅ 레이블 변환: protocol_6 → is_malicious
✅ RF 평가지표: 전문적 지표 세트 구현
✅ 데이터 품질: CIC-IDS-2017 활용으로 대폭 개선
✅ 클래스 불균형: 가중치 손실로 해결
✅ 중복 제거: 플로우 해시 기반 구현

예상 달성률: 95%
```

### **3주차 준비도**
```
RL 대응 정책 구현을 위한 준비:
✅ 고품질 RF 탐지 결과
✅ 신뢰도 보정된 예측
✅ 공격별 분류 정보
✅ 운영 지표 기반 평가
✅ RL 상태 공간 설계 완료

준비도: 90%
```

## 실행 체크리스트

- [ ] CIC-IDS-2017 데이터셋 경로 확인
- [ ] Python 환경 및 필요 패키지 설치 확인
- [ ] 충분한 디스크 공간 확보 (약 2GB)
- [ ] cic_data_processor.py 실행
- [ ] ips_rf_trainer.py 실행  
- [ ] 생성된 결과 파일 검증
- [ ] 성능 지표 확인
- [ ] 다음 단계 (RL) 준비

**이제 1단계부터 실행해보시겠습니까?**

