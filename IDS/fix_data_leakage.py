#!/usr/bin/env python3
"""
데이터 누수 문제 해결 스크립트
CIC-IDS-2017의 누수 특성 제거 및 모델 재학습
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, average_precision_score, matthews_corrcoef

def identify_leaky_features():
    """데이터 누수 의심 특성 식별"""
    print("=== 데이터 누수 특성 분석 ===")
    
    # 기존 모델 로드
    model = joblib.load('ips_random_forest_model.pkl')
    
    # 테스트 데이터 로드
    test_df = pd.read_csv('processed_data/cic_ids_2017_test.csv')
    
    # 특성과 레이블 분리
    exclude_columns = ['is_malicious', 'attack_type']
    X_test = test_df[[col for col in test_df.columns if col not in exclude_columns]]
    y_test = test_df['is_malicious']
    
    print(f"원본 특성 수: {len(X_test.columns)}개")
    
    # CIC-IDS-2017에서 누수 위험이 높은 특성들
    high_risk_features = [
        'Flow Bytes/s',           # 플로우별 고유 패턴
        'Flow Packets/s',         # 공격별 극단적 차이  
        'Flow Duration',          # 공격별 특징적 지속시간
        'Total Fwd Packets',      # 공격별 패킷 수 패턴
        'Total Backward Packets', # 응답 패킷 패턴
        'Down/Up Ratio',          # 공격별 고유 비율
        'Flow IAT Mean',          # 공격별 시간 간격
        'Flow IAT Std',           # 시간 간격 분산
        'Subflow Fwd Packets',    # 하위 플로우 정보
        'Subflow Fwd Bytes'       # 하위 플로우 바이트
    ]
    
    print(f"누수 위험 특성: {len(high_risk_features)}개")
    
    # 실제 존재하는 누수 위험 특성만 필터링
    existing_risk_features = [f for f in high_risk_features if f in X_test.columns]
    print(f"실제 존재: {len(existing_risk_features)}개")
    
    return existing_risk_features

def create_clean_features(risk_features):
    """정제된 특성 세트 생성"""
    print("\n=== 정제된 특성 세트 생성 ===")
    
    # 데이터 로드
    datasets = {}
    for split in ['train', 'val', 'test']:
        df = pd.read_csv(f'processed_data/cic_ids_2017_{split}.csv')
        datasets[split] = df
    
    # 안전한 특성 선택 (도메인 지식 기반)
    safe_features = [
        'Destination Port',       # 네트워크 기본 정보
        'Fwd Packet Length Mean', # 패킷 크기 통계 (상대적 안전)
        'Bwd Packet Length Mean',
        'Fwd Packet Length Std',
        'Bwd Packet Length Std', 
        'Packet Length Mean',     # 전체 패킷 통계
        'Packet Length Std',
        'FIN Flag Count',         # TCP 플래그 (행동 기반)
        'SYN Flag Count',
        'RST Flag Count',
        'PSH Flag Count', 
        'ACK Flag Count',
        'Average Packet Size',    # 평균 크기
        'Min Packet Length',      # 크기 범위
        'Max Packet Length',
        'Fwd Header Length',      # 헤더 정보
        'Bwd Header Length',
        'Fwd Packets/s',          # 속도 (상대적 안전)
        'Bwd Packets/s'
    ]
    
    # 실제 존재하는 안전한 특성만 선택
    train_df = datasets['train']
    exclude_columns = ['is_malicious', 'attack_type']
    all_features = [col for col in train_df.columns if col not in exclude_columns]
    
    existing_safe_features = [f for f in safe_features if f in all_features]
    
    print(f"선택된 안전한 특성: {len(existing_safe_features)}개")
    for i, feature in enumerate(existing_safe_features, 1):
        print(f"  {i:2d}. {feature}")
    
    # 정제된 데이터셋 생성
    clean_datasets = {}
    for split in ['train', 'val', 'test']:
        df = datasets[split]
        
        # 안전한 특성 + 레이블만 선택
        clean_features = existing_safe_features + ['is_malicious', 'attack_type']
        clean_df = df[clean_features].copy()
        
        clean_datasets[split] = clean_df
        
        # 저장
        clean_path = f'processed_data/cic_ids_2017_{split}_clean.csv'
        clean_df.to_csv(clean_path, index=False)
        print(f"  정제된 {split} 데이터 저장: {clean_path}")
    
    return clean_datasets, existing_safe_features

def retrain_conservative_model(clean_datasets, safe_features):
    """보수적 모델 재학습"""
    print("\n=== 보수적 모델 재학습 ===")
    
    # 데이터 준비
    train_df = clean_datasets['train']
    val_df = clean_datasets['val']
    test_df = clean_datasets['test']
    
    # 특성과 레이블 분리
    X_train = train_df[safe_features]
    y_train = train_df['is_malicious']
    X_val = val_df[safe_features]
    y_val = val_df['is_malicious']
    X_test = test_df[safe_features]
    y_test = test_df['is_malicious']
    
    # 보수적 모델 파라미터 (오버피팅 방지)
    conservative_params = {
        'n_estimators': 50,        # 트리 수 감소
        'max_depth': 8,            # 깊이 제한
        'min_samples_split': 20,   # 분할 최소 샘플 증가
        'min_samples_leaf': 10,    # 리프 최소 샘플 증가
        'max_features': 'sqrt',    # 특성 서브샘플링
        'random_state': 42,
        'class_weight': 'balanced',
        'n_jobs': -1
    }
    
    print(f"보수적 파라미터: {conservative_params}")
    
    # 모델 학습
    conservative_model = RandomForestClassifier(**conservative_params)
    conservative_model.fit(X_train, y_train)
    
    # 평가
    y_pred = conservative_model.predict(X_test)
    y_proba = conservative_model.predict_proba(X_test)[:, 1]
    
    # 성능 지표
    pr_auc = average_precision_score(y_test, y_proba)
    mcc = matthews_corrcoef(y_test, y_pred)
    
    print(f"\n보수적 모델 성능:")
    print(f"  PR-AUC: {pr_auc:.4f}")
    print(f"  MCC: {mcc:.4f}")
    
    print("\n상세 분류 보고서:")
    print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']))
    
    # 특성 중요도 (이번에는 기본 모델이므로 확인 가능)
    if hasattr(conservative_model, 'feature_importances_'):
        feature_importance = pd.DataFrame({
            'feature': safe_features,
            'importance': conservative_model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print(f"\n특성 중요도 (상위 10개):")
        for i, (_, row) in enumerate(feature_importance.head(10).iterrows()):
            print(f"  {i+1:2d}. {row['feature']}: {row['importance']:.4f}")
    
    # 모델 저장
    joblib.dump(conservative_model, 'ips_conservative_rf_model.pkl')
    print(f"\n보수적 모델 저장: ips_conservative_rf_model.pkl")
    
    return conservative_model, pr_auc, mcc

def main():
    """메인 실행"""
    try:
        # 1. 누수 특성 식별
        risk_features = identify_leaky_features()
        
        # 2. 정제된 특성 세트 생성
        clean_datasets, safe_features = create_clean_features(risk_features)
        
        # 3. 보수적 모델 재학습
        model, pr_auc, mcc = retrain_conservative_model(clean_datasets, safe_features)
        
        print("\n=== 결론 ===")
        if pr_auc > 0.8 and mcc > 0.6:
            print("✅ 보수적 모델도 좋은 성능 - 데이터 품질 양호")
        elif pr_auc > 0.7:
            print("⚠️ 적절한 성능 - 현실적 결과")
        else:
            print("❌ 성능 저하 - 추가 특성 엔지니어링 필요")
        
        print(f"보수적 모델 성능: PR-AUC {pr_auc:.3f}, MCC {mcc:.3f}")
        
    except Exception as e:
        print(f"오류: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()



