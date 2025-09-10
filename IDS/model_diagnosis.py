#!/usr/bin/env python3
"""
RF 모델 진단 스크립트
비현실적 성능의 원인 분석
"""

import pandas as pd
import numpy as np
import joblib
import json
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix

def diagnose_rf_model():
    """RF 모델 진단"""
    print("=== RF 모델 진단 시작 ===")
    
    # 1. 모델 로드
    try:
        model = joblib.load('ips_random_forest_model.pkl')
        print("✅ 모델 로드 성공")
    except Exception as e:
        print(f"❌ 모델 로드 실패: {e}")
        return
    
    # 2. 테스트 데이터 로드
    try:
        test_df = pd.read_csv('processed_data/cic_ids_2017_test.csv')
        print(f"✅ 테스트 데이터 로드: {len(test_df):,}행")
    except Exception as e:
        print(f"❌ 테스트 데이터 로드 실패: {e}")
        return
    
    # 3. 특성과 레이블 분리
    exclude_columns = ['is_malicious', 'attack_type']
    X_test = test_df[[col for col in test_df.columns if col not in exclude_columns]]
    y_test = test_df['is_malicious']
    
    print(f"특성 수: {len(X_test.columns)}개")
    print(f"테스트 샘플: {len(X_test):,}개")
    
    # 4. 예측 수행
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    # 5. 특성 중요도 분석 (데이터 누수 의심 특성 확인)
    print("\n=== 특성 중요도 분석 ===")
    if hasattr(model, 'feature_importances_'):
        feature_importance = pd.DataFrame({
            'feature': X_test.columns,
            'importance': model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("상위 20개 중요 특성:")
        for i, (_, row) in enumerate(feature_importance.head(20).iterrows()):
            print(f"  {i+1:2d}. {row['feature']}: {row['importance']:.4f}")
        
        # 데이터 누수 의심 특성 체크
        suspicious_features = []
        for _, row in feature_importance.head(10).iterrows():
            if row['importance'] > 0.1:  # 10% 이상 중요도
                suspicious_features.append(row['feature'])
        
        print(f"\n⚠️ 높은 중요도 특성 ({len(suspicious_features)}개):")
        for feature in suspicious_features:
            print(f"  - {feature}")
    else:
        print("⚠️ 특성 중요도 정보 없음")
        suspicious_features = []  # 초기화
    
    # 6. 클래스별 상세 분석
    print("\n=== 클래스별 분석 ===")
    
    # Test 세트 공격 유형 분포
    attack_dist = test_df[test_df['is_malicious']==1]['attack_type'].value_counts()
    print("공격 유형 분포:")
    for attack_type, count in attack_dist.items():
        print(f"  {attack_type}: {count:,}개")
    
    # 7. 예측 확률 분포 분석
    print("\n=== 예측 확률 분포 ===")
    
    benign_probs = y_proba[y_test == 0]
    attack_probs = y_proba[y_test == 1]
    
    print(f"정상 트래픽 예측 확률:")
    print(f"  평균: {benign_probs.mean():.4f}")
    print(f"  최대: {benign_probs.max():.4f}")
    print(f"  95퍼센타일: {np.percentile(benign_probs, 95):.4f}")
    
    print(f"공격 트래픽 예측 확률:")
    print(f"  평균: {attack_probs.mean():.4f}")
    print(f"  최소: {attack_probs.min():.4f}")
    print(f"  5퍼센타일: {np.percentile(attack_probs, 5):.4f}")
    
    # 8. 분리도 분석
    # 잘못 분류된 샘플 수 계산
    benign_misclassified = np.sum(benign_probs > 0.5)  # 정상인데 공격으로 분류
    attack_misclassified = np.sum(attack_probs < 0.5)  # 공격인데 정상으로 분류
    total_misclassified = benign_misclassified + attack_misclassified
    
    total = len(y_test)
    separation_quality = 1 - (total_misclassified / total)
    
    print(f"\n클래스 분리도: {separation_quality:.4f}")
    print(f"  정상 오분류: {benign_misclassified:,}개 / {len(benign_probs):,}개")
    print(f"  공격 오분류: {attack_misclassified:,}개 / {len(attack_probs):,}개")
    
    if separation_quality > 0.99:
        print("⚠️ 너무 완벽한 분리 - 데이터 누수 의심")
    elif separation_quality > 0.95:
        print("⚠️ 매우 높은 분리 - 검토 필요")
    else:
        print("✅ 적절한 분리도")
    
    # 9. 잠재적 문제 진단
    print("\n=== 잠재적 문제 진단 ===")
    
    issues = []
    
    if separation_quality > 0.99:
        issues.append("완벽한 클래스 분리 (데이터 누수 의심)")
    
    if len(suspicious_features) > 5:
        issues.append(f"과도한 고중요도 특성 ({len(suspicious_features)}개)")
    
    if benign_probs.max() < 0.1:
        issues.append("정상 트래픽 예측 확률이 너무 낮음")
    
    if attack_probs.min() > 0.9:
        issues.append("공격 트래픽 예측 확률이 너무 높음")
    
    if len(issues) == 0:
        print("✅ 특별한 문제 발견되지 않음")
    else:
        print("⚠️ 발견된 문제들:")
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")
    
    return {
        'feature_importance': feature_importance.head(20).to_dict('records'),
        'separation_quality': separation_quality,
        'issues': issues,
        'benign_prob_stats': {
            'mean': float(benign_probs.mean()),
            'max': float(benign_probs.max()),
            'p95': float(np.percentile(benign_probs, 95))
        },
        'attack_prob_stats': {
            'mean': float(attack_probs.mean()),
            'min': float(attack_probs.min()),
            'p5': float(np.percentile(attack_probs, 5))
        }
    }

def recommend_solutions():
    """해결 방안 제시"""
    print("\n=== 권장 해결 방안 ===")
    
    print("1. 데이터 누수 검증:")
    print("   - 높은 중요도 특성들의 의미 검토")
    print("   - 타겟과의 상관관계 분석")
    print("   - 시간 기반 분리 재검증")
    
    print("\n2. 모델 복잡도 조정:")
    print("   - max_depth 10-15로 감소")
    print("   - min_samples_leaf 5-10으로 증가")
    print("   - min_samples_split 10-20으로 증가")
    
    print("\n3. 교차 검증:")
    print("   - 시간 기반 K-fold 교차 검증")
    print("   - 외부 데이터셋 테스트 (UNSW-NB15)")
    print("   - Leave-One-Attack-Out 검증")
    
    print("\n4. 특성 선택:")
    print("   - 고상관 특성 제거")
    print("   - 도메인 지식 기반 특성 필터링")
    print("   - 순열 중요도 테스트")

if __name__ == "__main__":
    try:
        results = diagnose_rf_model()
        recommend_solutions()
        
        # 결과 저장
        with open('processed_data/model_diagnosis.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        print("\n진단 결과 저장: processed_data/model_diagnosis.json")
        
    except Exception as e:
        print(f"진단 중 오류: {e}")
        import traceback
        traceback.print_exc()
