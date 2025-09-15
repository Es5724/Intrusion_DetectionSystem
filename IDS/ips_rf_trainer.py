#!/usr/bin/env python3
"""
IPS용 Random Forest 모델 학습 시스템
CIC-IDS-2017 기반 is_malicious 타겟으로 학습
"""

import pandas as pd
import numpy as np
import joblib
import json
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, confusion_matrix, classification_report,
    precision_recall_curve, average_precision_score, matthews_corrcoef,
    balanced_accuracy_score, roc_auc_score, brier_score_loss
)
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
import matplotlib.pyplot as plt
import seaborn as sns
import time

class IPSRandomForestTrainer:
    """IPS용 Random Forest 학습 시스템"""
    
    def __init__(self, data_dir="processed_data"):
        self.data_dir = data_dir
        self.model = None
        self.calibrated_model = None
        self.feature_names = None
        self.class_weights = None
        
        # 평가 결과 저장
        self.evaluation_results = {}
        
        print("IPS Random Forest 학습기 초기화 완료")
    
    def load_processed_data(self):
        """전처리된 데이터 로드"""
        print("=== 전처리 데이터 로딩 ===")
        
        datasets = {}
        
        for split in ['train', 'val', 'test']:
            # KISTI 데이터 우선 사용, 없으면 CIC 데이터 사용
            kisti_path = os.path.join(self.data_dir, f"kisti_quick_{split}.csv")
            cic_path = os.path.join(self.data_dir, f"cic_ids_2017_{split}.csv")
            
            if os.path.exists(kisti_path):
                file_path = kisti_path
                print(f"  KISTI 데이터 사용: {split}")
            elif os.path.exists(cic_path):
                file_path = cic_path
                print(f"  CIC 데이터 사용: {split}")
            else:
                raise FileNotFoundError(f"데이터 파일을 찾을 수 없습니다: {kisti_path} 또는 {cic_path}")
            
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"데이터 파일을 찾을 수 없습니다: {file_path}")
            
            df = pd.read_csv(file_path)
            datasets[split] = df
            
            print(f"  {split.upper()}: {len(df):,}행 × {len(df.columns)}열")
            
            # 클래스 분포 확인
            if 'is_malicious' in df.columns:
                attack_ratio = df['is_malicious'].mean()
                print(f"    공격 비율: {attack_ratio:.3f}")
        
        # 클래스 가중치 로드
        weights_path = os.path.join(self.data_dir, "class_weights.json")
        if os.path.exists(weights_path):
            with open(weights_path, 'r') as f:
                weights_json = json.load(f)
                # JSON에서 문자열 키를 정수로 변환
                self.class_weights = {int(k): v for k, v in weights_json.items()}
            print(f"  클래스 가중치 로드: {self.class_weights}")
        
        return datasets['train'], datasets['val'], datasets['test']
    
    def prepare_features_and_labels(self, df):
        """특성과 레이블 분리"""
        # 레이블 컬럼 확인
        if 'is_malicious' not in df.columns:
            raise ValueError("is_malicious 컬럼이 없습니다")
        
        # 타겟이 될 컬럼들 제외
        exclude_columns = ['is_malicious', 'attack_type']
        feature_columns = [col for col in df.columns if col not in exclude_columns]
        
        X = df[feature_columns].copy()
        y = df['is_malicious']
        
        # 문자열 컬럼 처리 (IP 주소 등)
        string_columns = X.select_dtypes(include=['object']).columns
        if len(string_columns) > 0:
            print(f"문자열 컬럼 발견: {list(string_columns)}")
            
            from sklearn.preprocessing import LabelEncoder
            
            for col in string_columns:
                print(f"  {col} 컬럼 인코딩 중...")
                le = LabelEncoder()
                X[col] = le.fit_transform(X[col].astype(str))
        
        # 특성명 저장
        self.feature_names = feature_columns
        
        print(f"특성 수: {len(feature_columns)}개")
        print(f"샘플 수: {len(df):,}개")
        print(f"문자열 컬럼 처리: {len(string_columns)}개")
        
        return X, y
    
    def train_model(self, X_train, y_train, X_val=None, y_val=None):
        """Random Forest 모델 학습"""
        print("\n=== Random Forest 모델 학습 ===")
        
        # 모델 파라미터 설정
        rf_params = {
            'n_estimators': 100,
            'max_depth': 20,
            'min_samples_split': 5,
            'min_samples_leaf': 2,
            'random_state': 42,
            'n_jobs': -1,
            'class_weight': self.class_weights if self.class_weights else 'balanced'
        }
        
        print(f"모델 파라미터: {rf_params}")
        
        # 모델 학습
        start_time = time.time()
        
        self.model = RandomForestClassifier(**rf_params)
        self.model.fit(X_train, y_train)
        
        training_time = time.time() - start_time
        print(f"학습 완료: {training_time:.2f}초")
        
        # Calibration (신뢰도 보정)
        if X_val is not None and y_val is not None:
            print("모델 Calibration 중...")
            self.calibrated_model = CalibratedClassifierCV(self.model, method='isotonic', cv='prefit')
            self.calibrated_model.fit(X_val, y_val)
            print("Calibration 완료")
        
        return self.model
    
    def evaluate_model(self, X_test, y_test, save_plots=True):
        """IPS 전용 평가지표로 모델 평가"""
        print("\n=== IPS 전용 모델 평가 ===")
        
        # 예측 수행
        start_time = time.time()
        y_pred = self.model.predict(X_test)
        y_proba = self.model.predict_proba(X_test)[:, 1]
        prediction_time = (time.time() - start_time) / len(X_test) * 1000  # ms per sample
        
        # Calibrated 모델 예측 (있는 경우)
        if self.calibrated_model:
            y_proba_cal = self.calibrated_model.predict_proba(X_test)[:, 1]
        else:
            y_proba_cal = y_proba
        
        # 1. 기본 분류 성능
        accuracy = accuracy_score(y_test, y_pred)
        balanced_acc = balanced_accuracy_score(y_test, y_pred)
        mcc = matthews_corrcoef(y_test, y_pred)
        
        # 2. 클래스 불균형 고려 지표
        pr_auc = average_precision_score(y_test, y_proba)
        roc_auc = roc_auc_score(y_test, y_proba)
        
        # 3. 운영 지표
        detection_latency = prediction_time  # ms per sample
        
        # 4. Calibration 평가
        brier_score = brier_score_loss(y_test, y_proba_cal)
        
        # 5. 임계치별 성능 (FPR@TPR, TPR@FPR)
        precisions, recalls, thresholds = precision_recall_curve(y_test, y_proba)
        
        # TPR 90%에서 FPR 계산
        tpr_90_idx = np.argmax(recalls >= 0.9)
        if tpr_90_idx < len(thresholds):
            threshold_90 = thresholds[tpr_90_idx]
            y_pred_90 = (y_proba >= threshold_90).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_test, y_pred_90).ravel()
            fpr_at_tpr_90 = fp / (fp + tn) if (fp + tn) > 0 else 0
        else:
            fpr_at_tpr_90 = np.nan
        
        # FPR 1%에서 TPR 계산
        fpr_001_threshold = np.percentile(y_proba[y_test == 0], 99)  # 정상 샘플의 99퍼센타일
        y_pred_001 = (y_proba >= fpr_001_threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred_001).ravel()
        tpr_at_fpr_001 = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        # 결과 저장
        self.evaluation_results = {
            'classification_performance': {
                'accuracy': accuracy,
                'balanced_accuracy': balanced_acc,
                'mcc': mcc,
                'pr_auc': pr_auc,
                'roc_auc': roc_auc
            },
            'operational_performance': {
                'detection_latency_ms': detection_latency,
                'fpr_at_tpr_90': fpr_at_tpr_90,
                'tpr_at_fpr_001': tpr_at_fpr_001,
                'brier_score': brier_score
            },
            'threshold_analysis': {
                'default_threshold': 0.5,
                'tpr_90_threshold': threshold_90 if 'threshold_90' in locals() else None,
                'fpr_001_threshold': fpr_001_threshold
            }
        }
        
        # 결과 출력
        print("분류 성능:")
        print(f"  Accuracy: {accuracy:.4f}")
        print(f"  Balanced Accuracy: {balanced_acc:.4f}")
        print(f"  MCC: {mcc:.4f}")
        print(f"  PR-AUC: {pr_auc:.4f}")
        print(f"  ROC-AUC: {roc_auc:.4f}")
        
        print("\n운영 성능:")
        print(f"  Detection Latency: {detection_latency:.2f}ms/sample")
        print(f"  FPR@TPR=90%: {fpr_at_tpr_90:.4f}")
        print(f"  TPR@FPR=0.1%: {tpr_at_fpr_001:.4f}")
        print(f"  Brier Score: {brier_score:.4f}")
        
        # 상세 분류 보고서
        print("\n상세 분류 보고서:")
        print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']))
        
        # 시각화 (선택적)
        if save_plots:
            self.create_evaluation_plots(y_test, y_proba, y_proba_cal)
        
        return self.evaluation_results
    
    def create_evaluation_plots(self, y_test, y_proba, y_proba_cal):
        """평가 시각화 생성"""
        print("\n시각화 생성 중...")
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        
        # 1. PR 곡선
        precisions, recalls, _ = precision_recall_curve(y_test, y_proba)
        pr_auc = average_precision_score(y_test, y_proba)
        
        axes[0, 0].plot(recalls, precisions, label=f'PR-AUC = {pr_auc:.3f}')
        axes[0, 0].set_xlabel('Recall')
        axes[0, 0].set_ylabel('Precision')
        axes[0, 0].set_title('Precision-Recall Curve')
        axes[0, 0].legend()
        axes[0, 0].grid(True)
        
        # 2. Calibration 곡선
        fraction_of_positives, mean_predicted_value = calibration_curve(
            y_test, y_proba_cal, n_bins=10
        )
        
        axes[0, 1].plot(mean_predicted_value, fraction_of_positives, "s-", label='Calibrated')
        axes[0, 1].plot([0, 1], [0, 1], "k:", label="Perfectly calibrated")
        axes[0, 1].set_xlabel('Mean Predicted Probability')
        axes[0, 1].set_ylabel('Fraction of Positives')
        axes[0, 1].set_title('Calibration Curve')
        axes[0, 1].legend()
        axes[0, 1].grid(True)
        
        # 3. 혼동 행렬
        from sklearn.metrics import confusion_matrix
        cm = confusion_matrix(y_test, (y_proba >= 0.5).astype(int))
        sns.heatmap(cm, annot=True, fmt='d', ax=axes[1, 0], cmap='Blues')
        axes[1, 0].set_title('Confusion Matrix')
        axes[1, 0].set_xlabel('Predicted')
        axes[1, 0].set_ylabel('Actual')
        
        # 4. 특성 중요도 (상위 20개)
        if hasattr(self.model, 'feature_importances_'):
            feature_importance = pd.DataFrame({
                'feature': self.feature_names,
                'importance': self.model.feature_importances_
            }).sort_values('importance', ascending=False).head(20)
            
            axes[1, 1].barh(range(len(feature_importance)), feature_importance['importance'])
            axes[1, 1].set_yticks(range(len(feature_importance)))
            axes[1, 1].set_yticklabels(feature_importance['feature'], fontsize=8)
            axes[1, 1].set_xlabel('Feature Importance')
            axes[1, 1].set_title('Top 20 Feature Importance')
        
        plt.tight_layout()
        
        # 저장
        plot_path = os.path.join(self.data_dir, "rf_evaluation_plots.png")
        plt.savefig(plot_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"  시각화 저장: {plot_path}")
    
    def save_model_and_results(self):
        """모델 및 평가 결과 저장"""
        print("\n=== 모델 저장 ===")
        
        # 데이터셋에 따른 모델 저장
        kisti_train_path = os.path.join(self.data_dir, "kisti_quick_train.csv")
        if os.path.exists(kisti_train_path):
            model_path = "kisti_random_forest_model.pkl"
            dataset_name = "KISTI-IDS-2022"
        else:
            model_path = "ips_random_forest_model.pkl"
            dataset_name = "CIC-IDS-2017"
        
        # 통합 모델 저장 (Calibrated 모델 우선)
        if self.calibrated_model:
            joblib.dump(self.calibrated_model, model_path)
            print(f"  {dataset_name} RF 모델 (Calibrated): {model_path}")
        else:
            joblib.dump(self.model, model_path)
            print(f"  {dataset_name} RF 모델 (기본): {model_path}")
        
        # 평가 결과 저장
        results_path = os.path.join(self.data_dir, "rf_evaluation_results.json")
        with open(results_path, 'w') as f:
            json.dump(self.evaluation_results, f, indent=2)
        print(f"  평가 결과: {results_path}")
        
        # 특성 이름 저장
        if self.feature_names:
            features_path = os.path.join(self.data_dir, "feature_names.json")
            with open(features_path, 'w') as f:
                json.dump(self.feature_names, f, indent=2)
            print(f"  특성 이름: {features_path}")
    
    def generate_ips_report(self):
        """IPS 시스템용 성능 보고서 생성"""
        print("\n=== IPS 성능 보고서 ===")
        
        results = self.evaluation_results
        
        # 성능 등급 평가
        pr_auc = results['classification_performance']['pr_auc']
        mcc = results['classification_performance']['mcc']
        detection_latency = results['operational_performance']['detection_latency_ms']
        
        print("성능 평가:")
        
        # PR-AUC 등급
        if pr_auc >= 0.90:
            print(f"  PR-AUC: {pr_auc:.4f} (우수)")
        elif pr_auc >= 0.80:
            print(f"  PR-AUC: {pr_auc:.4f} (양호)")
        else:
            print(f"  PR-AUC: {pr_auc:.4f} (개선 필요)")
        
        # MCC 등급
        if mcc >= 0.80:
            print(f"  MCC: {mcc:.4f} (우수)")
        elif mcc >= 0.65:
            print(f"  MCC: {mcc:.4f} (양호)")
        else:
            print(f"  MCC: {mcc:.4f} (개선 필요)")
        
        # 지연시간 등급
        if detection_latency <= 100:
            print(f"  Detection Latency: {detection_latency:.2f}ms (우수)")
        elif detection_latency <= 200:
            print(f"  Detection Latency: {detection_latency:.2f}ms (양호)")
        else:
            print(f"  Detection Latency: {detection_latency:.2f}ms (개선 필요)")
        
        # RL 연동 준비도 평가
        brier_score = results['operational_performance']['brier_score']
        if brier_score <= 0.1:
            calibration_quality = "우수"
        elif brier_score <= 0.15:
            calibration_quality = "양호"
        else:
            calibration_quality = "개선 필요"
        
        print(f"\nRL 연동 준비도:")
        print(f"  Calibration 품질: {calibration_quality} (Brier Score: {brier_score:.4f})")
        print(f"  신뢰도 기반 대응 정책 적용 {'가능' if brier_score <= 0.15 else '주의 필요'}")
        
        # 운영 권장사항
        print("\n운영 권장사항:")
        fpr_at_tpr_90 = results['operational_performance']['fpr_at_tpr_90']
        
        if fpr_at_tpr_90 <= 0.01:  # 1% 이하
            print("  - 높은 민감도 설정 권장 (TPR 90% 임계치 사용)")
        elif fpr_at_tpr_90 <= 0.05:  # 5% 이하
            print("  - 중간 민감도 설정 권장")
        else:
            print("  - 낮은 민감도 설정 권장 (오탐 위험)")
        
        return results

def main():
    """메인 실행 함수"""
    print("IPS Random Forest 모델 학습 시작")
    print("=" * 60)
    
    try:
        # 학습기 초기화
        trainer = IPSRandomForestTrainer()
        
        # 1. 데이터 로드
        train_df, val_df, test_df = trainer.load_processed_data()
        
        # 2. 특성과 레이블 분리
        X_train, y_train = trainer.prepare_features_and_labels(train_df)
        X_val, y_val = trainer.prepare_features_and_labels(val_df)
        X_test, y_test = trainer.prepare_features_and_labels(test_df)
        
        # 3. 모델 학습
        model = trainer.train_model(X_train, y_train, X_val, y_val)
        
        # 4. 모델 평가
        results = trainer.evaluate_model(X_test, y_test)
        
        # 5. 모델 저장
        trainer.save_model_and_results()
        
        # 6. IPS 성능 보고서
        trainer.generate_ips_report()
        
        print("\n=== RF 모델 학습 완료 ===")
        print("다음 단계: RL 대응 정책 시스템 구현")
        print("생성된 파일:")
        print("  - ips_random_forest_model.pkl")
        print("  - ips_calibrated_rf_model.pkl") 
        print("  - processed_data/rf_evaluation_results.json")
        print("  - processed_data/rf_evaluation_plots.png")
        
    except Exception as e:
        print(f"학습 중 오류: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

