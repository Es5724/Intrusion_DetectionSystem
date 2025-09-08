#!/usr/bin/env python3
"""
IPS 시스템 데이터 분포 분석 스크립트
현재 데이터의 클래스 분포, 품질, 특성을 분석합니다.
"""

import pandas as pd
import numpy as np
import os
import glob
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns

def analyze_current_data():
    """현재 데이터 상태 분석"""
    print("=== IPS 데이터 분포 분석 시작 ===")
    
    # 1. 사용 가능한 데이터 파일 찾기
    data_files = []
    
    # CSV 파일들 찾기
    csv_files = glob.glob("captured_packets_*.csv")
    csv_files.extend(glob.glob("../captured_packets_*.csv"))
    
    # 전처리 데이터 찾기
    if os.path.exists("data_set/전처리데이터1.csv"):
        data_files.append("data_set/전처리데이터1.csv")
    
    data_files.extend(csv_files)
    
    if not data_files:
        print("분석할 데이터 파일을 찾을 수 없습니다.")
        return
    
    print(f"발견된 데이터 파일: {len(data_files)}개")
    for file in data_files[:5]:  # 최대 5개만 표시
        print(f"  - {file}")
    
    # 2. 각 파일 분석
    all_results = {}
    
    for file_path in data_files[:3]:  # 최대 3개 파일만 분석
        try:
            print(f"\n--- {file_path} 분석 중 ---")
            df = pd.read_csv(file_path)
            
            result = analyze_single_file(df, file_path)
            all_results[file_path] = result
            
        except Exception as e:
            print(f"파일 {file_path} 분석 실패: {e}")
    
    # 3. 종합 분석 결과
    print("\n=== 종합 분석 결과 ===")
    generate_summary_report(all_results)

def analyze_single_file(df, file_path):
    """개별 파일 분석"""
    result = {}
    
    print(f"데이터 크기: {df.shape}")
    print(f"컬럼: {list(df.columns)}")
    
    # 기본 통계
    result['shape'] = df.shape
    result['columns'] = list(df.columns)
    result['missing_values'] = df.isnull().sum().to_dict()
    result['data_types'] = df.dtypes.to_dict()
    
    # 클래스 분포 분석 (여러 가능한 레이블 컬럼 확인)
    label_columns = ['protocol_6', 'is_malicious', 'attack', 'label', 'class']
    result['class_distributions'] = {}
    
    for col in label_columns:
        if col in df.columns:
            distribution = df[col].value_counts().to_dict()
            result['class_distributions'][col] = distribution
            print(f"\n{col} 클래스 분포:")
            for class_name, count in distribution.items():
                percentage = (count / len(df)) * 100
                print(f"  {class_name}: {count:,}개 ({percentage:.2f}%)")
    
    # 특성 분석
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) > 0:
        result['numeric_stats'] = df[numeric_cols].describe().to_dict()
        
        # 이상치 탐지
        for col in numeric_cols:
            q1 = df[col].quantile(0.25)
            q3 = df[col].quantile(0.75)
            iqr = q3 - q1
            outliers = df[(df[col] < q1 - 1.5*iqr) | (df[col] > q3 + 1.5*iqr)]
            result[f'{col}_outliers'] = len(outliers)
            if len(outliers) > 0:
                print(f"{col} 이상치: {len(outliers)}개 ({len(outliers)/len(df)*100:.2f}%)")
    
    # 중복 데이터 분석
    duplicates = df.duplicated()
    result['duplicates'] = duplicates.sum()
    if duplicates.sum() > 0:
        print(f"중복 행: {duplicates.sum()}개 ({duplicates.sum()/len(df)*100:.2f}%)")
    
    # 5-튜플 중복 분석 (가능한 경우)
    tuple_cols = ['source', 'destination', 'protocol']
    if all(col in df.columns for col in tuple_cols):
        tuple_duplicates = df[tuple_cols].duplicated()
        result['tuple_duplicates'] = tuple_duplicates.sum()
        print(f"5-튜플 중복: {tuple_duplicates.sum()}개")
    
    return result

def generate_summary_report(all_results):
    """종합 분석 보고서 생성"""
    
    print("\n📊 데이터 품질 평가:")
    
    total_samples = 0
    total_duplicates = 0
    class_imbalance_issues = []
    
    for file_path, result in all_results.items():
        samples = result['shape'][0]
        total_samples += samples
        
        # 중복 데이터 집계
        if 'duplicates' in result:
            total_duplicates += result['duplicates']
        
        # 클래스 불균형 분석
        for col, distribution in result.get('class_distributions', {}).items():
            if len(distribution) >= 2:
                counts = list(distribution.values())
                max_count = max(counts)
                min_count = min(counts)
                imbalance_ratio = max_count / min_count
                
                if imbalance_ratio > 10:  # 10:1 이상 불균형
                    class_imbalance_issues.append({
                        'file': file_path,
                        'column': col,
                        'ratio': imbalance_ratio,
                        'distribution': distribution
                    })
    
    print(f"총 데이터 샘플: {total_samples:,}개")
    print(f"총 중복 데이터: {total_duplicates:,}개 ({total_duplicates/total_samples*100:.2f}%)")
    
    if class_imbalance_issues:
        print(f"\n⚠️ 클래스 불균형 문제 발견: {len(class_imbalance_issues)}개")
        for issue in class_imbalance_issues:
            print(f"  {issue['file']} - {issue['column']}: {issue['ratio']:.1f}:1 불균형")
            
    # 권장사항
    print("\n📋 권장 개선사항:")
    
    if total_duplicates > total_samples * 0.05:  # 5% 이상 중복
        print("  1. 중복 제거 시스템 구현 필요")
    
    if class_imbalance_issues:
        print("  2. 클래스 불균형 처리 필요")
        print("     - 가중치 손실 함수 적용")
        print("     - 언더샘플링 또는 SMOTE 고려")
    
    if total_samples < 10000:
        print("  3. 데이터 수집 확대 필요")
        print("     - 다양한 공격 시나리오 추가")
        print("     - 정상 트래픽 데이터 보강")
    
    print("  4. Train/Test 분리 시 시간 기반 분리 권장")
    print("  5. 세션 기반 특성 추가 고려")

def check_data_leakage_risk():
    """데이터 누수 위험 요소 분석"""
    print("\n🔍 데이터 누수 위험 분석:")
    
    # 시간 정보 확인
    time_columns = ['timestamp', 'time', 'datetime', 'created_at']
    
    # 실제 구현에서는 데이터 파일을 읽어서 분석
    print("  검사 항목:")
    print("  - 동일 세션/플로우의 train/test 분리 여부")
    print("  - 시간 순서 기반 분리 적용 여부") 
    print("  - 미래 정보 누수 가능성")
    print("  - 타겟 누수 피처 존재 여부")
    
    # 권장사항
    print("\n  권장 분리 전략:")
    print("  1. 시간 기반 분리: 70% (과거) / 30% (미래)")
    print("  2. 세션 기반 분리: 동일 플로우는 같은 세트에")
    print("  3. 계층적 분리: 공격 유형별 균등 분배")

def analyze_feature_quality():
    """특성 품질 분석"""
    print("\n🔬 특성 품질 분석:")
    
    print("  현재 특성 (추정):")
    print("  - source, destination: IP 주소")
    print("  - protocol: 프로토콜 번호/이름")
    print("  - length: 패킷 크기")
    print("  - ttl, flags: TCP/IP 특성")
    
    print("\n  품질 개선 필요 영역:")
    print("  1. 스케일링 제거 (트리 기반 모델)")
    print("  2. 범주형 변수 인코딩 최적화")
    print("  3. 시계열 특성 추가 (세션화)")
    print("  4. 컨텍스트 특성 추가")
    
    print("\n  누수 위험 특성:")
    print("  - 미래 정보 포함 특성 확인 필요")
    print("  - 타겟과 강상관 특성 검토 필요")
    print("  - ID 기반 특성 제거 필요")

if __name__ == "__main__":
    try:
        analyze_current_data()
        check_data_leakage_risk()
        analyze_feature_quality()
        
        print("\n=== 분석 완료 ===")
        print("다음 단계: IPS_REDESIGN_TODO.md 참조")
        
    except Exception as e:
        print(f"분석 중 오류: {e}")
        import traceback
        traceback.print_exc()
