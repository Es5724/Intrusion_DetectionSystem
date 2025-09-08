#!/usr/bin/env python3
"""
CIC-IDS-2017 데이터셋 분석 스크립트
IPS 시스템 재설계를 위한 데이터 분포 및 특성 분석
"""

import pandas as pd
import numpy as np
import os
import glob
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

def analyze_cic_ids_2017():
    """CIC-IDS-2017 데이터셋 종합 분석"""
    print("=== CIC-IDS-2017 데이터셋 분석 시작 ===")
    
    # 데이터 파일 목록
    data_dir = "../CIC-IDS- 2017"
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
    
    print(f"발견된 데이터 파일: {len(csv_files)}개")
    for file in csv_files:
        file_size = os.path.getsize(file) / (1024*1024)  # MB
        print(f"  - {os.path.basename(file)}: {file_size:.1f}MB")
    
    # 각 파일별 분석
    all_results = {}
    
    
    for file_path in csv_files:
        file_name = os.path.basename(file_path)
        print(f"\n--- {file_name} 분석 중 ---")
        
        try:
            # 메모리 효율적 로딩 (첫 1000행으로 구조 파악)
            df_sample = pd.read_csv(file_path, nrows=1000)
            print(f"샘플 데이터 크기: {df_sample.shape}")
            
            # 전체 파일 크기 추정
            total_lines = sum(1 for line in open(file_path, 'r', encoding='utf-8', errors='ignore'))
            print(f"추정 전체 크기: {total_lines:,}행")
            
            # 기본 분석
            result = analyze_single_day(df_sample, file_name, total_lines)
            all_results[file_name] = result
            
        except Exception as e:
            print(f"파일 {file_name} 분석 실패: {e}")
    
    # 종합 분석
    print("\n=== 종합 분석 결과 ===")
    generate_comprehensive_report(all_results)
    
    # IPS 적합성 평가
    evaluate_ips_suitability(all_results)

def analyze_single_day(df, file_name, total_lines):
    """개별 날짜 파일 분석"""
    result = {
        'file_name': file_name,
        'sample_size': len(df),
        'estimated_total': total_lines,
        'columns': list(df.columns),
        'column_count': len(df.columns)
    }
    
    print(f"컬럼 수: {len(df.columns)}개")
    
    # 레이블 분석 (가장 중요!)
    if 'Label' in df.columns:
        label_dist = df['Label'].value_counts()
        result['label_distribution'] = label_dist.to_dict()
        
        print("레이블 분포:")
        for label, count in label_dist.items():
            percentage = (count / len(df)) * 100
            print(f"  {label}: {count}개 ({percentage:.2f}%)")
        
        # 공격 vs 정상 비율
        benign_count = label_dist.get('BENIGN', 0)
        attack_count = len(df) - benign_count
        imbalance_ratio = benign_count / max(attack_count, 1)
        result['imbalance_ratio'] = imbalance_ratio
        
        print(f"클래스 불균형 비율: {imbalance_ratio:.1f}:1 (정상:공격)")
        
    else:
        print("경고: Label 컬럼을 찾을 수 없습니다")
        result['label_distribution'] = {}
    
    # 특성 분석
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    print(f"수치형 특성: {len(numeric_cols)}개")
    
    # 결측값 분석
    missing_values = df.isnull().sum()
    missing_cols = missing_values[missing_values > 0]
    if len(missing_cols) > 0:
        print(f"결측값 있는 컬럼: {len(missing_cols)}개")
        result['missing_values'] = missing_cols.to_dict()
    else:
        print("결측값: 없음")
        result['missing_values'] = {}
    
    # 무한값 분석
    inf_counts = {}
    for col in numeric_cols:
        inf_count = np.isinf(df[col]).sum()
        if inf_count > 0:
            inf_counts[col] = inf_count
    
    if inf_counts:
        print(f"무한값 있는 컬럼: {len(inf_counts)}개")
        result['infinite_values'] = inf_counts
    else:
        print("무한값: 없음")
        result['infinite_values'] = {}
    
    return result

def generate_comprehensive_report(all_results):
    """종합 분석 보고서"""
    
    # 전체 데이터 크기
    total_samples = sum(result['estimated_total'] for result in all_results.values())
    print(f"전체 데이터셋 크기: {total_samples:,}행 (약 {total_samples/1000000:.1f}M)")
    
    # 공격 유형 종합
    all_attack_types = set()
    total_benign = 0
    total_attack = 0
    
    for result in all_results.values():
        label_dist = result.get('label_distribution', {})
        for label in label_dist.keys():
            if label != 'BENIGN':
                all_attack_types.add(label)
            else:
                total_benign += label_dist[label]
        
        # 공격 샘플 수 계산
        attack_samples = sum(count for label, count in label_dist.items() if label != 'BENIGN')
        total_attack += attack_samples
    
    print(f"\n공격 유형: {len(all_attack_types)}개")
    for attack_type in sorted(all_attack_types):
        print(f"  - {attack_type}")
    
    print(f"\n전체 클래스 분포 (샘플 기준):")
    print(f"  정상 (BENIGN): {total_benign:,}개")
    print(f"  공격: {total_attack:,}개") 
    if total_attack > 0:
        overall_ratio = total_benign / total_attack
        print(f"  불균형 비율: {overall_ratio:.1f}:1")
    
    # 데이터 품질 평가
    files_with_missing = sum(1 for result in all_results.values() if result.get('missing_values'))
    files_with_inf = sum(1 for result in all_results.values() if result.get('infinite_values'))
    
    print(f"\n데이터 품질:")
    print(f"  결측값 있는 파일: {files_with_missing}개")
    print(f"  무한값 있는 파일: {files_with_inf}개")

def evaluate_ips_suitability(all_results):
    """IPS 프로젝트 적합성 평가"""
    print("\n=== IPS 프로젝트 적합성 평가 ===")
    
    # 1. 공격 다양성 평가
    attack_types = set()
    for result in all_results.values():
        for label in result.get('label_distribution', {}).keys():
            if label != 'BENIGN':
                attack_types.add(label)
    
    print(f"1. 공격 다양성: {len(attack_types)}개 유형")
    
    # IPS 시스템에 중요한 공격들 체크
    important_attacks = ['DDoS', 'DoS', 'PortScan', 'Brute Force', 'Web Attack', 'Infiltration', 'Botnet']
    found_attacks = []
    
    for important in important_attacks:
        for attack in attack_types:
            if important.lower() in attack.lower():
                found_attacks.append(important)
                break
    
    print(f"   IPS 핵심 공격 포함: {len(found_attacks)}/{len(important_attacks)}개")
    for attack in found_attacks:
        print(f"     ✓ {attack}")
    
    # 2. 시간 기반 분리 가능성
    time_based_files = []
    for file_name in all_results.keys():
        if any(day in file_name for day in ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']):
            time_based_files.append(file_name)
    
    print(f"\n2. 시간 기반 분리: 가능 ({len(time_based_files)}개 일별 파일)")
    print("   권장 분할:")
    print("     Train: Monday, Tuesday, Wednesday (60%)")
    print("     Validation: Thursday (20%)")  
    print("     Test: Friday (20%)")
    
    # 3. 세션화 가능성
    sample_result = next(iter(all_results.values()))
    flow_features = [col for col in sample_result['columns'] if 'Flow' in col or 'IAT' in col or 'Fwd' in col or 'Bwd' in col]
    
    print(f"\n3. 세션화 지원: 우수 ({len(flow_features)}개 플로우 특성)")
    print("   주요 플로우 특성:")
    for feature in flow_features[:10]:  # 상위 10개만 표시
        print(f"     - {feature}")
    
    # 4. 클래스 불균형 평가
    max_imbalance = 0
    for result in all_results.values():
        ratio = result.get('imbalance_ratio', 1)
        max_imbalance = max(max_imbalance, ratio)
    
    print(f"\n4. 클래스 불균형: {max_imbalance:.1f}:1")
    if max_imbalance > 100:
        print("     ⚠️ 심각한 불균형 - 가중치 손실 필수")
    elif max_imbalance > 10:
        print("     ⚠️ 중간 불균형 - 가중치 손실 권장")
    else:
        print("     ✓ 적절한 균형")
    
    # 5. 데이터 크기 충분성
    total_samples = sum(result['estimated_total'] for result in all_results.values())
    
    print(f"\n5. 데이터 크기: {total_samples:,}행")
    if total_samples > 2000000:
        print("     ✓ 충분한 크기 (2M+ 샘플)")
    elif total_samples > 1000000:
        print("     ✓ 적절한 크기 (1M+ 샘플)")
    else:
        print("     ⚠️ 부족할 수 있음")

def recommend_implementation_strategy(all_results):
    """구현 전략 권장사항"""
    print("\n=== 구현 전략 권장사항 ===")
    
    print("1. 데이터 전처리 전략:")
    print("   - 시간 기반 분할: Monday-Wednesday (Train), Thursday (Val), Friday (Test)")
    print("   - 레이블 통합: 모든 공격을 is_malicious=1로 통합")
    print("   - 공격 유형별 세부 분류: attack_type 컬럼 생성")
    print("   - 무한값/결측값 처리: 0 또는 중앙값으로 대체")
    
    print("\n2. RF 모델 학습:")
    print("   - 타겟: protocol_6 → is_malicious + attack_type")
    print("   - 특성: 78개 → 핵심 특성 선별 (상관관계 분석)")
    print("   - 불균형: 가중치 손실 함수 적용")
    print("   - 검증: 시간 기반 교차 검증")
    
    print("\n3. RL 학습 데이터 생성:")
    print("   - RF 예측 결과 → 대응 시나리오 매핑")
    print("   - 공격별 대응 비용 모델링")
    print("   - 시스템 상태 시뮬레이션")
    print("   - 보상 함수 설계 (비즈니스 임팩트 반영)")
    
    print("\n4. 예상 성능:")
    print("   - RF PR-AUC: 0.85-0.90 (클래스 불균형 고려)")
    print("   - Detection Latency: 50-100ms")
    print("   - RL 누적 보상: 기존 대비 30-50% 향상 예상")

if __name__ == "__main__":
    try:
        analyze_cic_ids_2017()
        recommend_implementation_strategy({})
        
        print("\n=== 다음 단계 ===")
        print("1. 전체 데이터셋 로딩 및 통합")
        print("2. 시간 기반 train/test 분리 구현") 
        print("3. 레이블 변환 (protocol_6 → is_malicious)")
        print("4. RF 모델 재학습")
        
    except Exception as e:
        print(f"분석 중 오류: {e}")
        import traceback
        traceback.print_exc()
