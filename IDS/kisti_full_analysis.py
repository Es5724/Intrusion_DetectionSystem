#!/usr/bin/env python3
"""
KISTI 전체 데이터 분포 분석
다양한 위치에서 샘플링하여 실제 레이블 분포 확인
"""

import pandas as pd
import numpy as np

def analyze_full_kisti_distribution():
    """KISTI 전체 데이터 분포 분석"""
    print("=== KISTI 전체 데이터 분포 분석 ===")
    
    data_path = "data_set/training_set.csv"
    
    try:
        # 파일 크기와 추정 행 수
        import os
        file_size = os.path.getsize(data_path)
        print(f"파일 크기: {file_size / (1024**3):.2f}GB")
        
        # 1. 처음 1만개 샘플
        print("\n1. 처음 1만개 샘플 분석:")
        df_start = pd.read_csv(data_path, nrows=10000, sep='\t')
        analyze_sample(df_start, "처음")
        
        # 2. 중간 부분 샘플 (2백만번째 근처)
        print("\n2. 중간 부분 샘플 분석:")
        try:
            df_middle = pd.read_csv(data_path, skiprows=2000000, nrows=10000, sep='\t')
            analyze_sample(df_middle, "중간")
        except:
            print("   중간 부분 읽기 실패")
        
        # 3. 끝 부분 샘플
        print("\n3. 끝 부분 샘플 분석:")
        try:
            # 전체 행 수 추정
            sample_for_count = pd.read_csv(data_path, nrows=1000, sep='\t')
            estimated_rows = file_size // (file_size // len(sample_for_count) * 1000)
            
            skip_rows = max(0, estimated_rows - 20000)
            df_end = pd.read_csv(data_path, skiprows=skip_rows, nrows=10000, sep='\t')
            analyze_sample(df_end, "끝")
        except:
            print("   끝 부분 읽기 실패")
        
        # 4. 전체 요약
        print("\n=== 전체 분포 요약 ===")
        print("권장 레이블 매핑:")
        
        # analyResult와 attackType 조합 분석
        print("analyResult=2, attackType=0 조합 해석:")
        print("  가능성 1: analyResult 우선 (2=공격)")
        print("  가능성 2: attackType 우선 (0=정상)")
        print("  가능성 3: 두 조건 모두 만족시 공격")
        
    except Exception as e:
        print(f"분석 실패: {e}")

def analyze_sample(df, position_name):
    """샘플 데이터 분석"""
    print(f"   {position_name} 부분 ({len(df)}행):")
    
    # attackType 분포
    if 'attackType' in df.columns:
        attack_dist = df['attackType'].value_counts()
        print(f"     attackType 분포:")
        for value, count in attack_dist.head(5).items():
            percentage = (count / len(df)) * 100
            print(f"       {value}: {count}개 ({percentage:.1f}%)")
    
    # analyResult 분포
    if 'analyResult' in df.columns:
        result_dist = df['analyResult'].value_counts()
        print(f"     analyResult 분포:")
        for value, count in result_dist.head(5).items():
            percentage = (count / len(df)) * 100
            print(f"       {value}: {count}개 ({percentage:.1f}%)")
    
    # 조합 분석
    if 'attackType' in df.columns and 'analyResult' in df.columns:
        combo_dist = df.groupby(['attackType', 'analyResult']).size()
        print(f"     attackType-analyResult 조합:")
        for (attack, result), count in combo_dist.head(10).items():
            percentage = (count / len(df)) * 100
            print(f"       attackType={attack}, analyResult={result}: {count}개 ({percentage:.1f}%)")

if __name__ == "__main__":
    analyze_full_kisti_distribution()
