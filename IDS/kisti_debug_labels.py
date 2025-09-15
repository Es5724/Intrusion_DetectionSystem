#!/usr/bin/env python3
"""
KISTI 데이터 레이블 값 확인 스크립트
"""

import pandas as pd

def check_kisti_labels():
    """KISTI 실제 레이블 값 확인"""
    print("=== KISTI 레이블 값 확인 ===")
    
    try:
        # 첫 1000행 샘플 로드 (탭 구분자)
        df = pd.read_csv("../data_set/training_set.csv", nrows=1000, sep='\t')
        
        print(f"샘플 크기: {len(df)}행")
        print(f"컬럼 수: {len(df.columns)}개")
        
        # analyResult 값 확인
        if 'analyResult' in df.columns:
            print("\n=== analyResult 값 분포 ===")
            result_counts = df['analyResult'].value_counts()
            for value, count in result_counts.head(10).items():
                print(f"  '{value}': {count}개")
            
            print(f"\n고유 analyResult 값: {df['analyResult'].nunique()}개")
            print(f"샘플 값들: {list(df['analyResult'].unique()[:10])}")
        
        # attackType 값 확인
        if 'attackType' in df.columns:
            print("\n=== attackType 값 분포 ===")
            attack_counts = df['attackType'].value_counts()
            for value, count in attack_counts.head(10).items():
                print(f"  '{value}': {count}개")
            
            print(f"\n고유 attackType 값: {df['attackType'].nunique()}개")
            print(f"샘플 값들: {list(df['attackType'].unique()[:10])}")
        
        # detectName 값 확인
        if 'detectName' in df.columns:
            print("\n=== detectName 값 분포 ===")
            detect_counts = df['detectName'].value_counts()
            for value, count in detect_counts.head(5).items():
                print(f"  '{value}': {count}개")
        
        # 실제 데이터 몇 행 출력
        print("\n=== 실제 데이터 샘플 ===")
        for i in range(min(3, len(df))):
            print(f"행 {i+1}:")
            if 'analyResult' in df.columns:
                print(f"  analyResult: '{df.iloc[i]['analyResult']}'")
            if 'attackType' in df.columns:
                print(f"  attackType: '{df.iloc[i]['attackType']}'")
            if 'detectName' in df.columns:
                print(f"  detectName: '{df.iloc[i]['detectName']}'")
            print()
        
    except Exception as e:
        print(f"레이블 확인 실패: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    check_kisti_labels()
