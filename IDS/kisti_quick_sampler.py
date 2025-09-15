#!/usr/bin/env python3
"""
KISTI 빠른 샘플링 처리기
복잡한 분석 없이 바로 랜덤 샘플링
"""

import pandas as pd
import numpy as np
import os
import time

def quick_kisti_sampling():
    """빠른 KISTI 샘플링"""
    print("=== KISTI 빠른 샘플링 시작 ===")
    
    data_path = "../data_set/training_set.csv"
    
    try:
        start_time = time.time()
        
        # 1. 전체 데이터 로드 (메모리가 충분하다면)
        print("1단계: 전체 데이터 로딩 중...")
        print("⚠️ 5GB 파일 로딩 - 메모리 8GB 이상 권장")
        
        df = pd.read_csv(data_path, sep='\t')
        
        load_time = time.time() - start_time
        print(f"✅ 로딩 완료: {len(df):,}행 ({load_time/60:.1f}분)")
        
        # 2. 랜덤 샘플링 (즉시)
        print("2단계: 랜덤 샘플링 중...")
        sample_size = min(500000, len(df))
        sampled_df = df.sample(n=sample_size, random_state=42)
        
        print(f"✅ 샘플링 완료: {len(sampled_df):,}행")
        
        # 3. 간단한 변환
        print("3단계: RF 형태 변환 중...")
        
        # 기본 특성 추출
        rf_data = pd.DataFrame()
        rf_data['source'] = sampled_df['sourceIP'].astype(str)
        rf_data['destination'] = sampled_df['destinationIP'].astype(str)
        rf_data['source_port'] = pd.to_numeric(sampled_df['sourcePort'], errors='coerce').fillna(0)
        rf_data['dest_port'] = pd.to_numeric(sampled_df['destinationPort'], errors='coerce').fillna(0)
        rf_data['protocol'] = sampled_df['protocol'].astype(str)
        rf_data['packet_size'] = pd.to_numeric(sampled_df['packetSize'], errors='coerce').fillna(0)
        
        # 레이블 생성 (analyResult=2 기반)
        result_values = pd.to_numeric(sampled_df['analyResult'], errors='coerce').fillna(0)
        rf_data['is_malicious'] = (result_values == 2).astype(int)
        rf_data['attack_type'] = ['detected_attack' if r == 2 else 'normal' for r in result_values]
        
        print(f"✅ 변환 완료")
        
        # 4. 클래스 분포 확인
        attack_ratio = rf_data['is_malicious'].mean()
        attack_count = rf_data['is_malicious'].sum()
        normal_count = len(rf_data) - attack_count
        
        print(f"클래스 분포:")
        print(f"  정상: {normal_count:,}개 ({(1-attack_ratio)*100:.1f}%)")
        print(f"  공격: {attack_count:,}개 ({attack_ratio*100:.1f}%)")
        
        # 5. Train/Test 분리
        print("4단계: Train/Test 분리 중...")
        
        # 간단한 랜덤 분리
        train_df = rf_data.sample(frac=0.7, random_state=42)
        remaining_df = rf_data.drop(train_df.index)
        val_df = remaining_df.sample(frac=0.5, random_state=42)
        test_df = remaining_df.drop(val_df.index)
        
        print(f"  Train: {len(train_df):,}행")
        print(f"  Val: {len(val_df):,}행")
        print(f"  Test: {len(test_df):,}행")
        
        # 6. 저장
        print("5단계: 데이터 저장 중...")
        
        os.makedirs("processed_data", exist_ok=True)
        
        train_df.to_csv("processed_data/kisti_quick_train.csv", index=False)
        val_df.to_csv("processed_data/kisti_quick_val.csv", index=False)
        test_df.to_csv("processed_data/kisti_quick_test.csv", index=False)
        
        total_time = time.time() - start_time
        print(f"\n=== KISTI 빠른 샘플링 완료 ===")
        print(f"총 처리 시간: {total_time/60:.1f}분")
        print(f"처리 속도: {len(sampled_df)/total_time:.0f} 행/초")
        print("생성된 파일:")
        print("  - processed_data/kisti_quick_train.csv")
        print("  - processed_data/kisti_quick_val.csv")
        print("  - processed_data/kisti_quick_test.csv")
        
        return True
        
    except MemoryError:
        print("❌ 메모리 부족: 파일이 너무 큼")
        print("대안: 청크 기반 샘플링 필요")
        return False
        
    except Exception as e:
        print(f"❌ 처리 실패: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    quick_kisti_sampling()
