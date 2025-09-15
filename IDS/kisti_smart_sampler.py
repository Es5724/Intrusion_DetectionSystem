#!/usr/bin/env python3
"""
KISTI 스마트 샘플링 처리기
5GB 전체 처리 대신 대표 샘플링으로 효율적 처리
"""

import pandas as pd
import numpy as np
import os
import time
import logging
from datetime import datetime

class KISTISmartSampler:
    """KISTI 데이터 스마트 샘플링 처리기"""
    
    def __init__(self, data_path="../data_set/training_set.csv", output_dir="processed_data"):
        self.data_path = data_path
        self.output_dir = output_dir
        
        os.makedirs(output_dir, exist_ok=True)
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger('KISTISampler')
        
        print("KISTI 스마트 샘플링 처리기 초기화 완료")
    
    def create_representative_sample(self, target_samples=500000, sample_ratio=0.1):
        """대표 샘플 생성 (전체 처리 대신)"""
        print("=== KISTI 스마트 샘플링 시작 ===")
        print(f"목표 샘플: {target_samples:,}개 (전체의 약 {sample_ratio*100:.1f}%)")
        
        try:
            # 1. 파일 크기 확인
            file_size = os.path.getsize(self.data_path)
            print(f"파일 크기: {file_size / (1024**3):.2f}GB")
            
            # 2. 전체 행 수 추정
            sample_df = pd.read_csv(self.data_path, nrows=1000, sep='\t')
            avg_row_size = file_size / len(sample_df) * 1000
            estimated_total_rows = int(file_size / avg_row_size)
            print(f"추정 전체 행 수: {estimated_total_rows:,}개")
            
            # 3. 스마트 샘플링 전략
            if target_samples >= estimated_total_rows:
                print("목표 샘플이 전체보다 크므로 전체 처리")
                return self._process_all_data()
            
            # 4. 랜덤 샘플링
            print("랜덤 샘플링 적용...")
            sample_indices = np.random.choice(
                estimated_total_rows, 
                size=min(target_samples, estimated_total_rows), 
                replace=False
            )
            sample_indices = np.sort(sample_indices)  # 순서대로 정렬
            
            # 5. 효율적 샘플 추출
            sampled_data = self._extract_samples(sample_indices)
            
            if sampled_data is None or len(sampled_data) == 0:
                print("샘플링 실패")
                return None
            
            print(f"샘플링 완료: {len(sampled_data):,}행")
            
            # 6. RF 형태로 변환
            rf_data = self._convert_to_rf_format(sampled_data)
            
            return rf_data
            
        except Exception as e:
            print(f"스마트 샘플링 실패: {e}")
            return None
    
    def _extract_samples(self, indices):
        """효율적 샘플 추출"""
        print("효율적 샘플 추출 중...")
        
        sampled_rows = []
        current_index = 0
        chunk_size = 50000  # 큰 청크로 I/O 최소화
        
        try:
            # 청크별로 읽으면서 필요한 행만 추출
            for chunk in pd.read_csv(self.data_path, chunksize=chunk_size, sep='\t'):
                chunk_start = current_index
                chunk_end = current_index + len(chunk)
                
                # 현재 청크에 포함된 샘플 인덱스 찾기
                chunk_indices = indices[(indices >= chunk_start) & (indices < chunk_end)]
                
                if len(chunk_indices) > 0:
                    # 청크 내 상대 인덱스로 변환
                    relative_indices = chunk_indices - chunk_start
                    selected_rows = chunk.iloc[relative_indices]
                    sampled_rows.append(selected_rows)
                    
                    print(f"  청크 {chunk_start//chunk_size + 1}: {len(selected_rows)}개 샘플 추출")
                
                current_index = chunk_end
                
                # 모든 필요한 샘플을 찾았으면 중단
                if current_index > indices.max():
                    break
            
            # 샘플들 통합
            if sampled_rows:
                final_sample = pd.concat(sampled_rows, ignore_index=True)
                return final_sample
            else:
                return pd.DataFrame()
                
        except Exception as e:
            print(f"샘플 추출 실패: {e}")
            return None
    
    def _convert_to_rf_format(self, df):
        """RF 학습 형태로 변환"""
        print("RF 형태로 변환 중...")
        
        try:
            rf_features = pd.DataFrame()
            
            # 기본 특성들 (안전한 변환)
            rf_features['source'] = df['sourceIP'].astype(str) if 'sourceIP' in df.columns else 'unknown'
            rf_features['destination'] = df['destinationIP'].astype(str) if 'destinationIP' in df.columns else 'unknown'
            rf_features['source_port'] = pd.to_numeric(df['sourcePort'], errors='coerce').fillna(0) if 'sourcePort' in df.columns else 0
            rf_features['dest_port'] = pd.to_numeric(df['destinationPort'], errors='coerce').fillna(0) if 'destinationPort' in df.columns else 0
            rf_features['protocol'] = df['protocol'].astype(str) if 'protocol' in df.columns else 'unknown'
            rf_features['packet_size'] = pd.to_numeric(df['packetSize'], errors='coerce').fillna(0) if 'packetSize' in df.columns else 0
            
            # 레이블 생성 (analyResult=2 기반)
            if 'analyResult' in df.columns:
                result_values = pd.to_numeric(df['analyResult'], errors='coerce').fillna(0)
                rf_features['is_malicious'] = (result_values == 2).astype(int)
                rf_features['attack_type'] = ['detected_attack' if r == 2 else 'normal' for r in result_values]
            else:
                rf_features['is_malicious'] = 0
                rf_features['attack_type'] = 'normal'
            
            # 데이터 품질 개선
            rf_features = self._improve_quality(rf_features)
            
            return rf_features
            
        except Exception as e:
            print(f"RF 변환 실패: {e}")
            return None
    
    def _improve_quality(self, df):
        """데이터 품질 개선"""
        # 무한값 처리
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        
        # 결측값 처리
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        for col in numeric_cols:
            df[col].fillna(df[col].median(), inplace=True)
        
        string_cols = df.select_dtypes(include=['object']).columns
        for col in string_cols:
            df[col].fillna('unknown', inplace=True)
        
        # 데이터 타입 최적화
        for col in numeric_cols:
            if col in ['source_port', 'dest_port']:
                df[col] = df[col].clip(0, 65535).astype('uint16')
            elif col in ['packet_size']:
                df[col] = df[col].clip(0, None).astype('uint32')
            elif col in ['is_malicious']:
                df[col] = df[col].clip(0, 1).astype('uint8')
        
        return df
    
    def create_train_test_split(self, df):
        """간단한 train/test 분리"""
        print("Train/Test 분리 중...")
        
        # 시간 기반 분리 (가능한 경우)
        if 'detectStart' in df.columns:
            df_sorted = df.sort_values('detectStart').reset_index(drop=True)
        else:
            df_sorted = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # 70/15/15 분리
        total_size = len(df_sorted)
        train_end = int(total_size * 0.7)
        val_end = int(total_size * 0.85)
        
        train_df = df_sorted.iloc[:train_end].copy()
        val_df = df_sorted.iloc[train_end:val_end].copy()
        test_df = df_sorted.iloc[val_end:].copy()
        
        # 클래스 분포 확인
        for name, subset in [('Train', train_df), ('Val', val_df), ('Test', test_df)]:
            if 'is_malicious' in subset.columns:
                attack_ratio = subset['is_malicious'].mean()
                print(f"  {name}: {len(subset):,}행, 공격 비율: {attack_ratio:.3f}")
        
        return train_df, val_df, test_df
    
    def save_data(self, train_df, val_df, test_df):
        """데이터 저장"""
        print("데이터 저장 중...")
        
        # 저장할 컬럼 선택
        save_columns = [col for col in train_df.columns if col not in ['detectStart', 'detectEnd']]
        
        for name, df in [('train', train_df), ('val', val_df), ('test', test_df)]:
            output_path = os.path.join(self.output_dir, f"kisti_smart_{name}.csv")
            df[save_columns].to_csv(output_path, index=False)
            print(f"  {name.upper()}: {output_path} ({len(df):,}행)")

def main():
    """메인 실행"""
    print("KISTI 스마트 샘플링 처리 시작")
    print("=" * 50)
    
    try:
        sampler = KISTISmartSampler()
        
        # 스마트 샘플링 (50만개)
        start_time = time.time()
        sampled_data = sampler.create_representative_sample(target_samples=500000)
        
        if sampled_data is None or len(sampled_data) == 0:
            print("샘플링 실패")
            return
        
        # Train/Test 분리
        train_df, val_df, test_df = sampler.create_train_test_split(sampled_data)
        
        # 저장
        sampler.save_data(train_df, val_df, test_df)
        
        elapsed_time = time.time() - start_time
        print(f"\n=== 스마트 샘플링 완료 ===")
        print(f"처리 시간: {elapsed_time/60:.1f}분")
        print(f"처리 효율: {len(sampled_data)/elapsed_time:.0f} 행/초")
        print("다음 단계: RF 모델 학습")
        
    except Exception as e:
        print(f"처리 실패: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
