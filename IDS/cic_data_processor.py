#!/usr/bin/env python3
"""
CIC-IDS-2017 데이터 통합 및 전처리 시스템
IPS 시스템용 train/test 분리 및 레이블 변환
"""

import pandas as pd
import numpy as np
import os
import glob
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import hashlib
import warnings
warnings.filterwarnings('ignore')

class CICDataProcessor:
    """CIC-IDS-2017 데이터 전처리 및 분리 시스템"""
    
    def __init__(self, data_dir="../CIC-IDS- 2017", output_dir="processed_data"):
        self.data_dir = data_dir
        self.output_dir = output_dir
        self.file_mapping = {
            'Monday': 'Monday-WorkingHours.pcap_ISCX.csv',
            'Tuesday': 'Tuesday-WorkingHours.pcap_ISCX.csv', 
            'Wednesday': 'Wednesday-workingHours.pcap_ISCX.csv',
            'Thursday_AM': 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
            'Thursday_PM': 'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
            'Friday_AM': 'Friday-WorkingHours-Morning.pcap_ISCX.csv',
            'Friday_PM_PortScan': 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
            'Friday_PM_DDoS': 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
        }
        
        # 출력 디렉토리 생성
        os.makedirs(output_dir, exist_ok=True)
        
        print("CIC-IDS-2017 데이터 프로세서 초기화 완료")
    
    def load_and_analyze_all(self):
        """모든 파일 로드 및 기본 분석"""
        print("=== 전체 데이터셋 분석 시작 ===")
        
        all_stats = {}
        
        for day, filename in self.file_mapping.items():
            filepath = os.path.join(self.data_dir, filename)
            
            if not os.path.exists(filepath):
                print(f"⚠️ 파일 없음: {filename}")
                continue
                
            print(f"\n--- {day} 분석 중 ---")
            
            # 파일 크기 확인
            file_size = os.path.getsize(filepath) / (1024*1024)  # MB
            print(f"파일 크기: {file_size:.1f}MB")
            
            # 샘플 로드 (메모리 절약을 위해)
            try:
                df_sample = pd.read_csv(filepath, nrows=1000)
                df_sample.columns = df_sample.columns.str.strip()  # 컬럼명 공백 제거
                
                # 전체 행 수 추정
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    total_lines = sum(1 for line in f) - 1  # 헤더 제외
                
                # 레이블 분포 분석 (전체 파일) - 컬럼명 공백 처리
                df_labels = pd.read_csv(filepath, usecols=[' Label'])  # 앞에 공백 있음
                df_labels.columns = df_labels.columns.str.strip()  # 공백 제거
                label_dist = df_labels['Label'].value_counts()
                
                stats = {
                    'file_size_mb': file_size,
                    'total_samples': total_lines,
                    'columns': len(df_sample.columns),
                    'label_distribution': label_dist.to_dict(),
                    'attack_ratio': (total_lines - label_dist.get('BENIGN', 0)) / total_lines
                }
                
                all_stats[day] = stats
                
                print(f"총 샘플: {total_lines:,}개")
                print(f"컬럼 수: {len(df_sample.columns)}개")
                print("레이블 분포:")
                for label, count in label_dist.items():
                    percentage = (count / total_lines) * 100
                    print(f"  {label}: {count:,}개 ({percentage:.2f}%)")
                
            except Exception as e:
                print(f"파일 {filename} 분석 실패: {e}")
        
        return all_stats
    
    def create_unified_dataset(self, sample_size=None):
        """통합 데이터셋 생성"""
        print("\n=== 통합 데이터셋 생성 시작 ===")
        
        all_dataframes = []
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday_AM', 'Thursday_PM', 
                    'Friday_AM', 'Friday_PM_PortScan', 'Friday_PM_DDoS']
        
        for day in day_order:
            if day not in self.file_mapping:
                continue
                
            filename = self.file_mapping[day]
            filepath = os.path.join(self.data_dir, filename)
            
            if not os.path.exists(filepath):
                print(f"⚠️ 파일 건너뛰기: {filename}")
                continue
            
            print(f"로딩 중: {day}")
            
            try:
                # 메모리 효율적 로딩 - 컬럼명 공백 처리
                if sample_size:
                    df = pd.read_csv(filepath, nrows=sample_size)
                else:
                    df = pd.read_csv(filepath)
                
                # 컬럼명 공백 제거
                df.columns = df.columns.str.strip()
                
                # 날짜 정보 추가
                df['day_of_week'] = day
                df['day_order'] = day_order.index(day)
                
                # 시간 정보 추가 (순서 기반)
                df['time_sequence'] = range(len(all_dataframes) * 10000, 
                                          len(all_dataframes) * 10000 + len(df))
                
                all_dataframes.append(df)
                print(f"  로딩 완료: {len(df):,}행")
                
            except Exception as e:
                print(f"파일 {filename} 로딩 실패: {e}")
        
        if not all_dataframes:
            raise Exception("로딩된 데이터가 없습니다")
        
        # 통합 데이터프레임 생성
        print("\n데이터프레임 통합 중...")
        unified_df = pd.concat(all_dataframes, ignore_index=True)
        print(f"통합 완료: {len(unified_df):,}행 × {len(unified_df.columns)}열")
        
        return unified_df
    
    def preprocess_data(self, df):
        """데이터 전처리"""
        print("\n=== 데이터 전처리 시작 ===")
        
        original_size = len(df)
        print(f"원본 데이터: {original_size:,}행")
        
        # 1. 레이블 변환 (protocol_6 → is_malicious)
        print("1. 레이블 변환 중...")
        df['is_malicious'] = (df['Label'] != 'BENIGN').astype(int)
        
        # 공격 유형 매핑
        attack_type_mapping = {
            'BENIGN': 'normal',
            'DDoS': 'ddos',
            'PortScan': 'port_scan', 
            'Bot': 'botnet',
            'DoS Hulk': 'dos',
            'DoS GoldenEye': 'dos',
            'DoS Slowhttptest': 'dos', 
            'DoS slowloris': 'dos',
            'FTP-Patator': 'brute_force',
            'SSH-Patator': 'brute_force',
            'Web Attack – Brute Force': 'web_attack',
            'Web Attack – XSS': 'web_attack',
            'Web Attack – Sql Injection': 'web_attack',
            'Infiltration': 'infiltration',
            'Heartbleed': 'vulnerability_exploit'
        }
        
        df['attack_type'] = df['Label'].map(attack_type_mapping).fillna('unknown')
        
        # 2. 중복 제거
        print("2. 중복 데이터 제거 중...")
        
        # 5-튜플 기반 중복 확인을 위한 컬럼 확인
        # CIC-IDS-2017은 플로우 기반이므로 이미 5-튜플이 고려됨
        
        # 완전 중복 행 제거
        before_dedup = len(df)
        df = df.drop_duplicates()
        after_dedup = len(df)
        removed_duplicates = before_dedup - after_dedup
        print(f"  완전 중복 제거: {removed_duplicates:,}개 ({removed_duplicates/before_dedup*100:.2f}%)")
        
        # 3. 결측값 및 무한값 처리
        print("3. 결측값/무한값 처리 중...")
        
        # 무한값을 NaN으로 변환
        df = df.replace([np.inf, -np.inf], np.nan)
        
        # 결측값 통계
        missing_counts = df.isnull().sum()
        missing_cols = missing_counts[missing_counts > 0]
        
        if len(missing_cols) > 0:
            print(f"  결측값 있는 컬럼: {len(missing_cols)}개")
            
            # 수치형 컬럼은 중앙값으로 대체
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            for col in missing_cols.index:
                if col in numeric_cols:
                    median_val = df[col].median()
                    df[col].fillna(median_val, inplace=True)
                    print(f"    {col}: 중앙값({median_val:.2f})으로 대체")
        else:
            print("  결측값 없음")
        
        # 4. 데이터 타입 최적화
        print("4. 데이터 타입 최적화 중...")
        
        # 정수형 최적화
        int_cols = df.select_dtypes(include=['int64']).columns
        for col in int_cols:
            col_min = df[col].min()
            col_max = df[col].max()
            
            if col_min >= 0:  # 양수만
                if col_max < 255:
                    df[col] = df[col].astype('uint8')
                elif col_max < 65535:
                    df[col] = df[col].astype('uint16')
                elif col_max < 4294967295:
                    df[col] = df[col].astype('uint32')
            else:  # 음수 포함
                if col_min >= -128 and col_max < 127:
                    df[col] = df[col].astype('int8')
                elif col_min >= -32768 and col_max < 32767:
                    df[col] = df[col].astype('int16')
                elif col_min >= -2147483648 and col_max < 2147483647:
                    df[col] = df[col].astype('int32')
        
        # 실수형 최적화
        float_cols = df.select_dtypes(include=['float64']).columns
        for col in float_cols:
            df[col] = pd.to_numeric(df[col], downcast='float')
        
        print(f"전처리 완료: {len(df):,}행 (제거: {original_size - len(df):,}행)")
        
        return df
    
    def create_train_test_split(self, df, test_ratio=0.2, val_ratio=0.1):
        """시간 기반 train/test/validation 분리"""
        print("\n=== 시간 기반 데이터 분리 시작 ===")
        
        # 시간 순서 기반 분리 (데이터 누수 방지)
        df_sorted = df.sort_values('time_sequence').reset_index(drop=True)
        
        total_size = len(df_sorted)
        
        # 분리 지점 계산
        train_end = int(total_size * (1 - test_ratio - val_ratio))
        val_end = int(total_size * (1 - test_ratio))
        
        # 데이터 분리
        train_df = df_sorted.iloc[:train_end].copy()
        val_df = df_sorted.iloc[train_end:val_end].copy()
        test_df = df_sorted.iloc[val_end:].copy()
        
        print(f"분리 결과:")
        print(f"  Train: {len(train_df):,}행 ({len(train_df)/total_size*100:.1f}%)")
        print(f"  Validation: {len(val_df):,}행 ({len(val_df)/total_size*100:.1f}%)")
        print(f"  Test: {len(test_df):,}행 ({len(test_df)/total_size*100:.1f}%)")
        
        # 각 세트의 클래스 분포 확인
        for name, subset in [('Train', train_df), ('Validation', val_df), ('Test', test_df)]:
            attack_ratio = subset['is_malicious'].mean()
            print(f"  {name} 공격 비율: {attack_ratio:.3f}")
            
            # 공격 유형 분포
            attack_types = subset[subset['is_malicious']==1]['attack_type'].value_counts()
            if len(attack_types) > 0:
                print(f"    주요 공격: {dict(attack_types.head(3))}")
        
        return train_df, val_df, test_df
    
    def remove_duplicates_advanced(self, df):
        """고급 중복 제거 (5-튜플 + 타임윈도)"""
        print("\n=== 고급 중복 제거 시작 ===")
        
        original_size = len(df)
        
        # CIC-IDS-2017은 플로우 기반이므로 이미 5-튜플이 고려됨
        # 하지만 추가적인 중복 제거 수행
        
        # 1. Flow Duration이 매우 짧은 중복성 높은 플로우 제거
        short_flows = df['Flow Duration'] < 1000  # 1ms 미만
        if short_flows.sum() > 0:
            print(f"  초단시간 플로우 제거: {short_flows.sum():,}개")
            df = df[~short_flows]
        
        # 2. 동일한 통계 특성을 가진 플로우 제거 (해시 기반)
        # 주요 플로우 특성으로 해시 생성
        hash_columns = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
                       'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
                       'Flow Bytes/s', 'Flow Packets/s']
        
        # 해시 컬럼들이 존재하는지 확인
        existing_hash_cols = [col for col in hash_columns if col in df.columns]
        
        if existing_hash_cols:
            # 해시 생성
            df['flow_hash'] = df[existing_hash_cols].apply(
                lambda row: hashlib.md5(str(tuple(row.values)).encode()).hexdigest()[:8], 
                axis=1
            )
            
            # 해시 기반 중복 제거 (같은 레이블 내에서만)
            before_hash_dedup = len(df)
            df = df.drop_duplicates(subset=['flow_hash', 'Label'], keep='first')
            after_hash_dedup = len(df)
            
            print(f"  플로우 해시 중복 제거: {before_hash_dedup - after_hash_dedup:,}개")
            
            # 해시 컬럼 제거
            df = df.drop('flow_hash', axis=1)
        
        total_removed = original_size - len(df)
        print(f"총 제거: {total_removed:,}개 ({total_removed/original_size*100:.2f}%)")
        
        return df
    
    def balance_classes(self, train_df, strategy='weighted'):
        """클래스 불균형 처리"""
        print("\n=== 클래스 불균형 처리 ===")
        
        # 현재 분포 확인
        class_dist = train_df['is_malicious'].value_counts()
        total = len(train_df)
        
        print("현재 클래스 분포:")
        print(f"  정상: {class_dist.get(0, 0):,}개 ({class_dist.get(0, 0)/total*100:.2f}%)")
        print(f"  공격: {class_dist.get(1, 0):,}개 ({class_dist.get(1, 0)/total*100:.2f}%)")
        
        imbalance_ratio = class_dist.get(0, 0) / max(class_dist.get(1, 1), 1)
        print(f"불균형 비율: {imbalance_ratio:.1f}:1")
        
        if strategy == 'weighted':
            # 가중치 계산 (class_weight='balanced' 방식)
            n_samples = len(train_df)
            n_classes = 2
            
            weights = {}
            for class_label in [0, 1]:
                n_samples_class = class_dist.get(class_label, 1)
                weights[class_label] = n_samples / (n_classes * n_samples_class)
            
            print(f"계산된 가중치: {weights}")
            return train_df, weights
            
        elif strategy == 'undersample':
            # 언더샘플링 (시간 일관성 유지)
            min_class_size = min(class_dist.values())
            target_size = min(min_class_size * 3, class_dist.get(0, 0))  # 최대 3:1 비율
            
            # 정상 데이터 언더샘플링 (시간 순서 유지하며 균등 선택)
            normal_df = train_df[train_df['is_malicious'] == 0]
            attack_df = train_df[train_df['is_malicious'] == 1]
            
            # 시간 순서 유지하며 균등 선택
            step_size = len(normal_df) // target_size
            selected_indices = range(0, len(normal_df), step_size)[:target_size]
            sampled_normal = normal_df.iloc[selected_indices]
            
            balanced_df = pd.concat([sampled_normal, attack_df], ignore_index=True)
            balanced_df = balanced_df.sort_values('time_sequence').reset_index(drop=True)
            
            print(f"언더샘플링 결과: {len(balanced_df):,}행")
            print(f"  정상: {len(sampled_normal):,}개")
            print(f"  공격: {len(attack_df):,}개")
            
            return balanced_df, None
        
        return train_df, None
    
    def save_processed_data(self, train_df, val_df, test_df, class_weights=None):
        """전처리된 데이터 저장"""
        print("\n=== 전처리 데이터 저장 ===")
        
        # 저장할 컬럼 선택 (중요한 특성만)
        # 시간 관련 임시 컬럼 제거
        columns_to_remove = ['day_of_week', 'day_order', 'time_sequence', 'Label']
        
        for dataset_name, dataset in [('train', train_df), ('val', val_df), ('test', test_df)]:
            # 임시 컬럼 제거
            clean_dataset = dataset.drop(columns=[col for col in columns_to_remove if col in dataset.columns])
            
            # 저장
            output_path = os.path.join(self.output_dir, f"cic_ids_2017_{dataset_name}.csv")
            clean_dataset.to_csv(output_path, index=False)
            
            print(f"  {dataset_name.upper()}: {output_path} ({len(clean_dataset):,}행)")
            
            # 클래스 분포 저장 - JSON 직렬화 가능하도록 타입 변환
            attack_type_counts = clean_dataset['attack_type'].value_counts()
            class_info = {
                'total_samples': int(len(clean_dataset)),
                'benign_samples': int((clean_dataset['is_malicious'] == 0).sum()),
                'attack_samples': int((clean_dataset['is_malicious'] == 1).sum()),
                'attack_types': {str(k): int(v) for k, v in attack_type_counts.to_dict().items()}
            }
            
            info_path = os.path.join(self.output_dir, f"cic_ids_2017_{dataset_name}_info.json")
            import json
            with open(info_path, 'w') as f:
                json.dump(class_info, f, indent=2)
        
        # 클래스 가중치 저장 - JSON 직렬화 타입 변환
        if class_weights:
            weights_path = os.path.join(self.output_dir, "class_weights.json")
            import json
            # numpy 타입을 Python 기본 타입으로 변환
            serializable_weights = {str(k): float(v) for k, v in class_weights.items()}
            with open(weights_path, 'w') as f:
                json.dump(serializable_weights, f, indent=2)
            print(f"  클래스 가중치: {weights_path}")
        
        # 전체 요약 저장 - JSON 직렬화 가능하도록 타입 변환
        summary = {
            'dataset_name': 'CIC-IDS-2017',
            'processing_date': datetime.now().isoformat(),
            'total_samples': int(len(train_df) + len(val_df) + len(test_df)),
            'train_samples': int(len(train_df)),
            'val_samples': int(len(val_df)), 
            'test_samples': int(len(test_df)),
            'features_count': int(len(clean_dataset.columns) - 2),  # is_malicious, attack_type 제외
            'attack_types': sorted([str(x) for x in train_df['attack_type'].unique().tolist()]),
            'class_weights': {str(k): float(v) for k, v in class_weights.items()} if class_weights else None
        }
        
        summary_path = os.path.join(self.output_dir, "dataset_summary.json")
        import json
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"  데이터셋 요약: {summary_path}")

def main():
    """메인 실행 함수"""
    print("CIC-IDS-2017 데이터 전처리 시작")
    print("=" * 60)
    
    try:
        # 프로세서 초기화
        processor = CICDataProcessor()
        
        # 1. 전체 데이터 분석
        stats = processor.load_and_analyze_all()
        
        # 2. 통합 데이터셋 생성 (메모리 절약을 위해 샘플링)
        # 개발/테스트용으로 각 파일당 10만 행씩만 로드
        print(f"\n개발용 샘플링 모드로 실행 중...")
        unified_df = processor.create_unified_dataset(sample_size=100000)
        
        # 3. 데이터 전처리
        processed_df = processor.preprocess_data(unified_df)
        
        # 4. 고급 중복 제거
        deduplicated_df = processor.remove_duplicates_advanced(processed_df)
        
        # 5. train/test/validation 분리
        train_df, val_df, test_df = processor.create_train_test_split(deduplicated_df)
        
        # 6. 클래스 불균형 처리
        balanced_train_df, class_weights = processor.balance_classes(train_df, strategy='weighted')
        
        # 7. 처리된 데이터 저장
        processor.save_processed_data(balanced_train_df, val_df, test_df, class_weights)
        
        print("\n=== 전처리 완료 ===")
        print("다음 단계: RF 모델 재학습 (is_malicious 타겟)")
        print("생성된 파일:")
        print("  - processed_data/cic_ids_2017_train.csv")
        print("  - processed_data/cic_ids_2017_val.csv") 
        print("  - processed_data/cic_ids_2017_test.csv")
        print("  - processed_data/dataset_summary.json")
        
    except Exception as e:
        print(f"전처리 중 오류: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

