#!/usr/bin/env python3
"""
KISTI-IDS-2022 데이터셋 전용 분석기 및 전처리기
5GB 대용량 데이터 효율적 처리, RF 학습용 데이터 생성
"""

import pandas as pd
import numpy as np
import os
import time
import logging
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import hashlib
import warnings
warnings.filterwarnings('ignore')

class KISTIDataProcessor:
    """KISTI-IDS-2022 데이터셋 전용 처리기"""
    
    def __init__(self, data_path="../data_set/training_set.csv", output_dir="processed_data"):
        self.data_path = data_path
        self.output_dir = output_dir
        
        # KISTI 데이터 구조 정의
        self.kisti_columns = [
            'uid', 'sourceIP', 'destinationIP', 'sourcePort', 'destinationPort',
            'protocol', 'directionType', 'jumboPayloadFlag', 'packetSize',
            'detectName', 'attackType', 'detectStart', 'detectEnd', 'orgIDX',
            'eventCount', 'analyResult', 'payload'
        ]
        
        # 출력 디렉토리 생성
        os.makedirs(output_dir, exist_ok=True)
        
        # 로깅 설정
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger('KISTIProcessor')
        
        print("KISTI-IDS-2022 데이터 프로세서 초기화 완료")
    
    def analyze_data_structure(self, sample_size=10000):
        """KISTI 데이터 구조 분석 (샘플링 기반)"""
        print("=== KISTI-IDS-2022 데이터 구조 분석 ===")
        
        try:
            # 파일 크기 확인
            file_size_bytes = os.path.getsize(self.data_path)
            file_size_gb = file_size_bytes / (1024**3)
            print(f"파일 크기: {file_size_gb:.2f}GB")
            
            # 전체 행 수 추정 (첫 1000행으로 추정)
            print("전체 행 수 추정 중...")
            # 탭 구분자로 시도
            try:
                sample_df = pd.read_csv(self.data_path, nrows=1000, sep='\t')
                print("✅ 탭 구분자로 파싱 성공")
            except:
                # 공백 구분자로 시도
                try:
                    sample_df = pd.read_csv(self.data_path, nrows=1000, sep=' ', skipinitialspace=True)
                    print("✅ 공백 구분자로 파싱 성공")
                except:
                    # 기본 쉼표 구분자
                    sample_df = pd.read_csv(self.data_path, nrows=1000)
                    print("✅ 쉼표 구분자로 파싱")
            avg_row_size = file_size_bytes / len(sample_df) * 1000
            estimated_total_rows = int(file_size_bytes / avg_row_size)
            print(f"추정 전체 행 수: {estimated_total_rows:,}개")
            
            # 헤더 분석
            print(f"컬럼 수: {len(sample_df.columns)}개")
            print("컬럼 목록:")
            for i, col in enumerate(sample_df.columns, 1):
                print(f"  {i:2d}. {col}")
            
            # 샘플 데이터로 상세 분석
            print(f"\n샘플 데이터 분석 ({sample_size}행)...")
            analysis_df = pd.read_csv(self.data_path, nrows=sample_size)
            
            return self._analyze_sample_data(analysis_df, estimated_total_rows)
            
        except Exception as e:
            print(f"데이터 분석 실패: {e}")
            return None
    
    def _analyze_sample_data(self, df, total_rows):
        """샘플 데이터 상세 분석"""
        analysis_result = {
            'total_estimated_rows': total_rows,
            'sample_size': len(df),
            'columns': list(df.columns),
            'column_count': len(df.columns)
        }
        
        # 1. 레이블 분석 (attackType, analyResult)
        print("\n=== 레이블 분석 ===")
        
        if 'attackType' in df.columns:
            attack_dist = df['attackType'].value_counts()
            analysis_result['attack_type_distribution'] = attack_dist.to_dict()
            
            print("공격 유형 분포:")
            for attack_type, count in attack_dist.head(10).items():
                percentage = (count / len(df)) * 100
                print(f"  {attack_type}: {count}개 ({percentage:.2f}%)")
        
        if 'analyResult' in df.columns:
            result_dist = df['analyResult'].value_counts()
            analysis_result['analysis_result_distribution'] = result_dist.to_dict()
            
            print("\n분석 결과 분포:")
            for result, count in result_dist.items():
                percentage = (count / len(df)) * 100
                print(f"  {result}: {count}개 ({percentage:.2f}%)")
        
        # 2. 데이터 품질 분석
        print("\n=== 데이터 품질 분석 ===")
        
        # 결측값 확인
        missing_counts = df.isnull().sum()
        missing_cols = missing_counts[missing_counts > 0]
        if len(missing_cols) > 0:
            print(f"결측값 있는 컬럼: {len(missing_cols)}개")
            analysis_result['missing_values'] = missing_cols.to_dict()
        else:
            print("결측값: 없음")
            analysis_result['missing_values'] = {}
        
        # 중복 확인
        duplicates = df.duplicated().sum()
        duplicate_percentage = (duplicates / len(df)) * 100
        print(f"중복 행: {duplicates}개 ({duplicate_percentage:.2f}%)")
        analysis_result['duplicates'] = duplicates
        
        # 3. 네트워크 특성 분석
        print("\n=== 네트워크 특성 분석 ===")
        
        if 'protocol' in df.columns:
            protocol_dist = df['protocol'].value_counts()
            print("프로토콜 분포:")
            for protocol, count in protocol_dist.head(5).items():
                percentage = (count / len(df)) * 100
                print(f"  {protocol}: {count}개 ({percentage:.2f}%)")
        
        if 'packetSize' in df.columns:
            packet_stats = df['packetSize'].describe()
            print(f"\n패킷 크기 통계:")
            print(f"  평균: {packet_stats['mean']:.1f} bytes")
            print(f"  최대: {packet_stats['max']:.0f} bytes")
            print(f"  최소: {packet_stats['min']:.0f} bytes")
        
        # 4. 시간 정보 분석
        if 'detectStart' in df.columns and 'detectEnd' in df.columns:
            print("\n시간 기반 분리 가능성: ✅")
            analysis_result['time_based_split'] = True
        else:
            print("\n시간 기반 분리: ❌ (시간 컬럼 없음)")
            analysis_result['time_based_split'] = False
        
        return analysis_result
    
    def create_rf_training_data(self, chunk_size=50000, max_samples=500000):
        """RF 학습용 데이터 생성 (메모리 효율적)"""
        print("=== KISTI → RF 학습 데이터 변환 ===")
        print(f"📋 처리 계획: 최대 {max_samples:,}개 샘플, 청크 크기: {chunk_size:,}개")
        print(f"📁 파일 크기: {os.path.getsize(self.data_path) / (1024**3):.2f}GB")
        
        try:
            processed_chunks = []
            total_processed = 0
            
            # 예상 청크 수 계산
            file_size = os.path.getsize(self.data_path)
            estimated_total_rows = file_size // 100  # 대략적 추정
            max_chunks = min(max_samples // chunk_size, estimated_total_rows // chunk_size)
            
            print(f"📊 예상 처리: 최대 {max_chunks}개 청크")
            
            # 청크 단위로 데이터 처리 (구분자 자동 감지)
            try:
                chunk_iter = pd.read_csv(self.data_path, chunksize=chunk_size, sep='\t')
                print("📄 탭 구분자로 청크 처리")
            except:
                try:
                    chunk_iter = pd.read_csv(self.data_path, chunksize=chunk_size, sep=' ', skipinitialspace=True)
                    print("📄 공백 구분자로 청크 처리")
                except:
                    chunk_iter = pd.read_csv(self.data_path, chunksize=chunk_size)
                    print("📄 쉼표 구분자로 청크 처리")
            
            start_time = time.time()
            
            for i, chunk in enumerate(chunk_iter):
                if total_processed >= max_samples:
                    break
                
                # 진행률 계산
                progress_percentage = (total_processed / max_samples) * 100
                elapsed_time = time.time() - start_time
                
                if i > 0:  # 첫 번째 청크 이후
                    avg_time_per_chunk = elapsed_time / i
                    remaining_chunks = (max_samples - total_processed) / chunk_size
                    eta_seconds = remaining_chunks * avg_time_per_chunk
                    eta_minutes = eta_seconds / 60
                    
                    print(f"📊 청크 {i+1} 처리 중... ({len(chunk)}행)")
                    print(f"   진행률: {progress_percentage:.1f}% | 경과시간: {elapsed_time/60:.1f}분 | 예상완료: {eta_minutes:.1f}분 후")
                else:
                    print(f"📊 청크 {i+1} 처리 중... ({len(chunk)}행)")
                    print(f"   진행률: {progress_percentage:.1f}% | 시작 단계")
                
                # KISTI → RF 형태로 변환
                processed_chunk = self._convert_kisti_to_rf_format(chunk)
                
                if processed_chunk is not None and len(processed_chunk) > 0:
                    processed_chunks.append(processed_chunk)
                    total_processed += len(processed_chunk)
                    
                    # 성공률 계산
                    success_rate = (len(processed_chunk) / len(chunk)) * 100
                    print(f"   ✅ 변환 완료: {len(processed_chunk)}행 (성공률: {success_rate:.1f}%) | 누적: {total_processed:,}행")
                else:
                    print(f"   ❌ 변환 실패: 청크 {i+1}")
                
                # 10청크마다 상세 진행 상황
                if (i + 1) % 10 == 0:
                    memory_usage = total_processed * 0.001  # 추정 메모리 MB
                    print(f"🔄 중간 체크포인트: 청크 {i+1}개 완료")
                    print(f"   처리 속도: {total_processed/elapsed_time:.0f} 행/초")
                    print(f"   메모리 사용 추정: {memory_usage:.1f}MB")
                    print(f"   남은 작업: {max_samples - total_processed:,}행")
                    print("   " + "="*50)
                
                # 메모리 관리
                del chunk
                
                if len(processed_chunks) >= 10:  # 10개 청크마다 중간 저장
                    self._save_intermediate_results(processed_chunks, i)
                    processed_chunks = []
            
            # 최종 통합
            if processed_chunks:
                final_df = pd.concat(processed_chunks, ignore_index=True)
            else:
                # 중간 저장된 파일들 통합
                final_df = self._load_intermediate_results()
            
            print(f"최종 처리 완료: {len(final_df)}행")
            
            return final_df
            
        except Exception as e:
            print(f"데이터 처리 실패: {e}")
            return None
    
    def _convert_kisti_to_rf_format(self, chunk):
        """KISTI 데이터를 RF 학습 형태로 변환"""
        try:
            # 1. 기본 네트워크 특성 추출
            rf_features = pd.DataFrame()
            
            # 기본 특성들 (안전한 변환)
            rf_features['source'] = chunk['sourceIP'].astype(str) if 'sourceIP' in chunk.columns else 'unknown'
            rf_features['destination'] = chunk['destinationIP'].astype(str) if 'destinationIP' in chunk.columns else 'unknown'
            
            # 포트 번호 (안전한 숫자 변환)
            rf_features['source_port'] = pd.to_numeric(chunk['sourcePort'], errors='coerce').fillna(0) if 'sourcePort' in chunk.columns else 0
            rf_features['dest_port'] = pd.to_numeric(chunk['destinationPort'], errors='coerce').fillna(0) if 'destinationPort' in chunk.columns else 0
            
            rf_features['protocol'] = chunk['protocol'].astype(str) if 'protocol' in chunk.columns else 'unknown'
            rf_features['packet_size'] = pd.to_numeric(chunk['packetSize'], errors='coerce').fillna(0) if 'packetSize' in chunk.columns else 0
            rf_features['event_count'] = pd.to_numeric(chunk['eventCount'], errors='coerce').fillna(1) if 'eventCount' in chunk.columns else 1
            
            # 2. 레이블 생성 (KISTI → RF 형태)
            rf_features['is_malicious'] = self._create_is_malicious_label(chunk)
            rf_features['attack_type'] = self._create_attack_type_label(chunk)
            
            # 3. 추가 특성 생성 (CIC 스타일)
            rf_features['flow_duration'] = self._calculate_flow_duration(chunk)
            rf_features['direction_type'] = chunk['directionType'] if 'directionType' in chunk.columns else 0
            rf_features['jumbo_flag'] = chunk['jumboPayloadFlag'] if 'jumboPayloadFlag' in chunk.columns else 0
            
            # 4. 데이터 품질 개선
            rf_features = self._improve_data_quality(rf_features)
            
            return rf_features
            
        except Exception as e:
            self.logger.error(f"데이터 변환 실패: {e}")
            return None
    
    def _create_is_malicious_label(self, chunk):
        """KISTI 데이터에서 is_malicious 레이블 생성"""
        if 'analyResult' in chunk.columns:
            # analyResult=2를 공격으로 해석 (KISTI 실제 분포 기반)
            result_values = pd.to_numeric(chunk['analyResult'], errors='coerce').fillna(0)
            return (result_values == 2).astype(int)  # 2 = 공격 탐지됨
        elif 'attackType' in chunk.columns:
            # attackType 기반 (보조)
            attack_values = pd.to_numeric(chunk['attackType'], errors='coerce').fillna(0)
            return (attack_values != 0).astype(int)  # 0 = Normal, 1+ = 공격
        else:
            # 기본값: 모두 정상으로 처리
            return pd.Series([0] * len(chunk))
    
    def _create_attack_type_label(self, chunk):
        """KISTI 데이터에서 attack_type 레이블 생성"""
        # analyResult=2인 경우 특정 공격으로 분류
        if 'analyResult' in chunk.columns:
            result_values = pd.to_numeric(chunk['analyResult'], errors='coerce').fillna(0)
            
            # analyResult=2인 경우 detectName으로 공격 유형 추정
            if 'detectName' in chunk.columns:
                # detectName 해시를 기반으로 공격 유형 추정
                attack_types = []
                for i, result in enumerate(result_values):
                    if result == 2:
                        # 실제로는 detectName 해시로 공격 유형 결정
                        # 현재는 간단히 'detected_attack'으로 분류
                        attack_types.append('detected_attack')
                    else:
                        attack_types.append('normal')
                return pd.Series(attack_types)
            else:
                # detectName이 없으면 analyResult만으로 분류
                return pd.Series(['detected_attack' if r == 2 else 'normal' for r in result_values])
        
        elif 'attackType' in chunk.columns:
            # attackType 기반 (보조)
            attack_code_mapping = {
                0: 'normal',                    # Normal
                1: 'dos',                       # DoS
                2: 'port_scan',                 # Port Scanning
                3: 'fuzzing',                   # Fuzzing
                4: 'malware',                   # Malware
                5: 'brute_force',               # Dictionary Attack
                6: 'web_attack',                # Web Hacking
                7: 'brute_force',               # Brute Force
                8: 'infiltration',              # Infiltration
                9: 'web_attack',                # XSS
                10: 'web_attack',               # SQL Injection
                11: 'exploit'                   # Exploit
            }
            
            attack_codes = pd.to_numeric(chunk['attackType'], errors='coerce').fillna(-1)
            mapped_types = attack_codes.map(attack_code_mapping).fillna('unknown')
            return mapped_types
        else:
            return pd.Series(['normal'] * len(chunk))
    
    def _calculate_flow_duration(self, chunk):
        """플로우 지속 시간 계산"""
        if 'detectStart' in chunk.columns and 'detectEnd' in chunk.columns:
            try:
                # 안전한 시간 변환
                start_times = pd.to_datetime(chunk['detectStart'], errors='coerce')
                end_times = pd.to_datetime(chunk['detectEnd'], errors='coerce')
                
                # 유효한 시간 데이터만 계산
                duration = (end_times - start_times).dt.total_seconds()
                return duration.fillna(0)
            except Exception as e:
                self.logger.warning(f"시간 계산 실패: {e}")
                return pd.Series([0] * len(chunk))
        else:
            return pd.Series([0] * len(chunk))
    
    def _improve_data_quality(self, df):
        """데이터 품질 개선"""
        # 1. 결측값 처리
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        for col in numeric_cols:
            df[col].fillna(df[col].median(), inplace=True)
        
        # 문자열 컬럼 결측값 처리
        string_cols = df.select_dtypes(include=['object']).columns
        for col in string_cols:
            df[col].fillna('unknown', inplace=True)
        
        # 2. 무한값 처리 (타입 변환 전)
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        
        # 3. 데이터 타입 최적화 (안전한 변환)
        for col in numeric_cols:
            if col in ['source_port', 'dest_port']:
                # 포트 번호: 0-65535 범위로 클리핑 후 변환
                df[col] = df[col].fillna(0).clip(0, 65535).astype('uint16')
            elif col in ['packet_size', 'event_count']:
                # 양수 값: 0 이상으로 클리핑
                df[col] = df[col].fillna(0).clip(0, None).astype('uint32')
            elif col in ['is_malicious', 'jumbo_flag']:
                # 바이너리 값: 0 또는 1
                df[col] = df[col].fillna(0).clip(0, 1).astype('uint8')
        
        # 3. 이상값 처리
        if 'packet_size' in df.columns:
            # 패킷 크기 이상값 클리핑 (최대 65535)
            df['packet_size'] = df['packet_size'].clip(0, 65535)
        
        return df
    
    def create_advanced_train_test_split(self, df, test_ratio=0.2, val_ratio=0.1):
        """강화된 train/test 분리 (호스트 격리 + 세션 분리 + 누수 방지)"""
        print("\n=== 강화된 Train/Test 분리 ===")
        
        # 1. 호스트 기반 그룹핑
        print("1. 호스트 기반 그룹핑 중...")
        df_with_groups = self._create_host_groups(df)
        
        # 2. 세션 기반 그룹핑
        print("2. 세션 기반 그룹핑 중...")
        df_with_sessions = self._create_session_groups(df_with_groups)
        
        # 3. 특징 누수 점검 및 제거
        print("3. 특징 누수 점검 중...")
        df_clean = self._remove_leaky_features(df_with_sessions)
        
        # 4. 그룹 기반 분리 (호스트/세션 단위)
        print("4. 그룹 기반 데이터 분리 중...")
        train_df, val_df, test_df = self._group_based_split(df_clean, test_ratio, val_ratio)
        
        # 5. 분리 품질 검증
        print("5. 분리 품질 검증 중...")
        self._validate_split_quality(train_df, val_df, test_df)
        
        return train_df, val_df, test_df
    
    def _create_host_groups(self, df):
        """호스트 기반 그룹 생성"""
        # sourceIP와 destinationIP 조합으로 호스트 그룹 생성
        df['host_pair'] = df['source'].astype(str) + "_" + df['destination'].astype(str)
        
        # 호스트 그룹별 통계
        host_stats = df['host_pair'].value_counts()
        print(f"   고유 호스트 쌍: {len(host_stats)}개")
        print(f"   평균 플로우/호스트: {host_stats.mean():.1f}개")
        
        # 주요 호스트 그룹 (상위 10개)
        major_hosts = host_stats.head(10)
        print(f"   주요 호스트 그룹:")
        for host, count in major_hosts.items():
            percentage = (count / len(df)) * 100
            print(f"     {host}: {count}개 ({percentage:.1f}%)")
        
        return df
    
    def _create_session_groups(self, df):
        """세션 기반 그룹 생성"""
        # 5-tuple 기반 세션 식별
        if 'uid' in df.columns:
            # uid가 있으면 그대로 사용
            df['session_id'] = df['uid']
        else:
            # 5-tuple 기반 세션 ID 생성
            df['session_id'] = (
                df['source'].astype(str) + "_" +
                df['destination'].astype(str) + "_" +
                df['source_port'].astype(str) + "_" +
                df['dest_port'].astype(str) + "_" +
                df['protocol'].astype(str)
            )
        
        # 세션 통계
        session_stats = df['session_id'].value_counts()
        print(f"   고유 세션: {len(session_stats)}개")
        print(f"   평균 이벤트/세션: {session_stats.mean():.1f}개")
        
        # 장기 세션 분석 (데이터 누수 위험)
        long_sessions = session_stats[session_stats > 100]
        if len(long_sessions) > 0:
            print(f"   ⚠️ 장기 세션 {len(long_sessions)}개 발견 (100+ 이벤트)")
            print(f"     최대 세션 길이: {session_stats.max()}개 이벤트")
        
        return df
    
    def _remove_leaky_features(self, df):
        """특징 누수 점검 및 제거"""
        print("   특징 누수 분석 중...")
        
        leaky_features = []
        
        # 1. 타겟과 강상관 특징 검사
        if 'is_malicious' in df.columns:
            numeric_features = df.select_dtypes(include=[np.number]).columns
            
            for feature in numeric_features:
                if feature != 'is_malicious':
                    try:
                        correlation = df[feature].corr(df['is_malicious'])
                        if abs(correlation) > 0.95:  # 95% 이상 상관관계
                            leaky_features.append(f"{feature} (상관계수: {correlation:.3f})")
                    except:
                        pass
        
        # 2. 시간 누수 특징 검사
        time_risk_features = ['detectStart', 'detectEnd', 'orgIDX']
        for feature in time_risk_features:
            if feature in df.columns:
                leaky_features.append(f"{feature} (시간 정보 누수)")
        
        # 3. ID 성격 특징 검사
        id_risk_features = ['uid']
        for feature in id_risk_features:
            if feature in df.columns:
                # uid가 순차적이거나 패턴이 있으면 위험
                if df[feature].dtype in ['object', 'int64']:
                    leaky_features.append(f"{feature} (ID 정보 누수)")
        
        # 4. 공격별 고유 특징 검사
        if 'attack_type' in df.columns and 'detectName' in df.columns:
            # detectName이 attack_type과 1:1 매핑되면 누수
            detect_attack_mapping = df.groupby('detectName')['attack_type'].nunique()
            single_mapping = detect_attack_mapping[detect_attack_mapping == 1]
            if len(single_mapping) > 0:
                leaky_features.append(f"detectName (공격 유형 직접 매핑)")
        
        # 누수 특징 제거
        features_to_remove = []
        for leaky_desc in leaky_features:
            feature_name = leaky_desc.split(' ')[0]
            if feature_name in df.columns:
                features_to_remove.append(feature_name)
        
        if features_to_remove:
            print(f"   ⚠️ 누수 위험 특징 제거: {len(features_to_remove)}개")
            for feature in features_to_remove:
                print(f"     - {feature}")
            
            df_clean = df.drop(columns=features_to_remove)
        else:
            print("   ✅ 누수 위험 특징 없음")
            df_clean = df
        
        return df_clean
    
    def _group_based_split(self, df, test_ratio, val_ratio):
        """그룹 기반 데이터 분리 (호스트/세션 단위)"""
        # 호스트 그룹별 분리
        if 'host_pair' in df.columns:
            print("   호스트 그룹 기반 분리 적용")
            return self._split_by_host_groups(df, test_ratio, val_ratio)
        
        # 세션별 분리
        elif 'session_id' in df.columns:
            print("   세션 기반 분리 적용")
            return self._split_by_sessions(df, test_ratio, val_ratio)
        
        # 시간 기반 분리 (기본)
        else:
            print("   시간 기반 분리 적용")
            return self._split_by_time(df, test_ratio, val_ratio)
    
    def _split_by_host_groups(self, df, test_ratio, val_ratio):
        """호스트 그룹별 완전 분리"""
        # 호스트 그룹 목록
        unique_hosts = df['host_pair'].unique()
        np.random.shuffle(unique_hosts)  # 랜덤 섞기
        
        # 그룹별 분리 지점 계산
        n_hosts = len(unique_hosts)
        train_hosts_end = int(n_hosts * (1 - test_ratio - val_ratio))
        val_hosts_end = int(n_hosts * (1 - test_ratio))
        
        # 호스트 그룹 분할
        train_hosts = unique_hosts[:train_hosts_end]
        val_hosts = unique_hosts[train_hosts_end:val_hosts_end]
        test_hosts = unique_hosts[val_hosts_end:]
        
        # 데이터 분리
        train_df = df[df['host_pair'].isin(train_hosts)].copy()
        val_df = df[df['host_pair'].isin(val_hosts)].copy()
        test_df = df[df['host_pair'].isin(test_hosts)].copy()
        
        print(f"   호스트 그룹 분리:")
        print(f"     Train 호스트: {len(train_hosts)}개")
        print(f"     Val 호스트: {len(val_hosts)}개")
        print(f"     Test 호스트: {len(test_hosts)}개")
        
        return train_df, val_df, test_df
    
    def _split_by_sessions(self, df, test_ratio, val_ratio):
        """세션별 완전 분리"""
        # 세션 목록
        unique_sessions = df['session_id'].unique()
        np.random.shuffle(unique_sessions)
        
        # 세션별 분리 지점 계산
        n_sessions = len(unique_sessions)
        train_sessions_end = int(n_sessions * (1 - test_ratio - val_ratio))
        val_sessions_end = int(n_sessions * (1 - test_ratio))
        
        # 세션 분할
        train_sessions = unique_sessions[:train_sessions_end]
        val_sessions = unique_sessions[train_sessions_end:val_sessions_end]
        test_sessions = unique_sessions[val_sessions_end:]
        
        # 데이터 분리
        train_df = df[df['session_id'].isin(train_sessions)].copy()
        val_df = df[df['session_id'].isin(val_sessions)].copy()
        test_df = df[df['session_id'].isin(test_sessions)].copy()
        
        print(f"   세션 기반 분리:")
        print(f"     Train 세션: {len(train_sessions)}개")
        print(f"     Val 세션: {len(val_sessions)}개")
        print(f"     Test 세션: {len(test_sessions)}개")
        
        return train_df, val_df, test_df
    
    def _split_by_time(self, df, test_ratio, val_ratio):
        """시간 기반 분리 (기본)"""
        if 'detectStart' in df.columns:
            df_sorted = df.sort_values('detectStart').reset_index(drop=True)
        else:
            df_sorted = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        total_size = len(df_sorted)
        train_end = int(total_size * (1 - test_ratio - val_ratio))
        val_end = int(total_size * (1 - test_ratio))
        
        train_df = df_sorted.iloc[:train_end].copy()
        val_df = df_sorted.iloc[train_end:val_end].copy()
        test_df = df_sorted.iloc[val_end:].copy()
        
        return train_df, val_df, test_df
    
    def _validate_split_quality(self, train_df, val_df, test_df):
        """분리 품질 검증"""
        print("   분리 품질 검증:")
        
        # 1. 호스트 중복 검사
        if 'host_pair' in train_df.columns:
            train_hosts = set(train_df['host_pair'].unique())
            val_hosts = set(val_df['host_pair'].unique())
            test_hosts = set(test_df['host_pair'].unique())
            
            host_overlap_val = len(train_hosts & val_hosts)
            host_overlap_test = len(train_hosts & test_hosts)
            
            print(f"     호스트 중복: Train-Val {host_overlap_val}개, Train-Test {host_overlap_test}개")
            
            if host_overlap_val == 0 and host_overlap_test == 0:
                print("     ✅ 호스트 완전 분리 확인")
            else:
                print("     ⚠️ 호스트 중복 발견")
        
        # 2. 세션 중복 검사
        if 'session_id' in train_df.columns:
            train_sessions = set(train_df['session_id'].unique())
            val_sessions = set(val_df['session_id'].unique())
            test_sessions = set(test_df['session_id'].unique())
            
            session_overlap_val = len(train_sessions & val_sessions)
            session_overlap_test = len(train_sessions & test_sessions)
            
            print(f"     세션 중복: Train-Val {session_overlap_val}개, Train-Test {session_overlap_test}개")
            
            if session_overlap_val == 0 and session_overlap_test == 0:
                print("     ✅ 세션 완전 분리 확인")
            else:
                print("     ⚠️ 세션 중복 발견")
        
        # 3. 시간 순서 검증
        if 'detectStart' in train_df.columns:
            train_max_time = train_df['detectStart'].max()
            val_min_time = val_df['detectStart'].min()
            test_min_time = test_df['detectStart'].min()
            
            if train_max_time <= val_min_time <= test_min_time:
                print("     ✅ 시간 순서 보장 확인")
            else:
                print("     ⚠️ 시간 순서 역전 발견")
        
        # 4. 클래스 분포 균형 확인
        for name, subset in [('Train', train_df), ('Val', val_df), ('Test', test_df)]:
            if 'is_malicious' in subset.columns:
                attack_ratio = subset['is_malicious'].mean()
                print(f"     {name} 공격 비율: {attack_ratio:.3f}")
                
                if 0.05 <= attack_ratio <= 0.5:  # 5-50% 범위
                    print(f"       ✅ 적절한 클래스 분포")
                else:
                    print(f"       ⚠️ 극단적 클래스 분포")
        
        # 분리 결과 출력
        total_size = len(train_df) + len(val_df) + len(test_df)
        print(f"분리 결과:")
        print(f"  Train: {len(train_df):,}행 ({len(train_df)/total_size*100:.1f}%)")
        print(f"  Validation: {len(val_df):,}행 ({len(val_df)/total_size*100:.1f}%)")
        print(f"  Test: {len(test_df):,}행 ({len(test_df)/total_size*100:.1f}%)")
        
        # 각 세트의 클래스 분포 확인
        for name, subset in [('Train', train_df), ('Validation', val_df), ('Test', test_df)]:
            if 'is_malicious' in subset.columns:
                attack_ratio = subset['is_malicious'].mean()
                print(f"  {name} 공격 비율: {attack_ratio:.3f}")
                
                if attack_ratio > 0:
                    attack_types = subset[subset['is_malicious']==1]['attack_type'].value_counts()
                    if len(attack_types) > 0:
                        print(f"    주요 공격: {dict(attack_types.head(3))}")
        
        return train_df, val_df, test_df
    
    def _save_intermediate_results(self, chunks, batch_num):
        """중간 결과 저장 (메모리 관리)"""
        if chunks:
            intermediate_df = pd.concat(chunks, ignore_index=True)
            filename = os.path.join(self.output_dir, f"kisti_intermediate_batch_{batch_num}.csv")
            intermediate_df.to_csv(filename, index=False)
            print(f"중간 저장: {filename} ({len(intermediate_df)}행)")
            del intermediate_df
    
    def _load_intermediate_results(self):
        """중간 저장된 파일들 통합"""
        intermediate_files = [f for f in os.listdir(self.output_dir) if f.startswith('kisti_intermediate_batch_')]
        
        if not intermediate_files:
            return pd.DataFrame()
        
        print("중간 저장 파일들 통합 중...")
        dfs = []
        for file in intermediate_files:
            file_path = os.path.join(self.output_dir, file)
            df = pd.read_csv(file_path)
            dfs.append(df)
            os.remove(file_path)  # 사용 후 삭제
        
        return pd.concat(dfs, ignore_index=True)
    
    def save_processed_data(self, train_df, val_df, test_df):
        """처리된 데이터 저장"""
        print("\n=== KISTI 전처리 데이터 저장 ===")
        
        # 저장할 컬럼 선택 (RF 학습에 필요한 것만)
        rf_columns = [
            'source', 'destination', 'source_port', 'dest_port', 'protocol',
            'packet_size', 'flow_duration', 'event_count', 'direction_type',
            'jumbo_flag', 'is_malicious', 'attack_type'
        ]
        
        # 실제 존재하는 컬럼만 선택
        available_columns = [col for col in rf_columns if col in train_df.columns]
        
        for dataset_name, dataset in [('train', train_df), ('val', val_df), ('test', test_df)]:
            # RF 학습용 컬럼만 저장
            clean_dataset = dataset[available_columns]
            
            # 저장
            output_path = os.path.join(self.output_dir, f"kisti_ids_2022_{dataset_name}.csv")
            clean_dataset.to_csv(output_path, index=False)
            
            print(f"  {dataset_name.upper()}: {output_path} ({len(clean_dataset):,}행)")
            
            # 클래스 분포 저장
            if 'is_malicious' in clean_dataset.columns:
                attack_ratio = clean_dataset['is_malicious'].mean()
                attack_count = clean_dataset['is_malicious'].sum()
                normal_count = len(clean_dataset) - attack_count
                
                class_info = {
                    'total_samples': int(len(clean_dataset)),
                    'normal_samples': int(normal_count),
                    'attack_samples': int(attack_count),
                    'attack_ratio': float(attack_ratio),
                    'attack_types': clean_dataset['attack_type'].value_counts().to_dict()
                }
                
                info_path = os.path.join(self.output_dir, f"kisti_ids_2022_{dataset_name}_info.json")
                import json
                with open(info_path, 'w') as f:
                    json.dump(class_info, f, indent=2)
        
        # 전체 요약 저장
        summary = {
            'dataset_name': 'KISTI-IDS-2022',
            'processing_date': datetime.now().isoformat(),
            'total_samples': len(train_df) + len(val_df) + len(test_df),
            'train_samples': len(train_df),
            'val_samples': len(val_df),
            'test_samples': len(test_df),
            'features_count': len(available_columns) - 2,  # is_malicious, attack_type 제외
            'available_features': available_columns
        }
        
        summary_path = os.path.join(self.output_dir, "kisti_dataset_summary.json")
        import json
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"  데이터셋 요약: {summary_path}")

def main():
    """메인 실행 함수"""
    print("KISTI-IDS-2022 데이터 처리 시작")
    print("=" * 60)
    
    try:
        # 프로세서 초기화
        processor = KISTIDataProcessor()
        
        # 1. 데이터 구조 분석
        print("1단계: 데이터 구조 분석")
        analysis_result = processor.analyze_data_structure(sample_size=10000)
        
        if analysis_result is None:
            print("데이터 분석 실패")
            return
        
        # 2. RF 학습용 데이터 생성 (샘플링)
        print("\n2단계: RF 학습용 데이터 생성")
        print("빠른 테스트를 위해 10만 샘플로 제한 (성공 후 50만으로 확장)")
        
        processed_df = processor.create_rf_training_data(
            chunk_size=10000,  # 작은 청크로 메모리 절약
            max_samples=100000  # 빠른 테스트를 위해 10만 샘플로 축소
        )
        
        if processed_df is None or len(processed_df) == 0:
            print("데이터 변환 실패")
            return
        
        # 3. 강화된 Train/Test 분리 (호스트/세션 격리 + 누수 방지)
        print("\n3단계: 강화된 Train/Test 분리")
        train_df, val_df, test_df = processor.create_advanced_train_test_split(processed_df)
        
        # 4. 처리된 데이터 저장
        print("\n4단계: 데이터 저장")
        processor.save_processed_data(train_df, val_df, test_df)
        
        print("\n=== KISTI-IDS-2022 전처리 완료 ===")
        print("다음 단계: RF 모델 재학습")
        print("생성된 파일:")
        print("  - processed_data/kisti_ids_2022_train.csv")
        print("  - processed_data/kisti_ids_2022_val.csv")
        print("  - processed_data/kisti_ids_2022_test.csv")
        print("  - processed_data/kisti_dataset_summary.json")
        
    except Exception as e:
        print(f"처리 중 오류: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
