import pandas as pd
import numpy as np
import joblib
import os
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.preprocessing import StandardScaler, LabelEncoder
import gc  # 명시적 가비지 컬렉션용


def train_random_forest(data_path, random_state=42, chunk_size=None):
    """청크 단위 처리를 지원하는 랜덤포레스트 모델 학습 함수"""
    print(f"데이터 파일 로드: {data_path}")
    
    if chunk_size is None or chunk_size <= 0:
        # 기존 방식: 전체 데이터 한 번에 로드
        preprocessed_df = pd.read_csv(data_path)
        return _train_random_forest_internal(preprocessed_df, random_state)
    else:
        # 청크 단위 처리 방식
        print(f"청크 크기 {chunk_size}로 데이터 처리 시작")
        
        # 스케일러와 레이블 인코더 초기화
        scaler = StandardScaler()
        label_encoders = {}
        
        # 초기값 설정
        chunk_count = 0
        all_X_train = []
        all_y_train = []
        all_X_test = []
        all_y_test = []
        
        # 청크 단위로 데이터 처리
        for chunk in pd.read_csv(data_path, chunksize=chunk_size):
            chunk_count += 1
            print(f"청크 {chunk_count} 처리 중 (크기: {len(chunk)})")
            
            # 메모리 최적화를 위해 불필요한 컬럼 제거
            necessary_columns = [col for col in chunk.columns if col in 
                               ['source', 'destination', 'protocol', 'length', 'ttl', 'flags', 'protocol_6']]
            chunk = chunk[necessary_columns]
            
            # 데이터 타입 최적화
            for col in chunk.columns:
                if col == 'length' and chunk[col].dtype != 'int32':
                    chunk[col] = chunk[col].astype('int32')
                elif col == 'ttl' and chunk[col].dtype != 'uint8':
                    chunk[col] = chunk[col].astype('uint8')
            
            # 문자열 데이터를 숫자로 변환
            for column in chunk.columns:
                if chunk[column].dtype == 'object':
                    # 이미 인코더가 생성된 경우 재사용
                    if column not in label_encoders:
                        label_encoders[column] = LabelEncoder()
                        chunk[column] = label_encoders[column].fit_transform(chunk[column].astype(str))
                    else:
                        # 새로운 범주 처리
                        new_categories = list(set(chunk[column].unique()) - 
                                            set(label_encoders[column].classes_))
                        if new_categories:
                            # 기존 인코더에 새로운 범주 추가
                            label_encoders[column].classes_ = np.append(
                                label_encoders[column].classes_, new_categories)
                        
                        # transform 함수로 변환
                        chunk[column] = label_encoders[column].transform(chunk[column].astype(str))
            
            # 특성과 레이블 분리
            if 'protocol_6' in chunk.columns:
                X_chunk = chunk.drop('protocol_6', axis=1)
                y_chunk = chunk['protocol_6']
            else:
                # 레이블이 없는 경우 처리
                print("경고: 'protocol_6' 컬럼이 없습니다. 처리를 건너뜁니다.")
                continue
            
            # 데이터 분할
            X_train_chunk, X_test_chunk, y_train_chunk, y_test_chunk = train_test_split(
                X_chunk, y_chunk, test_size=0.2, random_state=random_state)
            
            # 청크 데이터 누적
            all_X_train.append(X_train_chunk)
            all_y_train.append(y_train_chunk)
            all_X_test.append(X_test_chunk)
            all_y_test.append(y_test_chunk)
            
            # 메모리 절약을 위해 청크 데이터 삭제
            del chunk, X_chunk, y_chunk, X_train_chunk, X_test_chunk, y_train_chunk, y_test_chunk
            
            # 일정 크기 이상 누적되면 중간 병합 및 정리
            if len(all_X_train) > 5:
                all_X_train = [pd.concat(all_X_train)]
                all_y_train = [pd.concat(all_y_train)]
                all_X_test = [pd.concat(all_X_test)]
                all_y_test = [pd.concat(all_y_test)]
                
                # 명시적 가비지 컬렉션 호출
                gc.collect()
        
        # 모든 청크 데이터 병합
        X_train = pd.concat(all_X_train)
        y_train = pd.concat(all_y_train)
        X_test = pd.concat(all_X_test)
        y_test = pd.concat(all_y_test)
        
        # 메모리 절약을 위해 중간 데이터 삭제
        del all_X_train, all_y_train, all_X_test, all_y_test
        gc.collect()
        
        # 데이터 스케일링
        X_train = scaler.fit_transform(X_train)
        X_test = scaler.transform(X_test)
        
        # 모델 학습
        print(f"총 {chunk_count}개 청크 처리 완료, 모델 학습 시작")
        model = RandomForestClassifier(n_estimators=100, random_state=random_state)
        model.fit(X_train, y_train)
        
        # 모델 평가
        predictions = model.predict(X_test)
        accuracy = accuracy_score(y_test, predictions)
        conf_matrix = confusion_matrix(y_test, predictions)
        
        print(f'Accuracy: {accuracy}')
        print('Confusion Matrix:')
        print(conf_matrix)
        
        # 모델 저장
        joblib.dump(model, 'random_forest_model.pkl')
        
        return model, accuracy, conf_matrix

def _train_random_forest_internal(preprocessed_df, random_state=42):
    """내부 랜덤포레스트 학습 함수 (전체 데이터셋 처리)"""
    # 문자열 데이터를 숫자로 변환
    for column in preprocessed_df.columns:
        if preprocessed_df[column].dtype == 'object':
            # LabelEncoder를 사용하여 문자열을 숫자로 변환
            label_encoder = LabelEncoder()
            preprocessed_df[column] = label_encoder.fit_transform(preprocessed_df[column].astype(str))
            
    # 특성과 레이블 분리
    X = preprocessed_df.drop('protocol_6', axis=1)
    y = preprocessed_df['protocol_6']

    # 데이터 분할
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=random_state)

    # 데이터 스케일링
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # 모델 학습
    model = RandomForestClassifier(n_estimators=100, random_state=random_state)
    model.fit(X_train, y_train)

    # 모델 평가
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    conf_matrix = confusion_matrix(y_test, predictions)

    print(f'Accuracy: {accuracy}')
    print('Confusion Matrix:')
    print(conf_matrix)

    # 모델 저장
    joblib.dump(model, 'random_forest_model.pkl')
    
    return model, accuracy, conf_matrix

def add_rf_predictions(df):
    """메모리 최적화된 랜덤포레스트 예측 확률을 데이터프레임에 추가"""
    try:
        if os.path.exists('random_forest_model.pkl'):
            # 메모리 절약을 위해 필요한 컬럼만 선택하여 복사
            feature_cols = [col for col in ['source', 'destination', 'protocol', 'length'] if col in df.columns]
            
            # 데이터 타입 최적화
            df_copy = {}
            for col in feature_cols:
                if col == 'length' and df[col].dtype != 'int32':
                    df_copy[col] = df[col].astype('int32')
                elif col == 'protocol' and df[col].dtype == 'object':
                    # 객체는 그대로 유지 (아래에서 인코딩)
                    df_copy[col] = df[col]
                else:
                    df_copy[col] = df[col]
            
            # 필요한 열만 포함하는 데이터프레임 생성
            X_pred = pd.DataFrame(df_copy)
            
            # 문자열 데이터 인코딩
            for col in X_pred.columns:
                if X_pred[col].dtype == 'object':
                    le = LabelEncoder()
                    X_pred[col] = le.fit_transform(X_pred[col].astype(str))
            
            # 모델 로드 (메모리 최적화를 위한 방식)
            rf_model = joblib.load('random_forest_model.pkl')
            
            # 배치 단위로 예측 (큰 데이터셋 처리 시 메모리 효율성 향상)
            batch_size = 1000
            rf_prob_list = []
            
            for i in range(0, len(X_pred), batch_size):
                X_batch = X_pred.iloc[i:i+batch_size]
                
                if hasattr(rf_model, 'predict_proba'):
                    batch_probs = rf_model.predict_proba(X_batch)
                    
                    # 필요한 열만 선택 (양성 클래스 확률)
                    if batch_probs.shape[1] > 1:
                        rf_prob_list.extend(batch_probs[:, 1].tolist())
                    else:
                        rf_prob_list.extend(batch_probs[:, 0].tolist())
                else:
                    # predict_proba 메서드가 없는 경우 NaN으로 채움
                    rf_prob_list.extend([np.nan] * len(X_batch))
            
            # 중간 변수 제거하여 메모리 확보
            del X_pred, df_copy
            
            # 결과 적용
            df['rf_prob'] = rf_prob_list
        else:
            print('random_forest_model.pkl 파일이 없어 예측을 건너뜁니다.')
            df['rf_prob'] = np.nan
    except Exception as e:
        print(f'랜덤포레스트 예측 feature 추가 중 오류: {e}')
        df['rf_prob'] = np.nan
    
    return df  