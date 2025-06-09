import pandas as pd
import numpy as np
import joblib
import os
import tkinter as tk
from tkinter import ttk, scrolledtext
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import seaborn as sns
import queue
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.preprocessing import StandardScaler, LabelEncoder
import gc  # 명시적 가비지 컬렉션용

class MLTrainingWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("머신러닝 학습 모니터링")
        self.root.geometry("800x600")
        
        # 상태 표시 영역
        self.status_frame = ttk.LabelFrame(self.root, text="학습 상태", padding=10)
        self.status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.status_label = ttk.Label(self.status_frame, text="대기 중...")
        self.status_label.pack()
        
        # 로그 표시 영역
        self.log_frame = ttk.LabelFrame(self.root, text="학습 로그", padding=10)
        self.log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=10)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # 최대 로그 라인 수 (메모리 절약)
        self.max_log_lines = 1000
        
        # 성능 지표 표시 영역
        self.metrics_frame = ttk.LabelFrame(self.root, text="성능 지표", padding=10)
        self.metrics_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.accuracy_label = ttk.Label(self.metrics_frame, text="정확도: -")
        self.accuracy_label.pack()
        
        # 혼동 행렬 표시 영역 (지연 로딩)
        self.confusion_frame = ttk.LabelFrame(self.root, text="혼동 행렬", padding=10)
        self.confusion_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 지연 로딩을 위한 버튼 추가
        self.confusion_btn = ttk.Button(self.confusion_frame, text="혼동 행렬 시각화 보기", 
                                      command=self.create_confusion_matrix)
        self.confusion_btn.pack(pady=10)
        
        # 혼동 행렬 데이터 저장 변수
        self.last_conf_matrix = None
        
        # 캔버스와 피규어 지연 초기화
        self.figure = None
        self.canvas = None
        
        # GUI 업데이트를 위한 큐 생성
        self.gui_queue = queue.Queue()
        
        # 윈도우 종료 이벤트 처리
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # process_gui_queue 호출
        self.process_gui_queue()

    def create_confusion_matrix(self):
        """혼동 행렬 시각화를 필요할 때만 생성"""
        if self.last_conf_matrix is None:
            return
            
        # 기존 컴포넌트 제거
        for widget in self.confusion_frame.winfo_children():
            widget.destroy()
        
        # 경량화된 방식으로 혼동 행렬 생성
        self.figure = Figure(figsize=(6, 4), dpi=80)  # dpi 낮춤
        ax = self.figure.add_subplot(111)
        
        # 데이터 크기에 따라 좀 더 가벼운 표현 방식 선택
        matrix_size = len(self.last_conf_matrix)
        
        if matrix_size <= 10:  # 작은 행렬은 seaborn 히트맵 사용
            sns.heatmap(self.last_conf_matrix, annot=True, fmt='d', cmap='Blues', ax=ax)
        else:  # 큰 행렬은 이미지로 표시
            im = ax.imshow(self.last_conf_matrix, cmap='Blues')
            self.figure.colorbar(im)
            
            # 크기가 큰 경우 레이블 표시 생략
            if matrix_size <= 20:  # 중간 크기일 때만 일부 레이블 표시
                # x, y축 레이블 추가 (특정 간격으로)
                step = max(1, matrix_size // 10)
                ticks = range(0, matrix_size, step)
                ax.set_xticks(ticks)
                ax.set_yticks(ticks)
                ax.set_xticklabels(ticks)
                ax.set_yticklabels(ticks)
        
        ax.set_xlabel('예측 레이블')
        ax.set_ylabel('실제 레이블')
        
        # 캔버스 생성 및 표시
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.confusion_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # 메모리 초기화 버튼 추가
        ttk.Button(self.confusion_frame, text="시각화 제거 (메모리 확보)", 
                  command=self.clear_visualization).pack(pady=5)

    def clear_visualization(self):
        """시각화 메모리 명시적 해제"""
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
            self.canvas = None
        
        if self.figure:
            self.figure.clear()
            self.figure = None
            
        # 혼동 행렬 보기 버튼 다시 표시
        for widget in self.confusion_frame.winfo_children():
            widget.destroy()
            
        self.confusion_btn = ttk.Button(self.confusion_frame, text="혼동 행렬 시각화 보기", 
                                      command=self.create_confusion_matrix)
        self.confusion_btn.pack(pady=10)
        
        # 명시적 가비지 컬렉션 호출
        gc.collect()

    def process_gui_queue(self):
        try:
            while not self.gui_queue.empty():
                task = self.gui_queue.get_nowait()
                if task[0] == 'deiconify':
                    self.root.deiconify()
                elif task[0] == 'update_status':
                    self.status_label.config(text=task[1])
                    
                    # 로그 크기 제한 및 추가
                    current_text = self.log_text.get(1.0, tk.END).split('\n')
                    if len(current_text) > self.max_log_lines:
                        # 오래된 로그 제거
                        self.log_text.delete(1.0, tk.END)
                        new_text = '\n'.join(current_text[-self.max_log_lines:])
                        self.log_text.insert(tk.END, new_text)
                    
                    # 새 로그 추가
                    self.log_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {task[1]}\n")
                    self.log_text.see(tk.END)
                    
                elif task[0] == 'update_metrics':
                    accuracy = task[1]
                    conf_matrix = task[2]
                    self.accuracy_label.config(text=f"정확도: {accuracy:.4f}")
                    
                    # 혼동 행렬 데이터만 저장 (시각화는 나중에)
                    self.last_conf_matrix = conf_matrix
                    
                    # 혼동 행렬 버튼 텍스트 업데이트
                    if self.confusion_btn:
                        self.confusion_btn.config(text="혼동 행렬 시각화 보기 (업데이트됨)")
                    
                    # 메모리 정리
                    gc.collect()
        except queue.Empty:
            pass
        
        # 큐 확인 간격 조정 (100ms → 200ms, 메모리 사용량 감소)
        self.root.after(200, self.process_gui_queue)

    def on_closing(self):
        """윈도우 종료 시 메모리 정리"""
        self.clear_visualization()
        self.root.destroy()

    def show(self):
        self.root.mainloop()

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