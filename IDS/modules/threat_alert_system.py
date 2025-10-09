#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
위협 알림 시스템 모듈 - 실시간 위협 탐지 및 알림 기능

이 모듈은 위협이 탐지되면 위험도에 따라 다양한 방식으로 사용자에게 알림을 제공합니다.
"""

import os
import time
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from collections import deque
import logging

logger = logging.getLogger("ThreatAlertSystem")

class ThreatLevel:
    """위협 수준 정의"""
    CRITICAL = "치명적"
    HIGH = "높음"
    MEDIUM = "중간"
    LOW = "낮음"
    INFO = "정보"

class ThreatAlertSystem:
    """위협 알림 시스템 클래스"""
    
    def __init__(self, config=None):
        """위협 알림 시스템 초기화"""
        self.config = config or {}
        self.alert_queue = queue.Queue(maxsize=100)  # 🔥 큐 크기 제한으로 블로킹 방지
        self.threat_history = deque(maxlen=1000)  # 최근 1000개 위협 기록
        self.is_running = True
        
        # 🔥 팝업 제한 설정 (과도한 팝업 방지)
        self.popup_enabled = self.config.get('popup_enabled', False)  # 기본값을 False로 변경
        self.dashboard_enabled = self.config.get('dashboard_enabled', False)  # 대시보드도 기본 비활성화
        self.max_popups_per_minute = self.config.get('max_popups_per_minute', 3)  # 분당 최대 3개
        self.popup_timestamps = deque(maxlen=self.max_popups_per_minute)
        
        # 위협 수준별 임계값
        self.thresholds = {
            ThreatLevel.CRITICAL: 0.95,
            ThreatLevel.HIGH: 0.85,
            ThreatLevel.MEDIUM: 0.70,
            ThreatLevel.LOW: 0.50
        }
        
        # 중간 위협 누적 카운터 및 알림 임계값
        self.medium_threat_counter = {}  # IP별 카운터
        self.medium_threat_threshold = self.config.get('medium_threat_threshold', 5)  # 기본값 5회
        self.medium_threat_window = 300  # 5분 시간 윈도우
        self.medium_threat_timestamps = {}  # IP별 타임스탬프 리스트
        
        # 대시보드 초기화
        if self.dashboard_enabled:
            self.dashboard = None
            self.dashboard_thread = threading.Thread(target=self._init_dashboard, daemon=True)
            self.dashboard_thread.start()
        
        # 알림 처리 스레드 시작 (대시보드와 독립적으로 실행)
        self.alert_thread = threading.Thread(target=self._process_alerts, daemon=True)
        self.alert_thread.start()
        
        logger.info("위협 알림 시스템 초기화 완료 (사운드 비활성화)")
    
    def _init_dashboard(self):
        """위협 대시보드 초기화"""
        try:
            self.dashboard = ThreatDashboard(self)
            self.dashboard.run()
        except Exception as e:
            logger.error(f"대시보드 초기화 실패: {e}")
            self.dashboard_enabled = False
    
    def add_threat(self, threat_info):
        """새로운 위협 추가
        
        Args:
            threat_info (dict): 위협 정보
                - source_ip: 출발지 IP
                - destination_ip: 목적지 IP
                - confidence: 위협 신뢰도 (0.0 ~ 1.0)
                - protocol: 프로토콜
                - packet_info: 추가 패킷 정보
                - action_taken: 수행된 방어 조치
        """
        # 위협 수준 결정
        threat_level = self._determine_threat_level(threat_info['confidence'])
        threat_info['threat_level'] = threat_level
        threat_info['timestamp'] = datetime.now()
        
        # 위협 기록에 추가
        self.threat_history.append(threat_info)
        
        # 🔥 큐가 가득 찬 경우 블로킹하지 않고 드롭
        if self.alert_queue.full():
            logger.warning(f"알림 큐 가득 참 - 위협 알림 드롭: {threat_info['source_ip']}")
            return
        
        # 중간 위협의 경우 누적 처리
        if threat_level == ThreatLevel.MEDIUM:
            source_ip = threat_info['source_ip']
            current_time = time.time()
            
            # IP별 타임스탬프 리스트 초기화
            if source_ip not in self.medium_threat_timestamps:
                self.medium_threat_timestamps[source_ip] = []
            
            # 시간 윈도우 내의 타임스탬프만 유지
            self.medium_threat_timestamps[source_ip] = [
                ts for ts in self.medium_threat_timestamps[source_ip] 
                if current_time - ts < self.medium_threat_window
            ]
            
            # 현재 타임스탬프 추가
            self.medium_threat_timestamps[source_ip].append(current_time)
            
            # 임계값 도달 확인
            if len(self.medium_threat_timestamps[source_ip]) >= self.medium_threat_threshold:
                # 임계값에 도달한 경우에만 알림 큐에 추가
                threat_info['accumulated_count'] = len(self.medium_threat_timestamps[source_ip])
                self.alert_queue.put(threat_info)
                # 카운터 리셋
                self.medium_threat_timestamps[source_ip] = []
                logger.info(f"중간 위협 임계값 도달: {source_ip} - {threat_info['accumulated_count']}회 탐지")
            else:
                logger.info(f"중간 위협 누적 중: {source_ip} - {len(self.medium_threat_timestamps[source_ip])}/{self.medium_threat_threshold}")
        else:
            # 높은/치명적 위협은 즉시 알림
            if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                self.alert_queue.put(threat_info)
        
        logger.info(f"위협 탐지: {threat_info['source_ip']} - 수준: {threat_level} - 신뢰도: {threat_info['confidence']:.2f}")
    
    def _determine_threat_level(self, confidence):
        """신뢰도를 기반으로 위협 수준 결정"""
        for level, threshold in self.thresholds.items():
            if confidence >= threshold:
                return level
        return ThreatLevel.INFO
    
    def _process_alerts(self):
        """알림 처리 스레드 - 대시보드와 독립적으로 실행"""
        while self.is_running:
            try:
                # 타임아웃으로 큐에서 알림 가져오기
                threat_info = self.alert_queue.get(timeout=1)
                
                # 위협 수준에 따른 알림 처리
                self._handle_alert(threat_info)
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"알림 처리 중 오류: {e}")
    
    def _handle_alert(self, threat_info):
        """위협 수준에 따른 알림 처리"""
        threat_level = threat_info['threat_level']
        
        # 팝업 알림 (치명적/높음/누적된 중간 수준)
        if self.popup_enabled:
            if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
                self._show_popup_alert(threat_info)
            elif threat_level == ThreatLevel.MEDIUM and 'accumulated_count' in threat_info:
                # 누적된 중간 위협에 대한 특별한 팝업
                self._show_accumulated_popup_alert(threat_info)
        
        # 대시보드 업데이트 (활성화된 경우에만)
        if self.dashboard_enabled and self.dashboard:
            self.dashboard.update_threat(threat_info)
    
    def _show_popup_alert(self, threat_info):
        """팝업 알림 표시 (비블로킹 방식)"""
        # 🔥 팝업 제한 확인 (분당 최대 개수)
        current_time = time.time()
        # 1분 이내의 팝업만 카운트
        recent_popups = [ts for ts in self.popup_timestamps if current_time - ts < 60]
        
        if len(recent_popups) >= self.max_popups_per_minute:
            logger.debug(f"팝업 제한 도달 - 알림 건너뜀: {threat_info['source_ip']}")
            return
        
        # 팝업 타임스탬프 기록
        self.popup_timestamps.append(current_time)
        
        def show_popup():
            try:
                root = tk.Tk()
                root.withdraw()  # 메인 윈도우 숨김
                
                # 메시지 구성
                title = f"보안 경고 - {threat_info['threat_level']}"
                message = f"""
위협이 탐지되었습니다!

출발지 IP: {threat_info['source_ip']}
위협 수준: {threat_info['threat_level']}
신뢰도: {threat_info['confidence']:.2%}
프로토콜: {threat_info.get('protocol', 'Unknown')}
시간: {threat_info['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}

조치: {threat_info.get('action_taken', '모니터링 중')}
                """
                
                # 비블로킹 팝업 생성 (자동으로 3초 후 닫힘)
                popup = tk.Toplevel(root)
                popup.title(title)
                popup.geometry("400x300")
                popup.attributes('-topmost', True)  # 항상 위에 표시
                
                # 메시지 표시
                label = tk.Label(popup, text=message, justify='left', padx=20, pady=20)
                label.pack()
                
                # 확인 버튼
                def close_popup():
                    popup.destroy()
                    root.destroy()
                
                btn = tk.Button(popup, text="확인", command=close_popup, width=10)
                btn.pack(pady=10)
                
                # 3초 후 자동 닫기
                popup.after(3000, close_popup)
                
                root.mainloop()
                
            except Exception as e:
                logger.error(f"팝업 표시 오류: {e}")
        
        # 별도 스레드에서 팝업 표시
        popup_thread = threading.Thread(target=show_popup, daemon=True)
        popup_thread.start()
    
    def _show_accumulated_popup_alert(self, threat_info):
        """누적된 중간 위협에 대한 특별한 팝업 표시"""
        def show_popup():
            root = tk.Tk()
            root.withdraw()  # 메인 윈도우 숨김
            
            # 메시지 구성
            title = f"보안 경고 - 중간 위협 누적"
            message = f"""
중간 위협이 누적되었습니다!

출발지 IP: {threat_info['source_ip']}
위협 수준: 중간
신뢰도: {threat_info['confidence']:.2%}
프로토콜: {threat_info.get('protocol', 'Unknown')}
시간: {threat_info['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}

누적 횟수: {threat_info['accumulated_count']}회 (5분 이내)
조치: {threat_info.get('action_taken', '모니터링 강화')}
            """
            
            # 비블로킹 팝업 생성 (자동으로 3초 후 닫힘)
            popup = tk.Toplevel(root)
            popup.title(title)
            popup.geometry("400x350")
            popup.attributes('-topmost', True)
            
            label = tk.Label(popup, text=message, justify='left', padx=20, pady=20)
            label.pack()
            
            def close_popup():
                popup.destroy()
                root.destroy()
            
            btn = tk.Button(popup, text="확인", command=close_popup, width=10)
            btn.pack(pady=10)
            
            # 3초 후 자동 닫기
            popup.after(3000, close_popup)
            
            root.mainloop()
        
        # 별도 스레드에서 팝업 표시
        popup_thread = threading.Thread(target=show_popup, daemon=True)
        popup_thread.start()
    
    def get_threat_statistics(self):
        """위협 통계 반환"""
        stats = {
            'total': len(self.threat_history),
            'by_level': {},
            'recent_threats': []
        }
        
        # 수준별 통계
        for level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.MEDIUM, ThreatLevel.LOW, ThreatLevel.INFO]:
            count = sum(1 for t in self.threat_history if t.get('threat_level') == level)
            stats['by_level'][level] = count
        
        # 최근 10개 위협
        stats['recent_threats'] = list(self.threat_history)[-10:]
        
        return stats
    
    def shutdown(self):
        """시스템 종료"""
        self.is_running = False
        if self.dashboard:
            self.dashboard.close()
        logger.info("위협 알림 시스템 종료")


class ThreatDashboard:
    """위협 모니터링 대시보드"""
    
    def __init__(self, alert_system):
        self.alert_system = alert_system
        self.root = None
        self.update_queue = queue.Queue()
        
    def run(self):
        """대시보드 실행"""
        self.root = tk.Tk()
        self.root.title("IPS 위협 모니터링 대시보드")
        self.root.geometry("800x600")
        
        # 스타일 설정
        style = ttk.Style()
        style.theme_use('clam')
        
        # 상단 요약 프레임
        self.summary_frame = ttk.LabelFrame(self.root, text="위협 요약", padding=10)
        self.summary_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 통계 레이블
        self.stats_labels = {}
        for i, level in enumerate([ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.MEDIUM, ThreatLevel.LOW]):
            label = ttk.Label(self.summary_frame, text=f"{level}: 0", font=('Arial', 12))
            label.grid(row=0, column=i, padx=10)
            self.stats_labels[level] = label
        
        # 실시간 위협 목록
        self.threat_frame = ttk.LabelFrame(self.root, text="실시간 위협", padding=10)
        self.threat_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 트리뷰 생성
        columns = ('시간', 'IP 주소', '위협 수준', '신뢰도', '프로토콜', '조치')
        self.threat_tree = ttk.Treeview(self.threat_frame, columns=columns, show='headings', height=15)
        
        # 컬럼 설정
        for col in columns:
            self.threat_tree.heading(col, text=col)
            self.threat_tree.column(col, width=120)
        
        # 스크롤바
        scrollbar = ttk.Scrollbar(self.threat_frame, orient=tk.VERTICAL, command=self.threat_tree.yview)
        self.threat_tree.configure(yscrollcommand=scrollbar.set)
        
        self.threat_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 컨트롤 프레임
        self.control_frame = ttk.Frame(self.root)
        self.control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 알림 설정 체크박스 (사운드 제거)
        self.popup_var = tk.BooleanVar(value=self.alert_system.popup_enabled)
        
        ttk.Checkbutton(self.control_frame, text="팝업 알림", variable=self.popup_var,
                       command=self._toggle_popup).pack(side=tk.LEFT, padx=5)
        
        # 중간 위협 임계값 설정
        ttk.Label(self.control_frame, text="중간 위협 임계값:").pack(side=tk.LEFT, padx=5)
        self.threshold_var = tk.StringVar(value=str(self.alert_system.medium_threat_threshold))
        threshold_spinbox = ttk.Spinbox(self.control_frame, from_=1, to=20, 
                                      textvariable=self.threshold_var, width=5,
                                      command=self._update_threshold)
        threshold_spinbox.pack(side=tk.LEFT, padx=5)
        
        # 통계 초기화 버튼
        ttk.Button(self.control_frame, text="통계 초기화", 
                  command=self._clear_stats).pack(side=tk.RIGHT, padx=5)
        
        # 업데이트 타이머 시작
        self._update_display()
        
        # 윈도우 종료 처리
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        
        self.root.mainloop()
    
    def update_threat(self, threat_info):
        """새로운 위협 업데이트"""
        self.update_queue.put(threat_info)
    
    def _update_display(self):
        """디스플레이 업데이트"""
        # 큐에서 새로운 위협 처리
        while not self.update_queue.empty():
            try:
                threat_info = self.update_queue.get_nowait()
                self._add_threat_to_list(threat_info)
            except queue.Empty:
                break
        
        # 통계 업데이트
        self._update_statistics()
        
        # 다음 업데이트 예약
        if self.root:
            self.root.after(1000, self._update_display)
    
    def _add_threat_to_list(self, threat_info):
        """위협을 목록에 추가"""
        # 트리뷰에 새 항목 추가
        values = (
            threat_info['timestamp'].strftime('%H:%M:%S'),
            threat_info['source_ip'],
            threat_info['threat_level'],
            f"{threat_info['confidence']:.2%}",
            threat_info.get('protocol', 'Unknown'),
            threat_info.get('action_taken', '모니터링')
        )
        
        # 위협 수준에 따른 태그 설정
        tags = []
        if threat_info['threat_level'] == ThreatLevel.CRITICAL:
            tags.append('critical')
        elif threat_info['threat_level'] == ThreatLevel.HIGH:
            tags.append('high')
        
        item = self.threat_tree.insert('', 0, values=values, tags=tags)
        
        # 스타일 적용
        self.threat_tree.tag_configure('critical', background='#ff6b6b')
        self.threat_tree.tag_configure('high', background='#ffa94d')
        
        # 오래된 항목 제거 (최대 100개 유지)
        items = self.threat_tree.get_children()
        if len(items) > 100:
            self.threat_tree.delete(items[-1])
    
    def _update_statistics(self):
        """통계 업데이트"""
        stats = self.alert_system.get_threat_statistics()
        
        for level, label in self.stats_labels.items():
            count = stats['by_level'].get(level, 0)
            label.config(text=f"{level}: {count}")
    
    def _toggle_popup(self):
        """팝업 알림 토글"""
        self.alert_system.popup_enabled = self.popup_var.get()
    
    def _update_threshold(self):
        """중간 위협 임계값 업데이트"""
        new_threshold = int(self.threshold_var.get())
        self.alert_system.medium_threat_threshold = new_threshold
        logger.info(f"중간 위협 임계값 업데이트: {new_threshold}")
    
    def _clear_stats(self):
        """통계 초기화"""
        self.alert_system.threat_history.clear()
        for item in self.threat_tree.get_children():
            self.threat_tree.delete(item)
    
    def close(self):
        """대시보드 닫기"""
        if self.root:
            self.root.quit()
            self.root = None 