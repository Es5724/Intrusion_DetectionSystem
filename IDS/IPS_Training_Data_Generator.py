# -*- coding: utf-8 -*-

"""
IDS Training Data Generator

이 스크립트는 패킷 캡처, 트래픽 생성, 데이터 전처리 등 
AI학습에 필요한 데이터 생성 및 가공에 필요한 기능들의 인터페이스 제공 .
"""

import os
import sys
import time
import threading
import pandas as pd
import numpy as np
from datetime import datetime
import matplotlib.pyplot as plt
import torch
import ctypes
import platform

# 모듈 경로 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

# PyQt6 임포트
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QStackedWidget, QMessageBox
)
from PyQt6.QtGui import QIcon, QFont
from PyQt6.QtCore import Qt, QSize

# 애플리케이션 모듈 임포트
from scripts.components.packet_collector import PacketCapture, PacketCaptureCore, MainApp as PacketCollectorApp
from scripts.components.TrafficGeneratorApp import TrafficGeneratorApp

#
def is_admin():
    """현재 프로세스가 관리자 권한으로 실행 중인지 확인"""
    try:
        if platform.system() == 'Windows':
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            # Unix/Linux 시스템에서는 UID가 0인지 확인
            return os.getuid() == 0
    except:
        return False

def run_as_admin():
    """프로그램을 관리자 권한으로 재실행"""
    if is_admin():
        return True
    
    if platform.system() == 'Windows':
        try:
            # Windows에서 관리자 권한으로 재실행
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            return False  # 새 프로세스가 시작되므로 현재 프로세스는 종료해야 함
        except Exception as e:
            print(f"관리자 권한으로 실행 중 오류 발생: {e}")
            return False
    else:
        # Unix/Linux 시스템에서는 sudo로 재실행
        print("관리자 권한이 필요합니다. sudo로 실행해주세요.")
        return False

def clear_screen():
    """콘솔 화면 지우기"""
    os.system('cls' if os.name == 'nt' else 'clear')

class MainApplication(QMainWindow):
    """메인 애플리케이션 클래스"""
    
    def __init__(self, is_admin_mode=False):
        super().__init__()
        
        # 관리자 권한 상태 저장
        self.is_admin_mode = is_admin_mode
        
        # 기본 설정
        self.setWindowTitle("IDS Training Data Generator" + (" [관리자]" if self.is_admin_mode else ""))
        self.setMinimumSize(800, 500)  # 세로 크기 600 → 500으로 축소
        
        # 중앙 위젯 설정
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # 스택 위젯 생성 (화면 전환용)
        self.stacked_widget = QStackedWidget()
        
        # 메인 화면 레이아웃 설정
        main_layout = QVBoxLayout(self.central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)  # 여백 설정
        main_layout.addWidget(self.stacked_widget)
        
        # 메인 화면 초기화
        self.init_main_screen()
        
        # 관리자 권한 확인 제거 (이미 main에서 처리됨)
        # self.check_admin_privileges()
        
        # 패킷 캡처 화면 초기화
        self.packet_collector_app = PacketCollectorApp(self)
        self.stacked_widget.addWidget(self.packet_collector_app)
        
        # 트래픽 생성 화면 초기화
        self.traffic_generator_app = TrafficGeneratorApp(self)
        self.stacked_widget.addWidget(self.traffic_generator_app)
        
        # 시작 화면 표시
        self.show_main_screen()
    
    def init_main_screen(self):
        """메인 시작 화면 초기화"""
        self.main_screen = QWidget()
        layout = QVBoxLayout(self.main_screen)
        layout.setSpacing(15)  # 요소 간격 줄임
        
        # 제목 라벨
        title_label = QLabel("IDS Training Data Generator")
        title_font = QFont("Segoe UI", 22, QFont.Weight.Bold)  # 폰트를 Segoe UI로 변경
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("""
            color: 7F8C8D;
            margin-bottom: 10px;
            padding: 5px;
            border-bottom: 2px solid #3498DB;
        """)
        layout.addWidget(title_label)
        
        # 부제목 추가
        subtitle_label = QLabel("침입 탐지 시스템 학습 데이터 생성 도구")
        subtitle_font = QFont("Segoe UI", 12)  # 폰트를 Segoe UI로 변경
        subtitle_font.setItalic(True)
        subtitle_label.setFont(subtitle_font)
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_label.setStyleSheet("color: #7F8C8D; margin-bottom: 20px;")
        layout.addWidget(subtitle_label)
        
        # 버튼 컨테이너
        button_container = QWidget()
        button_layout = QVBoxLayout(button_container)
        button_layout.setSpacing(10)  # 버튼 간격 더 줄임
        button_layout.setContentsMargins(50, 0, 50, 0)  # 좌우 여백 추가
        
        # 메인 기능 버튼들 추가
        self.add_main_button(button_layout, "패킷 캡처", self.show_packet_collector)
        self.add_main_button(button_layout, "트래픽 생성", self.show_traffic_generator)
        
        # 종료 버튼
        exit_button = self.add_main_button(button_layout, "종료", self.close)
        exit_button.setStyleSheet("""
            QPushButton {
                background-color: #5b5b5b;
                color: white;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: ;
            }
            QPushButton:pressed {
                background-color: #5b5b5b;
            }
        """)
        
        layout.addWidget(button_container, alignment=Qt.AlignmentFlag.AlignCenter)
        
        # 상태 표시줄
        self.status_label = QLabel("시스템 상태: 준비 완료")
        if hasattr(self, 'is_admin_mode') and self.is_admin_mode:
            self.status_label.setText("시스템 상태: 준비 완료 [관리자 권한]")
        self.status_label.setStyleSheet("color: #666666; font-style: italic; font-size: 11px;")
        layout.addWidget(self.status_label, alignment=Qt.AlignmentFlag.AlignBottom)
        
        # 푸터 영역 추가
        footer_label = QLabel("© 2025 IDS Training Data Generator")
        footer_label.setStyleSheet("color: #999999; font-size: 10px;")
        footer_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(footer_label)
        
        self.stacked_widget.addWidget(self.main_screen)
    
    def add_main_button(self, layout, text, slot):
        """메인 화면에 버튼 추가"""
        button = QPushButton(text)
        button.setFixedSize(300, 40)  # 버튼 크기를 더 넓고 얇게 변경 (200,50 → 300,40)
        
        # 버튼 스타일 설정
        button.setStyleSheet("""
            QPushButton {
                background-color: #5b5b5b;
                color: white;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #5b5b5b;
            }
            QPushButton:pressed {
                background-color: #5b5b5b;
            }
        """)
        
        button.clicked.connect(slot)
        layout.addWidget(button, alignment=Qt.AlignmentFlag.AlignCenter)
        
        return button  # 버튼 객체 반환
    
    def show_main_screen(self):
        """메인 화면 표시"""
        self.stacked_widget.setCurrentWidget(self.main_screen)
    
    def show_packet_collector(self):
        """패킷 캡처 화면 표시"""
        self.stacked_widget.setCurrentWidget(self.packet_collector_app)
    
    def show_traffic_generator(self):
        """트래픽 생성 화면 표시"""
        self.stacked_widget.setCurrentWidget(self.traffic_generator_app)

def main():
    """메인 함수"""
    # 프로그램 시작 전에 관리자 권한 확인
    if platform.system() == 'Windows' and not is_admin():
        # QApplication을 먼저 생성하여 메시지박스 표시 가능하게 함
        app = QApplication(sys.argv)
        
        reply = QMessageBox.question(
            None,
            "관리자 권한 필요",
            "이 프로그램은 패킷 캡처 및 전송을 위해 관리자 권한이 필요합니다.\n"
            "관리자 권한으로 실행하시겠습니까?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # 관리자 권한으로 재실행
            if not run_as_admin():
                # 새 프로세스가 시작되므로 현재 프로세스 종료
                sys.exit(0)
        else:
            # 사용자가 거부한 경우 제한된 기능으로 실행
            reply = QMessageBox.information(
                None,
                "제한된 기능",
                "관리자 권한 없이 실행합니다.\n"
                "일부 네트워크 기능이 제한될 수 있습니다.",
                QMessageBox.StandardButton.Ok
            )
    else:
        # 이미 관리자 권한이 있거나 Linux/Mac인 경우
        app = QApplication(sys.argv)
    
    # 관리자 권한 상태를 MainApplication에 전달
    window = MainApplication(is_admin_mode=is_admin())
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main() 