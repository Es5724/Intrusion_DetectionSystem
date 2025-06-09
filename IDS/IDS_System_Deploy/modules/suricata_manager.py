#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
수리카타(Suricata) 통합 관리 모듈

수리카타 IDS 엔진을 제어하고 결과를 처리하는 기능을 제공합니다.
"""
import os
import sys
import time
import json
import queue
import threading
import subprocess
import re
import logging
import ipaddress
from datetime import datetime

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("suricata.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SuricataManager")

class SuricataManager:
    """수리카타 IDS 엔진 관리 클래스"""
    
    def __init__(self, config_path=None, rules_path=None, eve_json_path=None):
        """수리카타 관리자 초기화
        
        Args:
            config_path (str): 수리카타 설정 파일 경로
            rules_path (str): 수리카타 규칙 파일 경로
            eve_json_path (str): 수리카타 이벤트 로그 파일 경로
        """
        self.suricata_path = self._find_suricata_binary()
        self.config_path = config_path
        self.rules_path = rules_path
        self.eve_json_path = eve_json_path or "eve.json"
        
        self.alerts_queue = queue.Queue(maxsize=1000)
        self.is_running = False
        self.process = None
        self.alert_thread = None
        self.last_read_position = 0
        
        # 수리카타 이벤트 타입 매핑
        self.event_types = {
            "alert": 1,       # 알림 이벤트
            "anomaly": 0.8,   # 이상 행동
            "http": 0.5,      # HTTP 이벤트 
            "dns": 0.4,       # DNS 이벤트
            "tls": 0.3,       # TLS/SSL 이벤트
            "flow": 0.2       # 플로우 이벤트
        }
        
        logger.info("수리카타 관리자 초기화 완료")
        
    def _find_suricata_binary(self):
        """수리카타 실행 파일 경로 찾기"""
        # 우선 환경변수 확인
        if 'SURICATA_PATH' in os.environ:
            path = os.environ['SURICATA_PATH']
            if os.path.exists(path):
                return path
        
        # 일반적인 설치 경로 확인
        common_paths = [
            "/usr/bin/suricata",
            "/usr/local/bin/suricata",
            "/opt/suricata/bin/suricata",
            "C:\\Program Files\\Suricata\\suricata.exe",
            "C:\\Suricata\\suricata.exe"
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        # 시스템 PATH에서 검색
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(["where", "suricata"], 
                                      capture_output=True, text=True, check=False)
            else:  # Linux/Unix
                result = subprocess.run(["which", "suricata"], 
                                      capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception as e:
            logger.error(f"수리카타 검색 중 오류: {e}")
        
        logger.warning("수리카타 실행 파일을 찾을 수 없습니다. 수동으로 경로를 지정해주세요.")
        return "suricata"  # 기본값, PATH에 있다고 가정
    
    def initialize(self):
        """수리카타 초기화 및 설정 확인"""
        if not self._check_suricata_installed():
            raise RuntimeError("수리카타가 설치되지 않았거나 실행할 수 없습니다.")
        
        # 기본 설정 파일 생성
        if not self.config_path:
            self.config_path = self._create_default_config()
            
        # 기본 규칙 세트 생성
        if not self.rules_path:
            self.rules_path = self._create_default_rules()
            
        logger.info(f"수리카타 초기화 완료: 버전 {self._get_suricata_version()}")
        return True
    
    def _check_suricata_installed(self):
        """수리카타 설치 여부 확인"""
        try:
            result = subprocess.run([self.suricata_path, "--version"], 
                                  capture_output=True, text=True, check=False)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"수리카타 확인 중 오류: {e}")
            return False
    
    def _get_suricata_version(self):
        """수리카타 버전 정보 가져오기"""
        try:
            result = subprocess.run([self.suricata_path, "--version"], 
                                  capture_output=True, text=True, check=False)
            if result.returncode == 0:
                # 버전 정보 추출
                match = re.search(r'(\d+\.\d+\.\d+)', result.stdout)
                if match:
                    return match.group(1)
            return "알 수 없음"
        except Exception as e:
            logger.error(f"수리카타 버전 확인 중 오류: {e}")
            return "오류"
    
    def _create_default_config(self):
        """기본 수리카타 설정 파일 생성"""
        config_dir = "config"
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
        
        config_path = os.path.join(config_dir, "suricata.yaml")
        
        # 매우 기본적인 설정 파일 생성
        basic_config = """
%YAML 1.1
---
# 기본 수리카타 설정
default-log-dir: .
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - flow

# 기본 규칙 설정
default-rule-path: rules
rule-files:
  - suricata.rules
"""
        
        with open(config_path, 'w') as f:
            f.write(basic_config)
        
        logger.info(f"기본 수리카타 설정 파일 생성됨: {config_path}")
        return config_path
    
    def _create_default_rules(self):
        """기본 수리카타 규칙 파일 생성"""
        rules_dir = "rules"
        if not os.path.exists(rules_dir):
            os.makedirs(rules_dir)
        
        rules_path = os.path.join(rules_dir, "suricata.rules")
        
        # 기본 규칙 파일 생성
        basic_rules = """
# 기본 침입 탐지 규칙

# ICMP Ping 탐지
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping"; itype:8; sid:1000001; rev:1;)

# SSH 무차별 대입 공격 시도 감지
alert tcp any any -> $HOME_NET 22 (msg:"SSH 무차별 대입 공격 시도"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000002; rev:1;)

# 포트 스캔 감지
alert tcp any any -> $HOME_NET any (msg:"포트 스캔 감지"; flags:S; threshold:type threshold, track by_src, count 30, seconds 60; classtype:attempted-recon; sid:1000003; rev:1;)

# HTTP 비정상 요청
alert http any any -> $HOME_NET any (msg:"HTTP SQL 인젝션 시도"; content:"union"; http_uri; nocase; classtype:web-application-attack; sid:1000004; rev:1;)
"""
        
        with open(rules_path, 'w') as f:
            f.write(basic_rules)
        
        logger.info(f"기본 수리카타 규칙 파일 생성됨: {rules_path}")
        return rules_path
    
    def start_monitoring(self, interface):
        """수리카타 모니터링 시작
        
        Args:
            interface (str): 모니터링할 네트워크 인터페이스
        """
        if self.is_running:
            logger.warning("수리카타가 이미 실행 중입니다.")
            return False
        
        try:
            # 이전 이벤트 로그 파일 삭제
            if os.path.exists(self.eve_json_path):
                os.remove(self.eve_json_path)
            
            # 수리카타 실행 명령
            cmd = [
                self.suricata_path,
                "-c", self.config_path,
                "--set", f"vars.address-groups.HOME_NET=[{interface}]",
                "-i", interface
            ]
            
            # Windows에서는 다른 명령 필요할 수 있음
            if os.name == 'nt':
                cmd = [
                    self.suricata_path,
                    "-c", self.config_path,
                    "-i", interface
                ]
            
            logger.info(f"수리카타 실행 명령: {' '.join(cmd)}")
            
            # 비동기로 수리카타 실행
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # 상태 설정
            self.is_running = True
            
            # 이벤트 로그 모니터링 스레드 시작
            self.alert_thread = threading.Thread(
                target=self._monitor_alerts,
                daemon=True
            )
            self.alert_thread.start()
            
            logger.info(f"수리카타 모니터링 시작됨: 인터페이스 {interface}")
            return True
            
        except Exception as e:
            logger.error(f"수리카타 실행 중 오류: {e}")
            return False
    
    def _monitor_alerts(self):
        """수리카타 경고 모니터링 스레드"""
        logger.info("경고 모니터링 스레드 시작")
        
        # 경고 파일이 생성될 때까지 대기
        wait_count = 0
        while not os.path.exists(self.eve_json_path) and wait_count < 30:
            time.sleep(1)
            wait_count += 1
        
        if not os.path.exists(self.eve_json_path):
            logger.error("수리카타 이벤트 로그 파일이 생성되지 않았습니다.")
            return
        
        # 파일 테일링하며 새 이벤트 처리
        while self.is_running:
            try:
                with open(self.eve_json_path, 'r') as f:
                    # 이전에 읽은 위치로 이동
                    f.seek(self.last_read_position)
                    
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            # JSON 파싱
                            event = json.loads(line)
                            # 경고 이벤트만 처리
                            if event.get('event_type') in self.event_types:
                                self.alerts_queue.put(event)
                        except json.JSONDecodeError:
                            continue
                    
                    # 현재 위치 저장
                    self.last_read_position = f.tell()
            
            except Exception as e:
                logger.error(f"이벤트 로그 읽기 중 오류: {e}")
            
            # 잠시 대기
            time.sleep(1)
    
    def stop_monitoring(self):
        """수리카타 모니터링 중지"""
        if not self.is_running:
            return True
        
        self.is_running = False
        
        # 프로세스 종료
        if self.process:
            try:
                if os.name == 'nt':  # Windows
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(self.process.pid)], 
                                  check=False)
                else:  # Linux/Unix
                    self.process.terminate()
                    self.process.wait(timeout=5)
            except Exception as e:
                logger.error(f"수리카타 프로세스 종료 중 오류: {e}")
        
        # 스레드 종료 대기
        if self.alert_thread and self.alert_thread.is_alive():
            self.alert_thread.join(timeout=5)
        
        logger.info("수리카타 모니터링 중지됨")
        return True
    
    def get_alerts(self):
        """수집된 경고 반환"""
        alerts = []
        try:
            while not self.alerts_queue.empty():
                alerts.append(self.alerts_queue.get_nowait())
        except queue.Empty:
            pass
        
        return alerts
    
    def check_packet(self, packet_info):
        """패킷 정보와 일치하는 수리카타 경고 확인
        
        Args:
            packet_info (dict): 패킷 정보 (source, destination, protocol 등)
            
        Returns:
            dict: 매칭된 수리카타 경고 정보
        """
        try:
            # 패킷 타입 검사 및 변환
            if not isinstance(packet_info, dict):
                print(f"check_packet - 유효하지 않은 패킷 타입: {type(packet_info).__name__}")
                # 문자열 패킷을 딕셔너리로 변환 시도
                if isinstance(packet_info, str):
                    packet_info = {
                        'source': 'unknown',
                        'destination': 'unknown',
                        'protocol': 'unknown',
                        'length': len(packet_info) if packet_info else 0,
                        'info': packet_info,
                        'raw_data': packet_info
                    }
                else:
                    return None
            
            # 수리카타가 실행 중이 아니면 빈 결과 반환
            if not self.is_running:
                return None
            
            # 필수 필드 존재 확인
            if 'source' not in packet_info or 'destination' not in packet_info:
                print(f"check_packet - 필수 필드 누락: {packet_info.keys()}")
                return None
            
            # 최근 경고 가져오기
            alerts = self.get_alerts()
            if not alerts:
                return None
            
            # 소스/목적지 IP 가져오기
            src_ip = packet_info.get('source', '').split(':')[0] if isinstance(packet_info.get('source', ''), str) and ':' in packet_info.get('source', '') else packet_info.get('source', '')
            dst_ip = packet_info.get('destination', '').split(':')[0] if isinstance(packet_info.get('destination', ''), str) and ':' in packet_info.get('destination', '') else packet_info.get('destination', '')
            
            # 디버그 로그
            print(f"수리카타 패킷 검사 - 출발지: {src_ip}, 목적지: {dst_ip}")
            
            # 일치하는 경고 찾기
            for alert in alerts:
                alert_src_ip = alert.get('src_ip', '')
                alert_dest_ip = alert.get('dest_ip', '')
                
                # IP 일치 여부 확인
                if (src_ip == alert_src_ip and dst_ip == alert_dest_ip) or \
                (src_ip == alert_dest_ip and dst_ip == alert_src_ip):
                    
                    # 결과 구성
                    result = {
                        'suricata_alert': True,
                        'suricata_signature_id': alert.get('alert', {}).get('signature_id', 0),
                        'suricata_signature': alert.get('alert', {}).get('signature', '알 수 없음'),
                        'suricata_category': alert.get('alert', {}).get('category', '알 수 없음'),
                        'suricata_severity': alert.get('alert', {}).get('severity', 2),
                        'suricata_event_type': alert.get('event_type', 'alert'),
                        'suricata_confidence': self.event_types.get(alert.get('event_type', 'alert'), 0.5)
                    }
                    
                    return result
            
            # 일치하는 경고가 없는 경우
            return None
            
        except Exception as e:
            print(f"수리카타 패킷 검사 중 오류 발생: {str(e)}, 패킷 타입: {type(packet_info).__name__ if packet_info is not None else 'None'}")
            import traceback
            traceback.print_exc()
            return None

    def shutdown(self):
        """수리카타 관리자 종료"""
        self.stop_monitoring()
        logger.info("수리카타 관리자 종료됨")

# 단독 실행 테스트
if __name__ == "__main__":
    print("수리카타 관리자 테스트")
    
    # 관리자 초기화
    manager = SuricataManager()
    try:
        manager.initialize()
        
        # 모니터링 시작
        interface = "eth0"  # 리눅스 기준, 윈도우는 인터페이스 이름 다름
        if os.name == 'nt':
            interface = "Ethernet"  # 윈도우 기본 이름, 실제 환경에 맞게 변경 필요
            
        if manager.start_monitoring(interface):
            print(f"인터페이스 {interface}에서 수리카타 모니터링 시작됨")
            
            # 10초간 실행 후 종료
            time.sleep(10)
            
            # 경고 확인
            alerts = manager.get_alerts()
            print(f"탐지된 경고 수: {len(alerts)}")
            for alert in alerts[:5]:  # 처음 5개만 출력
                print(f"- {alert.get('alert', {}).get('signature', '알 수 없음')}")
            
            # 모니터링 중지
            manager.stop_monitoring()
            print("수리카타 모니터링 중지됨")
        else:
            print("수리카타 모니터링 시작 실패")
    
    finally:
        # 종료
        manager.shutdown() 