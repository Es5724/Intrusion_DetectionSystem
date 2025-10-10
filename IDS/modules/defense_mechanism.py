#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
방어 메커니즘 모듈 - IDS 시스템의 공격 대응 기능을 제공

이 모듈은 침입 탐지 시스템에서 악의적인 트래픽을 차단하고,
관리자에게 알림을 보내며, 자동 방어 기능을 제공합니다.
"""
import os
import sys
import time
import socket
import logging
import logging.handlers
import subprocess
import smtplib
import json
import threading
import gc  # 가비지 컬렉션 명시적 호출용
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# 수리카타 매니저 추가 시도
try:
    from .suricata_manager import SuricataManager
    SURICATA_SUPPORT = True
except ImportError:
    SURICATA_SUPPORT = False

# 위협 알림 시스템 추가
try:
    from .threat_alert_system import ThreatAlertSystem
    THREAT_ALERT_SUPPORT = True
except ImportError:
    try:
        from threat_alert_system import ThreatAlertSystem
        THREAT_ALERT_SUPPORT = True
    except ImportError:
        THREAT_ALERT_SUPPORT = False
        print("위협 알림 시스템을 찾을 수 없습니다. 기본 알림 기능만 사용됩니다.")

# 포트 스캔 탐지 시스템 추가
try:
    from .port_scan_detector import PortScanDetector, VulnerabilityScanner, SecurityHardening
    PORT_SCAN_SUPPORT = True
except ImportError:
    try:
        from port_scan_detector import PortScanDetector, VulnerabilityScanner, SecurityHardening
        PORT_SCAN_SUPPORT = True
    except ImportError:
        PORT_SCAN_SUPPORT = False
        print("포트 스캔 탐지 시스템을 찾을 수 없습니다. 기본 탐지 기능만 사용됩니다.")

# 로그 디렉토리 생성
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 로그 파일 경로
log_file = os.path.join(log_dir, "defense_actions.log")

# 로깅 설정 - 로테이팅 파일 핸들러 사용
logger = logging.getLogger("DefenseMechanism")
logger.setLevel(logging.INFO)

# 기존 핸들러 제거 (재시작 시 중복 방지)
for handler in logger.handlers[:]:
    logger.removeHandler(handler)

# 로테이팅 파일 핸들러 추가 (5MB마다 로테이션, 최대 5개 백업 유지)
file_handler = logging.handlers.RotatingFileHandler(
    log_file, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8'
)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# 콘솔 핸들러 추가
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(console_handler)

# 🔥 로그 버퍼링을 위한 메모리 캐시 (크기 증가 및 비동기 처리)
log_cache = []
MAX_LOG_CACHE_SIZE = 500  # 최대 로그 캐시 크기 (100 -> 500)
log_cache_lock = threading.Lock()
last_flush_time = time.time()
FLUSH_INTERVAL = 5.0  # 5초마다 강제 플러시

def log_with_cache(level, message):
    """메모리 효율적인 로깅 함수 (개선됨)"""
    global log_cache, last_flush_time
    
    # 로그 캐시에 추가 (락 최소화)
    with log_cache_lock:
        log_cache.append((level, message))
        cache_size = len(log_cache)
        current_time = time.time()
        
        # 크기 또는 시간 기준으로 플러시
        should_flush = (cache_size >= MAX_LOG_CACHE_SIZE or 
                       (current_time - last_flush_time) >= FLUSH_INTERVAL)
    
    # 락 밖에서 플러시 (블로킹 최소화)
    if should_flush:
        flush_log_cache()

def flush_log_cache():
    """로그 캐시를 파일에 기록하고 메모리 정리 (개선됨)"""
    global log_cache, last_flush_time
    
    # 로컬 복사본 생성 (락 시간 최소화)
    with log_cache_lock:
        if not log_cache:
            return
        
        local_cache = log_cache[:]
        log_cache.clear()
        last_flush_time = time.time()
    
    # 락 밖에서 로깅 수행 (블로킹 최소화)
    try:
        for level, message in local_cache:
            if level == 'INFO':
                logger.info(message)
            elif level == 'ERROR':
                logger.error(message)
            elif level == 'WARNING':
                logger.warning(message)
            elif level == 'DEBUG':
                logger.debug(message)
    except Exception as e:
        # 로깅 실패 시에도 계속 진행
        pass
    finally:
        # 로컬 캐시 메모리 해제
        del local_cache

class DefenseManager:
    """방어 메커니즘 통합 관리 클래스"""
    
    def __init__(self, config_file=None, mode="lightweight", stats_callback=None):
        """방어 메커니즘 초기화
        
        Args:
            config_file (str): 설정 파일 경로
            mode (str): 운영 모드 ('lightweight' 또는 'performance')
            stats_callback (callable): 통계 업데이트 콜백 함수
        """
        self.mode = mode
        self.blocker = BlockMaliciousTraffic()
        self.alert_system = AlertSystem(config_file)
        # 통계 콜백 전달
        self.auto_defense = AutoDefenseActions(config_file, mode, stats_callback)
        self.is_active = True
        self.recent_threats = []
        self.thread_lock = threading.Lock()
        
        # 수리카타 관련 속성
        self.suricata_manager = None
        self.suricata_enabled = False
        
        # 위협 알림 시스템 초기화
        self.threat_alert_system = None
        if THREAT_ALERT_SUPPORT:
            # 설정 파일에서 threat_alert 섹션 읽기
            alert_config = {
                'popup_enabled': True,
                'dashboard_enabled': True,
                'medium_threat_threshold': 5
            }
            
            # 설정 파일이 있으면 해당 설정 사용
            if config_file and os.path.exists(config_file):
                try:
                    with open(config_file, 'r', encoding='utf-8') as f:
                        file_config = json.load(f)
                        if 'threat_alert' in file_config:
                            alert_config.update(file_config['threat_alert'])
                except Exception as e:
                    logger.warning(f"위협 알림 설정 로드 실패: {e}")
            
            try:
                self.threat_alert_system = ThreatAlertSystem(alert_config)
                logger.info("위협 알림 시스템 초기화 완료")
            except Exception as e:
                logger.error(f"위협 알림 시스템 초기화 실패: {e}")
                self.threat_alert_system = None
        
        # 포트 스캔 탐지 시스템 초기화
        self.port_scan_detector = None
        self.vulnerability_scanner = None
        self.security_hardening = None
        
        if PORT_SCAN_SUPPORT:
            try:
                # 설정 파일에서 port_scan 섹션 읽기
                scan_config_file = None
                if config_file and os.path.exists(config_file):
                    scan_config_file = config_file
                
                self.port_scan_detector = PortScanDetector(scan_config_file)
                self.vulnerability_scanner = VulnerabilityScanner()
                self.security_hardening = SecurityHardening()
                logger.info("포트 스캔 탐지 시스템 초기화 완료")
            except Exception as e:
                logger.error(f"포트 스캔 탐지 시스템 초기화 실패: {e}")
                self.port_scan_detector = None
        
        # 설정 파일 로드
        self.config = self._load_config(config_file)
        
        # 모드에 따른 초기화
        self._initialize_by_mode()
        
        logger.info(f"방어 메커니즘 관리자 초기화 완료 (모드: {self.mode})")
    
    def _initialize_by_mode(self):
        """현재 모드에 따른 초기화 수행"""
        if self.mode == "performance":
            if SURICATA_SUPPORT:
                try:
                    self.suricata_manager = SuricataManager()
                    self.suricata_manager.initialize()
                    self.suricata_enabled = True
                    logger.info("수리카타 통합 모듈 초기화 완료")
                except Exception as e:
                    logger.error(f"수리카타 초기화 실패: {e} - 경량 모드로 전환합니다.")
                    self.mode = "lightweight"
                    self.suricata_enabled = False
            else:
                logger.warning("수리카타 지원 모듈을 찾을 수 없습니다. 경량 모드로 전환합니다.")
                self.mode = "lightweight"
        else:
            logger.info("경량 모드로 실행 중입니다.")
    
    def switch_mode(self, new_mode):
        """운영 모드 전환
        
        Args:
            new_mode (str): 새 운영 모드 ('lightweight' 또는 'performance')
            
        Returns:
            bool: 모드 전환 성공 여부
        """
        if new_mode == self.mode:
            logger.info(f"이미 {new_mode} 모드로 실행 중입니다.")
            return True
            
        logger.info(f"{self.mode} 모드에서 {new_mode} 모드로 전환 시도 중...")
        
        if new_mode == "performance":
            # 경량 → 고성능 모드 전환
            if not SURICATA_SUPPORT:
                logger.error("수리카타 지원 모듈이 설치되지 않았습니다. 모드 전환 실패.")
                return False
                
            try:
                if not self.suricata_manager:
                    self.suricata_manager = SuricataManager()
                    
                self.suricata_manager.initialize()
                self.suricata_enabled = True
                self.mode = "performance"
                logger.info("고성능 모드로 성공적으로 전환되었습니다.")
                return True
            except Exception as e:
                logger.error(f"고성능 모드 전환 실패: {e}")
                return False
        else:
            # 고성능 → 경량 모드 전환
            if self.suricata_manager and self.suricata_enabled:
                try:
                    self.suricata_manager.shutdown()
                    self.suricata_enabled = False
                except Exception as e:
                    logger.warning(f"수리카타 종료 중 경고: {e}")
                    
            self.mode = "lightweight"
            logger.info("경량 모드로 성공적으로 전환되었습니다.")
            return True
        
    def _load_config(self, config_file):
        """설정 파일 로드"""
        default_config = {
            "defense": {
                "auto_block": True,
                "block_duration": 1800,
                "high_threat_threshold": 0.9,
                "medium_threat_threshold": 0.8,
                "low_threat_threshold": 0.7
            }
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    # 기본 설정과 병합
                    if "defense" in config:
                        default_config["defense"].update(config["defense"])
                logger.info(f"설정 파일 로드됨: {config_file}")
            except Exception as e:
                logger.error(f"설정 파일 로드 오류: {str(e)}")
        
        return default_config
    
    def handle_packet(self, packet_info):
        """
        패킷 캡처 모듈로부터 직접 패킷을 전달받아 처리하는 콜백 함수
        
        Args:
            packet_info (dict): 캡처된 패킷 정보
        """
        if not self.is_active:
            # 비활성화 상태에서도 패킷은 처리하되 방어 조치만 건너뜀
            logger.debug("방어 메커니즘이 비활성화되어 있습니다.")
            return  # 이 경우는 return이 맞음 (시스템 비활성화 상태)
        
        try:
            # 패킷 타입 확인 및 변환
            if not isinstance(packet_info, dict):
                print(f"비 딕셔너리 패킷 수신됨, 타입: {type(packet_info).__name__}")
                
                # utils.py의 convert_packet_to_dict 함수를 사용할 수 있으면 사용, 아니면 직접 변환
                try:
                    from .utils import convert_packet_to_dict
                    packet_info = convert_packet_to_dict(packet_info)
                except ImportError:
                    # 직접 변환
                    if isinstance(packet_info, str):
                        # 문자열을 간단한 딕셔너리로 변환
                        packet_info = {
                            'source': 'unknown',
                            'destination': 'unknown',
                            'protocol': 'unknown',
                            'length': len(packet_info) if packet_info else 0,
                            'info': packet_info,
                            'raw_data': packet_info
                        }
                    else:
                        # 다른 타입의 경우, 기본 값 딕셔너리 반환
                        packet_info = {
                            'source': 'unknown',
                            'destination': 'unknown',
                            'protocol': 'unknown',
                            'length': 0,
                            'info': str(packet_info),
                            'raw_data': str(packet_info)
                        }
            
            # 기본 분석 수행 (락 없이 - 읽기 전용 작업)
            prediction, confidence = self.auto_defense.analyze_packet(packet_info)
            
            # 포트 스캔 탐지 분석 추가
            port_scan_detected = False
            port_scan_risk = 0.0
            port_scan_type = "none"
            
            if self.port_scan_detector:
                try:
                    port_scan_detected, port_scan_risk, port_scan_type = self.port_scan_detector.analyze_packet(packet_info)
                    
                    if port_scan_detected:
                        logger.warning(f"포트 스캔 탐지: {packet_info.get('source', 'unknown')} -> "
                                     f"위험도: {port_scan_risk:.2f}, 패턴: {port_scan_type}")
                        
                        # 포트 스캔이 탐지되면 예측 결과와 신뢰도를 업데이트
                        if port_scan_risk > confidence:
                            prediction = 1
                            confidence = port_scan_risk
                            # 패킷 정보에 포트 스캔 정보 추가
                            packet_info['port_scan_detected'] = True
                            packet_info['port_scan_type'] = port_scan_type
                            packet_info['port_scan_risk'] = port_scan_risk
                except Exception as e:
                    logger.error(f"포트 스캔 탐지 중 오류: {e}")
            
            # 고성능 모드에서 수리카타 분석 추가
            if self.mode == "performance" and self.suricata_enabled and self.suricata_manager:
                suricata_result = self.suricata_manager.check_packet(packet_info)
                if suricata_result:
                    # 수리카타 결과로 예측 및 신뢰도 보강
                    prediction = 1  # 수리카타가 경고를 발생시켰으므로 위협으로 표시
                    suricata_confidence = suricata_result.get('suricata_confidence', 0.8)
                    
                    # 기존 신뢰도와 수리카타 신뢰도 중 높은 값 사용
                    confidence = max(confidence, suricata_confidence)
                    
                    # 패킷 정보에 수리카타 결과 추가
                    packet_info.update(suricata_result)
                    
                    logger.info(f"수리카타 경고 감지: {suricata_result.get('suricata_signature', '알 수 없음')}, "
                               f"신뢰도: {suricata_confidence:.2f}")
            
            # 위협으로 탐지된 경우 방어 조치
            if prediction == 1 and confidence >= self.config["defense"]["low_threat_threshold"]:
                source_ip = packet_info.get('source', '').split(':')[0] if ':' in packet_info.get('source', '') else packet_info.get('source', '')
                
                #  개선: 락 없이 먼저 빠른 중복 체크 (읽기 전용)
                is_duplicate = self._check_recent_threat_fast(source_ip)
                
                if is_duplicate:
                    logger.debug(f"중복 위협 무시: {source_ip} (최근에 이미 대응함)")
                    return  # 빠른 리턴으로 락 경합 방지
                
                # 중복이 아닌 경우에만 락 사용
                with self.thread_lock:
                    # 락 획득 후 재확인 (Double-checked locking pattern)
                    if not self._check_recent_threat(source_ip):
                        # 최근 위협 목록에 추가
                        self._add_recent_threat(source_ip)
                    else:
                        # 다른 스레드가 이미 추가함
                        return
                    # 수리카타 경고가 있는 경우 추가 정보 출력
                    if 'suricata_alert' in packet_info and packet_info['suricata_alert']:
                        print(f"\n[경고] 수리카타 시그니처 탐지: {packet_info.get('suricata_signature', '알 수 없음')}")
                        print(f"출발지: {source_ip}, 카테고리: {packet_info.get('suricata_category', '알 수 없음')}")
                    else:
                        print(f"\n[경고] 잠재적 공격 탐지: {source_ip} (신뢰도: {confidence:.2f})")
                    
                    # 위협 수준에 따른 대응 (락 없이 - 시간이 걸리는 작업)
                    action_taken = self.auto_defense.execute_defense_action(packet_info, confidence)
                    
                    # 포트 스캔 탐지 시 추가 대응
                    if port_scan_detected and self.security_hardening:
                        try:
                            threat_info_for_hardening = {
                                'source_ip': source_ip,
                                'risk_level': 'high' if port_scan_risk >= 0.8 else 'medium',
                                'scan_type': port_scan_type,
                                'confidence': port_scan_risk
                            }
                            
                            # 긴급 대응 조치 적용
                            hardening_actions = self.security_hardening.apply_emergency_response(threat_info_for_hardening)
                            if hardening_actions:
                                logger.info(f"포트 스캔 대응 조치 적용: {', '.join(hardening_actions)}")
                                action_taken += f" | 추가 대응: {', '.join(hardening_actions)}"
                        except Exception as e:
                            logger.error(f"포트 스캔 대응 중 오류: {e}")
                    
                    # 위협 알림 시스템에 전달
                    if self.threat_alert_system:
                        threat_info = {
                            'source_ip': source_ip,
                            'destination_ip': packet_info.get('destination', 'unknown'),
                            'confidence': confidence,
                            'protocol': packet_info.get('protocol', 'unknown'),
                            'packet_info': packet_info,
                            'action_taken': action_taken
                        }
                        
                        # 포트 스캔 정보 추가
                        if port_scan_detected:
                            threat_info['port_scan_detected'] = True
                            threat_info['port_scan_type'] = port_scan_type
                            threat_info['port_scan_risk'] = port_scan_risk
                        
                        # 수리카타 정보 추가
                        if 'suricata_alert' in packet_info and packet_info['suricata_alert']:
                            threat_info['suricata_signature'] = packet_info.get('suricata_signature', 'unknown')
                            threat_info['suricata_category'] = packet_info.get('suricata_category', 'unknown')
                        
                        self.threat_alert_system.add_threat(threat_info)
                    
                    logger.info(f"패킷 처리 완료: {source_ip} (신뢰도: {confidence:.2f})")
        except Exception as e:
            logger.error(f"패킷 처리 중 오류 발생: {str(e)}")
            print(f"패킷 처리 중 오류: {str(e)}, 패킷 타입: {type(packet_info).__name__}")
            import traceback
            traceback.print_exc()
    
    def _check_recent_threat_fast(self, ip_address):
        """최근 위협 목록에 IP가 있는지 빠르게 확인 (락 없이 읽기 전용)"""
        try:
            current_time = time.time()
            # 락 없이 읽기만 수행 (race condition 가능하지만 성능 우선)
            for threat in self.recent_threats:
                if threat["ip"] == ip_address and (current_time - threat["timestamp"] <= 5):
                    return True
            return False
        except:
            # 예외 발생 시 안전하게 False 반환
            return False
    
    def _check_recent_threat(self, ip_address):
        """최근 위협 목록에 IP가 있는지 확인 (락 안에서 호출됨)"""
        # 5초 이내의 중복 처리 방지
        current_time = time.time()
        
        # 오래된 항목 제거 (리스트 컴프리헨션 사용)
        self.recent_threats = [
            threat for threat in self.recent_threats 
            if current_time - threat["timestamp"] <= 5
        ]
        
        # IP 존재 여부 확인
        for threat in self.recent_threats:
            if threat["ip"] == ip_address:
                return True
        
        return False
    
    def _add_recent_threat(self, ip_address):
        """최근 위협 목록에 IP 추가"""
        self.recent_threats.append({
            "ip": ip_address,
            "timestamp": time.time()
        })
        # 목록 크기 제한
        if len(self.recent_threats) > 100:
            self.recent_threats.pop(0)
    
    def register_to_packet_capture(self, packet_capture_core):
        """패킷 캡처 코어에 콜백 함수 등록"""
        if packet_capture_core:
            result = packet_capture_core.register_defense_module(self.handle_packet)
            
            # 고성능 모드인 경우 수리카타 모니터링 시작
            if result and self.mode == "performance" and self.suricata_enabled and self.suricata_manager:
                # 패킷 캡처와 동일한 인터페이스에서 수리카타 모니터링 시작
                interface = packet_capture_core.get_active_interface()
                if interface:
                    self.suricata_manager.start_monitoring(interface)
                    logger.info(f"수리카타 모니터링 시작: 인터페이스 {interface}")
            
            return result
        return False
    
    def activate(self):
        """방어 메커니즘 활성화"""
        self.is_active = True
        logger.info("방어 메커니즘 활성화됨")
    
    def deactivate(self):
        """방어 메커니즘 비활성화"""
        self.is_active = False
        # 수리카타 모니터링 중지
        if self.suricata_enabled and self.suricata_manager:
            self.suricata_manager.stop_monitoring()
        logger.info("방어 메커니즘 비활성화됨")
    
    def get_status(self):
        """방어 메커니즘 상태 반환"""
        status = {
            "is_active": self.is_active,
            "mode": self.mode,
            "blocked_ips": self.blocker.get_blocked_ips(),
            "alert_enabled": self.alert_system.email_config["enabled"],
            "config": self.config
        }
        
        # 수리카타 관련 상태 추가
        if self.mode == "performance":
            status["suricata_enabled"] = self.suricata_enabled
            if self.suricata_enabled and self.suricata_manager:
                status["suricata_running"] = self.suricata_manager.is_running
        
        return status
    
    def perform_port_scan(self, target_ip: str, ports: List[int]) -> Dict:
        """
        대상 IP에 대한 포트 스캔 수행
        
        Args:
            target_ip (str): 스캔할 대상 IP
            ports (List[int]): 스캔할 포트 목록
            
        Returns:
            Dict: 스캔 결과 및 취약점 분석
        """
        try:
            # utils.py의 syn_scan 함수 사용
            from .utils import syn_scan
            
            # 포트 스캔 수행
            scan_result = syn_scan(target_ip, ports)
            
            if not scan_result:
                return {'error': '스캔 실패', 'target_ip': target_ip}
            
            # 열린 포트에 대한 취약점 분석
            vulnerability_analysis = {}
            if self.vulnerability_scanner and scan_result.get('open'):
                vulnerability_analysis = self.vulnerability_scanner.analyze_open_ports(
                    scan_result['open'], target_ip
                )
            
            # 보안 강화 권장사항 생성
            recommendations = []
            if self.security_hardening and vulnerability_analysis:
                recommendations = self.security_hardening.generate_hardening_recommendations(
                    vulnerability_analysis
                )
            
            result = {
                'target_ip': target_ip,
                'scan_result': scan_result,
                'vulnerability_analysis': vulnerability_analysis,
                'security_recommendations': recommendations,
                'scan_timestamp': datetime.now().isoformat()
            }
            
            logger.info(f"포트 스캔 완료: {target_ip}, 열린 포트: {len(scan_result.get('open', []))}개")
            return result
            
        except Exception as e:
            logger.error(f"포트 스캔 중 오류: {e}")
            return {'error': str(e), 'target_ip': target_ip}
    
    def get_port_scan_statistics(self, source_ip: str) -> Dict:
        """
        특정 IP의 포트 스캔 통계 조회
        
        Args:
            source_ip (str): 조회할 IP 주소
            
        Returns:
            Dict: 스캔 통계 정보
        """
        if self.port_scan_detector:
            return self.port_scan_detector.get_scan_statistics(source_ip)
        return {}
    
    def generate_security_report(self, scan_results: List[Dict] = None) -> str:
        """
        보안 취약점 분석 보고서 생성
        
        Args:
            scan_results (List[Dict]): 스캔 결과 목록 (없으면 기본 보고서)
            
        Returns:
            str: 보안 보고서 텍스트
        """
        if self.vulnerability_scanner:
            if scan_results:
                # 취약점 분석 결과만 추출
                vulnerability_results = []
                for result in scan_results:
                    if 'vulnerability_analysis' in result:
                        vulnerability_results.append(result['vulnerability_analysis'])
                
                if vulnerability_results:
                    return self.vulnerability_scanner.generate_security_report(vulnerability_results)
            
            # 기본 보고서 생성
            return self.vulnerability_scanner.generate_security_report([])
        
        return "취약점 스캐너가 초기화되지 않았습니다."
    
    def shutdown(self):
        """방어 메커니즘 종료"""
        self.deactivate()
        if self.suricata_enabled and self.suricata_manager:
            self.suricata_manager.shutdown()
        if self.threat_alert_system:
            self.threat_alert_system.shutdown()
        if self.port_scan_detector:
            self.port_scan_detector.shutdown()
        logger.info("방어 메커니즘 종료됨")


class BlockMaliciousTraffic:
    """악의적인 트래픽 차단을 위한 클래스"""
    
    def __init__(self):
        """방화벽 규칙 관리를 위한 초기화"""
        self.blocked_ips = set()
        self.block_history = []
        self.os_type = os.name
        
        # 기존 차단 기록 및 방화벽 규칙 복원
        self._load_block_history()
        self._sync_with_firewall()
        
        logger.info("트래픽 차단 시스템 초기화 완료")
    
    def block_ip(self, ip_address):
        """
        악의적인 IP 주소를 방화벽에서 차단     
        Args:
            ip_address (str): 차단할 IP 주소
        Returns:
            bool: 차단 성공 여부
        """
        if not self._is_valid_ip(ip_address):
            logger.error(f"유효하지 않은 IP 주소: {ip_address}")
            return False
        
        # 사설 IP 보호 (차단 금지)
        if self._is_private_ip(ip_address):
            logger.warning(f"사설 IP 차단 시도 차단됨: {ip_address} (내부 네트워크 보호)")
            return False
        
        if ip_address in self.blocked_ips:
            logger.info(f"이미 차단된 IP 주소: {ip_address}")
            return True
        try:
            # OS별 방화벽 명령어 실행
            if self.os_type == 'nt':  # Windows
                result = self._block_ip_windows(ip_address)
            else:  # Linux/Unix
                result = self._block_ip_linux(ip_address)
            if result:
                # 방화벽 규칙이 실제로 적용되었는지 검증 (비동기적으로 처리)
                # time.sleep 제거 - 방화벽 규칙은 즉시 적용됨
                if self.verify_firewall_rule(ip_address):
                    self.blocked_ips.add(ip_address)
                    block_event = {
                        "ip": ip_address,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "success": True
                    }
                    self.block_history.append(block_event)
                    self._save_block_history()
                    logger.info(f"✅ IP 주소 차단 성공 및 검증 완료: {ip_address}")
                    return True
                else:
                    logger.error(f"⚠️ 방화벽 규칙 추가는 성공했으나 검증 실패: {ip_address}")
                    return False
            else:
                logger.error(f"❌ IP 주소 차단 실패: {ip_address}")
                return False
                
        except Exception as e:
            logger.error(f"IP 차단 중 오류 발생: {str(e)}")
            return False
    
    def unblock_ip(self, ip_address):
        """
        차단된 IP 주소를 방화벽에서 해제
        
        Args:
            ip_address (str): 해제할 IP 주소
            
        Returns:
            bool: 해제 성공 여부
        """
        if not self._is_valid_ip(ip_address):
            logger.error(f"유효하지 않은 IP 주소: {ip_address}")
            return False
        
        if ip_address not in self.blocked_ips:
            logger.info(f"차단되지 않은 IP 주소: {ip_address}")
            return True
        
        try:
            # OS별 방화벽 명령어 실행
            if self.os_type == 'nt':  # Windows
                result = self._unblock_ip_windows(ip_address)
            else:  # Linux/Unix
                result = self._unblock_ip_linux(ip_address)
            
            if result:
                self.blocked_ips.remove(ip_address)
                unblock_event = {
                    "ip": ip_address,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "unblock",
                    "success": True
                }
                self.block_history.append(unblock_event)
                self._save_block_history()
                logger.info(f"IP 주소 차단 해제 성공: {ip_address}")
                return True
            else:
                logger.error(f"IP 주소 차단 해제 실패: {ip_address}")
                return False
                
        except Exception as e:
            logger.error(f"IP 차단 해제 중 오류 발생: {str(e)}")
            return False
    
    def get_blocked_ips(self):
        """
        현재 차단된 IP 주소 목록 반환
        
        Returns:
            list: 차단된 IP 주소 목록
        """
        return list(self.blocked_ips)
    
    def _block_ip_windows(self, ip_address):
        """Windows 방화벽에서 IP 차단 (인바운드 + 아웃바운드)"""
        try:
            rule_name = f"IDS_Block_{ip_address.replace('.', '_')}"
            
            # 인바운드 차단 규칙 (타임아웃 5초)
            command_in = f'netsh advfirewall firewall add rule name="{rule_name}_IN" dir=in action=block remoteip={ip_address}'
            process_in = subprocess.run(command_in, shell=True, capture_output=True, text=True, timeout=5)
            
            # 아웃바운드 차단 규칙 (타임아웃 5초)
            command_out = f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block remoteip={ip_address}'
            process_out = subprocess.run(command_out, shell=True, capture_output=True, text=True, timeout=5)
            
            # 둘 다 성공해야 True
            success = process_in.returncode == 0 and process_out.returncode == 0
            
            if not success:
                # 실패 원인 로깅
                if process_in.returncode != 0:
                    logger.error(f"인바운드 차단 실패: {process_in.stderr}")
                if process_out.returncode != 0:
                    logger.error(f"아웃바운드 차단 실패: {process_out.stderr}")
                
                # 관리자 권한 확인
                if "액세스가 거부되었습니다" in process_in.stderr or "Access is denied" in process_in.stderr:
                    logger.error("⚠️ 관리자 권한이 필요합니다! 프로그램을 관리자 권한으로 실행하세요.")
            else:
                logger.info(f"✅ Windows 방화벽 규칙 추가 완료: {rule_name} (IN+OUT)")
            
            return success
        except subprocess.TimeoutExpired:
            logger.error(f"방화벽 명령 타임아웃: {ip_address} (5초 초과)")
            return False
        except Exception as e:
            logger.error(f"Windows IP 차단 중 오류: {str(e)}")
            return False
    
    def _unblock_ip_windows(self, ip_address):
        """Windows 방화벽에서 IP 차단 해제 (인바운드 + 아웃바운드)"""
        try:
            rule_name = f"IDS_Block_{ip_address.replace('.', '_')}"
            
            # 인바운드 규칙 삭제 (타임아웃 5초)
            command_in = f'netsh advfirewall firewall delete rule name="{rule_name}_IN"'
            process_in = subprocess.run(command_in, shell=True, capture_output=True, text=True, timeout=5)
            
            # 아웃바운드 규칙 삭제 (타임아웃 5초)
            command_out = f'netsh advfirewall firewall delete rule name="{rule_name}_OUT"'
            process_out = subprocess.run(command_out, shell=True, capture_output=True, text=True, timeout=5)
            
            # 둘 중 하나라도 성공하면 OK (규칙이 없을 수도 있음)
            success = process_in.returncode == 0 or process_out.returncode == 0
            
            if success:
                logger.info(f"✅ Windows 방화벽 규칙 삭제 완료: {rule_name}")
            
            return success
        except subprocess.TimeoutExpired:
            logger.error(f"방화벽 명령 타임아웃: {ip_address} (5초 초과)")
            return False
        except Exception as e:
            logger.error(f"Windows IP 차단 해제 중 오류: {str(e)}")
            return False
    
    def _block_ip_linux(self, ip_address):
        """Linux 방화벽(iptables)에서 IP 차단"""
        try:
            command = f'iptables -A INPUT -s {ip_address} -j DROP'
            process = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
            return process.returncode == 0
        except subprocess.TimeoutExpired:
            logger.error(f"iptables 명령 타임아웃: {ip_address} (5초 초과)")
            return False
        except Exception as e:
            logger.error(f"Linux IP 차단 중 오류: {str(e)}")
            return False
    
    def _unblock_ip_linux(self, ip_address):
        """Linux 방화벽(iptables)에서 IP 차단 해제"""
        try:
            command = f'iptables -D INPUT -s {ip_address} -j DROP'
            process = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
            return process.returncode == 0
        except subprocess.TimeoutExpired:
            logger.error(f"iptables 명령 타임아웃: {ip_address} (5초 초과)")
            return False
        except Exception as e:
            logger.error(f"Linux IP 차단 해제 중 오류: {str(e)}")
            return False
    
    def verify_firewall_rule(self, ip_address):
        """
        방화벽 규칙이 실제로 적용되었는지 확인
        
        Args:
            ip_address (str): 확인할 IP 주소
            
        Returns:
            bool: 규칙 존재 여부
        """
        try:
            if self.os_type == 'nt':  # Windows
                rule_name = f"IDS_Block_{ip_address.replace('.', '_')}"
                command = f'netsh advfirewall firewall show rule name="{rule_name}_IN"'
                process = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
                return process.returncode == 0
            else:  # Linux
                command = f'iptables -L INPUT -n | grep {ip_address}'
                process = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
                return ip_address in process.stdout
        except subprocess.TimeoutExpired:
            logger.error(f"방화벽 규칙 확인 타임아웃: {ip_address} (5초 초과)")
            return False
        except Exception as e:
            logger.error(f"방화벽 규칙 확인 중 오류: {str(e)}")
            return False
    
    def _is_valid_ip(self, ip_address):
        """IP 주소 유효성 검사"""
        try:
            socket.inet_aton(ip_address)
            return True
        except:
            return False
    
    def _is_private_ip(self, ip_address):
        """사설 IP 주소 확인 (차단 금지 대상)"""
        try:
            # 사설 IP 범위 확인
            private_ranges = [
                '127.',          # 루프백
                '10.',           # Class A 사설 IP
                '172.16.', '172.17.', '172.18.', '172.19.',  # Class B 사설 IP 시작
                '172.20.', '172.21.', '172.22.', '172.23.',
                '172.24.', '172.25.', '172.26.', '172.27.',
                '172.28.', '172.29.', '172.30.', '172.31.',  # Class B 사설 IP 끝
                '192.168.'       # Class C 사설 IP
            ]
            
            return any(ip_address.startswith(prefix) for prefix in private_ranges)
        except:
            return False
    
    def _load_block_history(self):
        """차단 기록 로드"""
        try:
            if os.path.exists('blocked_ips_history.json'):
                with open('blocked_ips_history.json', 'r', encoding='utf-8') as f:
                    self.block_history = json.load(f)
                
                # 차단 기록에서 현재 차단된 IP 추출 (unblock되지 않은 IP만)
                blocked_ips_dict = {}
                for event in self.block_history:
                    ip = event.get('ip')
                    action = event.get('action', 'block')
                    
                    if action == 'block' or 'action' not in event:
                        blocked_ips_dict[ip] = True
                    elif action == 'unblock':
                        blocked_ips_dict[ip] = False
                
                # 차단 상태인 IP만 blocked_ips에 추가
                for ip, is_blocked in blocked_ips_dict.items():
                    if is_blocked:
                        self.blocked_ips.add(ip)
                
                if self.blocked_ips:
                    logger.info(f"차단 기록 로드 완료: {len(self.blocked_ips)}개 IP")
        except Exception as e:
            logger.error(f"차단 기록 로드 중 오류: {str(e)}")
    
    def _sync_with_firewall(self):
        """방화벽 규칙과 blocked_ips 동기화"""
        try:
            if self.os_type == 'nt':  # Windows
                # 현재 방화벽에 있는 IDS 규칙 확인 (타임아웃 10초)
                command = 'netsh advfirewall firewall show rule name=all | findstr "IDS_Block"'
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
                
                if result.stdout:
                    # 규칙 이름에서 IP 추출
                    for line in result.stdout.split('\n'):
                        if 'Rule Name:' in line and 'IDS_Block_' in line:
                            # IDS_Block_192_168_1_1_IN -> 192.168.1.1
                            rule_name = line.split('Rule Name:')[1].strip()
                            if rule_name.startswith('IDS_Block_'):
                                # _IN 또는 _OUT 제거
                                ip_part = rule_name.replace('IDS_Block_', '').replace('_IN', '').replace('_OUT', '')
                                # 언더스코어를 점으로 변환
                                ip = ip_part.replace('_', '.')
                                
                                # 유효한 IP인지 확인
                                if self._is_valid_ip(ip):
                                    self.blocked_ips.add(ip)
                    
                    if self.blocked_ips:
                        logger.info(f"방화벽 규칙 동기화 완료: {len(self.blocked_ips)}개 IP")
            else:  # Linux
                # iptables 규칙 확인 (타임아웃 10초)
                command = 'iptables -L INPUT -n | grep DROP'
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
                
                if result.stdout:
                    for line in result.stdout.split('\n'):
                        # IP 추출 로직
                        parts = line.split()
                        if len(parts) >= 4:
                            ip = parts[3]
                            if self._is_valid_ip(ip):
                                self.blocked_ips.add(ip)
                    
                    if self.blocked_ips:
                        logger.info(f"방화벽 규칙 동기화 완료: {len(self.blocked_ips)}개 IP")
        except subprocess.TimeoutExpired:
            logger.error(f"방화벽 동기화 타임아웃 (10초 초과) - 건너뜀")
        except Exception as e:
            logger.error(f"방화벽 규칙 동기화 중 오류: {str(e)}")
    
    def _save_block_history(self):
        """차단 기록 저장"""
        try:
            with open('blocked_ips_history.json', 'w', encoding='utf-8') as f:
                json.dump(self.block_history, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logger.error(f"차단 기록 저장 중 오류: {str(e)}")
            
class AlertSystem:
    """관리자에게 알림을 보내는 시스템"""
    def __init__(self, config_file=None):
        """알림 시스템 초기화"""
        self.alerts = []
        self.email_config = {
            "enabled": False,
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "username": "",
            "password": "",
            "recipient": ""
        }
        
        # 설정 파일이 있으면 로드
        if config_file and os.path.exists(config_file):
            self._load_config(config_file)
        
        logger.info("알림 시스템 초기화 완료")
    
    def send_alert(self, alert_info):
        """
        경고 알림 발송
        
        Args:
            alert_info (dict): 알림 정보 (소스 IP, 타임스탬프, 프로토콜 등)
        
        Returns:
            bool: 알림 발송 성공 여부
        """
        try:
            # 콘솔에 경고 출력
            alert_text = self._format_alert(alert_info)
            print("\n" + "!"*50)
            print(alert_text)
            print("!"*50)
            
            # 알림 기록 저장
            self.alerts.append(alert_info)
            self._save_alerts()
            
            # 이메일 알림 설정이 활성화된 경우 이메일 발송
            if self.email_config["enabled"]:
                self._send_email_alert(alert_info)
            
            logger.info(f"알림 발송 성공: {alert_info['source_ip']}")
            return True
            
        except Exception as e:
            logger.error(f"알림 발송 중 오류: {str(e)}")
            return False
    
    def _format_alert(self, alert_info):
        """알림 정보 서식화"""
        alert_text = f"[보안 경고] 잠재적 공격 탐지\n"
        alert_text += f"시간: {alert_info.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n"
        alert_text += f"출발지 IP: {alert_info.get('source_ip', 'Unknown')}\n"
        alert_text += f"프로토콜: {alert_info.get('protocol', 'Unknown')}\n"
        alert_text += f"신뢰도: {alert_info.get('confidence', 0):.2f}\n"
        alert_text += f"취한 조치: {alert_info.get('action_taken', '없음')}"
        return alert_text
    
    def _send_email_alert(self, alert_info):
        """이메일로 알림 발송"""
        try:
            if not all([
                self.email_config["smtp_server"],
                self.email_config["username"],
                self.email_config["password"],
                self.email_config["recipient"]
            ]):
                logger.error("이메일 설정이 완료되지 않았습니다.")
                return False
            
            # 이메일 메시지 생성
            msg = MIMEMultipart()
            msg['From'] = self.email_config["username"]
            msg['To'] = self.email_config["recipient"]
            msg['Subject'] = f"[IDS 경고] 잠재적 공격 탐지 - {alert_info.get('source_ip', 'Unknown')}"
            
            body = self._format_alert(alert_info)
            msg.attach(MIMEText(body, 'plain'))
            
            # SMTP 서버로 이메일 발송
            with smtplib.SMTP(self.email_config["smtp_server"], self.email_config["smtp_port"]) as server:
                server.starttls()
                server.login(self.email_config["username"], self.email_config["password"])
                server.send_message(msg)
            
            logger.info(f"이메일 알림 발송 성공: {self.email_config['recipient']}")
            return True
            
        except Exception as e:
            logger.error(f"이메일 알림 발송 중 오류: {str(e)}")
            return False
    
    def _save_alerts(self):
        """알림 기록 저장"""
        try:
            with open('security_alerts.json', 'w', encoding='utf-8') as f:
                json.dump(self.alerts, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logger.error(f"알림 기록 저장 중 오류: {str(e)}")
    
    def _load_config(self, config_file):
        """설정 파일에서 알림 설정 로드"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                if "email" in config:
                    self.email_config.update(config["email"])
                    if all([
                        self.email_config["smtp_server"],
                        self.email_config["username"],
                        self.email_config["password"],
                        self.email_config["recipient"]
                    ]):
                        self.email_config["enabled"] = True
        except Exception as e:
            logger.error(f"설정 파일 로드 중 오류: {str(e)}")


class AutoDefenseActions:
    """위협 수준에 따른 자동 방어 조치 실행"""
    
    def __init__(self, config=None, mode="lightweight", stats_callback=None):
        # 설정 파일 로드
        self.config = {}
        
        # config가 문자열(파일 경로)인 경우 파일에서 로드
        if isinstance(config, str):
            try:
                if os.path.exists(config):
                    with open(config, 'r', encoding='utf-8') as f:
                        self.config = json.load(f)
                    print(f"파일에서 설정 로드됨: {config}")
                else:
                    print(f"설정 파일을 찾을 수 없음: {config}")
            except Exception as e:
                print(f"설정 파일 로드 오류: {str(e)}")
        # config가 딕셔너리인 경우 그대로 사용
        elif isinstance(config, dict):
            self.config = config
        
        self.is_enabled = self.config.get('auto_defense_enabled', True)
        self.threshold = self.config.get('defense_threshold', 0.8)
        self.action_history = []
        self.action_history_max_size = self.config.get('action_history_max_size', 1000)
        self.blocker = BlockMaliciousTraffic()
        self.alert_system = AlertSystem(self.config.get('alert', {}))
        
        #  통계 업데이트 콜백 (대시보드 통계 연동)
        self.stats_callback = stats_callback
        
        #  누적 기반 차단 시스템
        self.threat_accumulation = {}  # IP별 위협 누적 추적
        self.accumulation_lock = threading.Lock()
        
        # 누적 임계값 설정
        self.medium_threat_count_threshold = 3   # 1분 내 3회
        self.medium_threat_time_window = 60      # 1분
        self.low_threat_count_threshold = 10     # 5분 내 10회
        self.low_threat_time_window = 300        # 5분
        
        # 기존 기록 로드
        self._load_action_history()
        
        # 선택적으로 수리카타 활성화 (고성능 모드에서만)
        self.suricata_enabled = False
        if mode == "performance" and SURICATA_SUPPORT:
            try:
                self.suricata = SuricataManager()
                self.suricata_enabled = self.suricata.is_available()
                if self.suricata_enabled:
                    log_with_cache('INFO', "수리카타 엔진 로드 성공")
                else:
                    log_with_cache('WARNING', "수리카타 엔진 로드 실패")
            except Exception as e:
                log_with_cache('ERROR', f"수리카타 엔진 초기화 오류: {str(e)}")
        
        log_with_cache('INFO', f"자동 방어 시스템 초기화 완료 (모드: {mode})")
    
    def analyze_packet(self, packet):
        """
        패킷 분석 및 위협 예측
        
        Args:
            packet (dict): 분석할 패킷 정보
            
        Returns:
            tuple: (예측 결과, 신뢰도) - 1=공격, 0=정상
        """
        try:
            # 유효한 패킷 확인
            if not isinstance(packet, dict):
                log_with_cache('DEBUG', f"analyze_packet - 유효하지 않은 패킷 타입: {type(packet).__name__}")
                # 문자열을 딕셔너리로 변환 시도
                if isinstance(packet, str):
                    packet = {
                        'source': 'unknown',
                        'destination': 'unknown',
                        'protocol': 'unknown',
                        'length': len(packet) if packet else 0,
                        'info': packet,
                        'raw_data': packet
                    }
                else:
                    return 0, 0.5
                
            # 필수 필드 존재 확인
            if 'info' not in packet and 'protocol' not in packet:
                log_with_cache('DEBUG', f"analyze_packet - 필수 필드 누락: {packet.keys()}")
                return 0, 0.5
                
            info = str(packet.get('info', '')).lower()
            protocol = str(packet.get('protocol', '')).lower()
            raw_data = str(packet.get('raw_data', '')).lower()
            
            # 프로토콜 번호를 문자열로 변환
            if protocol == '6':  # TCP
                protocol = 'tcp'
            elif protocol == '17':  # UDP
                protocol = 'udp'
            elif protocol == '1':  # ICMP
                protocol = 'icmp'
            
            # 포트 추출
            dest_port = 0
            src_port = 0
            dest = packet.get('destination', '')
            src = packet.get('source', '')
            
            if ':' in dest:
                try:
                    dest_port = int(dest.split(':')[1])
                except:
                    pass
            
            if ':' in src:
                try:
                    src_port = int(src.split(':')[1])
                except:
                    pass
            
            # === 개선된 위협 탐지 로직 ===
            
            # 1. SYN 플러딩 검사
            if ('tcp' in protocol) and 'syn' in info:
                log_with_cache('DEBUG', f"SYN 플러딩 탐지: {src} -> {dest}")
                return 1, 0.95
            
            # 2. TCP 핸드셰이크 오용 (RST 플래그)
            if ('tcp' in protocol) and 'rst' in info:
                log_with_cache('DEBUG', f"TCP RST 공격 탐지: {src} -> {dest}")
                return 1, 0.90
            
            # 3. HTTP Slowloris 공격
            if protocol == 'tcp' and dest_port == 80:
                # Slowloris 특징: X-Header, keep-alive, 불완전한 HTTP 요청
                slowloris_patterns = ['x-header', 'x-a:', 'x-b:', 'x-c:']
                if any(pattern in info or pattern in raw_data for pattern in slowloris_patterns):
                    log_with_cache('DEBUG', f"HTTP Slowloris 탐지: {src} -> {dest}")
                    return 1, 0.88
                
                # Keep-alive와 GET이 함께 있으면서 불완전한 요청
                if 'keep-alive' in info and 'get' in info and '\r\n\r\n' not in raw_data:
                    log_with_cache('DEBUG', f"HTTP Slowloris (불완전 요청) 탐지: {src} -> {dest}")
                    return 1, 0.85
            
            # 4. HTTP 요청 변조 공격 (SQL Injection, XSS, Path Traversal)
            if protocol == 'tcp' and dest_port == 80:
                malicious_patterns = [
                    # Path Traversal
                    ('../', 0.92, 'Path Traversal'),
                    ('etc/passwd', 0.92, 'Path Traversal'),
                    ('..\\.', 0.92, 'Path Traversal'),
                    
                    # SQL Injection
                    ('or 1=1', 0.93, 'SQL Injection'),
                    ("or '1'='1", 0.93, 'SQL Injection'),
                    ('union select', 0.95, 'SQL Injection'),
                    ('drop table', 0.95, 'SQL Injection'),
                    
                    # XSS
                    ('<script>', 0.93, 'XSS'),
                    ('alert(', 0.90, 'XSS'),
                    ('onerror=', 0.90, 'XSS'),
                    ('javascript:', 0.90, 'XSS'),
                ]
                
                for pattern, confidence, attack_type in malicious_patterns:
                    if pattern in info or pattern in raw_data:
                        log_with_cache('INFO', f"{attack_type} 탐지: {src} -> {dest}, 패턴: {pattern}")
                        return 1, confidence
            
            # 5. SSL/TLS 포트 공격 (443)
            if protocol == 'tcp' and dest_port == 443:
                # 비정상적인 SSL 핸드셰이크 시도
                if 'syn' in info:
                    log_with_cache('DEBUG', f"SSL 포트 SYN 공격 탐지: {src} -> {dest}")
                    return 1, 0.85
            
            # 6. UDP 플러딩
            if protocol == 'udp':
                # UDP 플러딩은 짧은 시간 내 다수 패킷으로 판단
                # 현재는 UDP 프로토콜 자체를 의심
                if dest_port in [53, 123, 161]:  # DNS, NTP, SNMP (증폭 공격에 사용)
                    log_with_cache('DEBUG', f"UDP 증폭 공격 가능성: {src} -> {dest}:{dest_port}")
                    return 1, 0.80
                else:
                    log_with_cache('DEBUG', f"UDP 플러딩 가능성: {src} -> {dest}")
                    return 1, 0.75
            
            # 7. ICMP 리다이렉트 공격
            if protocol == 'icmp':
                icmp_type = packet.get('icmp_type', packet.get('type', 0))
                if icmp_type == 5:  # ICMP Redirect
                    log_with_cache('INFO', f"ICMP 리다이렉트 공격 탐지: {src} -> {dest}")
                    return 1, 0.92
                # ICMP 플러딩
                log_with_cache('DEBUG', f"ICMP 플러딩 가능성: {src} -> {dest}")
                return 1, 0.78
            
            # 8. ARP 스푸핑
            if 'arp' in protocol.lower() or packet.get('protocol') == 'ARP':
                log_with_cache('INFO', f"ARP 스푸핑 탐지: {src} -> {dest}")
                return 1, 0.85
            
            # 9. 비정상적인 패킷 크기
            packet_length = packet.get('length', 0)
            if packet_length > 5000:
                log_with_cache('DEBUG', f"비정상 패킷 크기 탐지: {packet_length} bytes, {src} -> {dest}")
                return 1, 0.90
            
            # 10. 확장된 악성 포트 체크
            suspicious_ports = [
                # 해킹 도구
                4444, 31337, 1337,
                # IRC (봇넷)
                6667, 6668, 6669,
                # 백도어
                12345, 27374, 27665,
                # 트로이 목마
                1243, 6711, 6776,
                # 원격 접근 도구
                5900, 5901,  # VNC
            ]
            
            if dest_port in suspicious_ports:
                log_with_cache('INFO', f"악성 포트 접근 탐지: {src} -> {dest}:{dest_port}")
                return 1, 0.92
            
            # 11. 포트 스캔 패턴 (다양한 포트로의 접근)
            if dest_port > 0:
                # 일반적이지 않은 포트 범위
                if dest_port > 49152:  # 동적/사설 포트
                    log_with_cache('DEBUG', f"비정상 포트 접근: {src} -> {dest}:{dest_port}")
                    return 1, 0.70
            
            # 정상 패킷으로 판단
            return 0, 0.65
            
        except Exception as e:
            log_with_cache('ERROR', f"패킷 분석 중 오류: {str(e)}")
            log_with_cache('DEBUG', f"패킷 분석 중 오류 발생: {str(e)}, 패킷 타입: {type(packet).__name__ if packet is not None else 'None'}")
            import traceback
            log_with_cache('DEBUG', traceback.format_exc())
            return 0, 0.5  # 오류 발생 시 기본값 반환
    
    def execute_defense_action(self, packet, confidence):
        """
        위협 수준에 따른 방어 조치 실행
        
        Args:
            packet (dict): 패킷 정보
            confidence (float): 위협 감지 신뢰도 (0.0 ~ 1.0)
            
        Returns:
            str: 수행된 방어 조치
        """
        if not self.is_enabled:
            log_with_cache('INFO', "자동 방어 시스템이 비활성화 되어 있습니다.")
            return "자동 방어 비활성화"
        
        try:
            # 패킷 타입 검사
            if not isinstance(packet, dict):
                log_with_cache('DEBUG', f"execute_defense_action - 유효하지 않은 패킷 타입: {type(packet).__name__}")
                return "유효하지 않은 패킷"
                
            # 로그 추가
            log_with_cache('DEBUG', f"방어 조치 실행 - 신뢰도: {confidence:.2f}, 패킷: {packet.get('source', 'N/A')} -> {packet.get('destination', 'N/A')}")
                
            source_ip = packet.get('source', '').split(':')[0] if ':' in packet.get('source', '') else packet.get('source', '')
            protocol = packet.get('protocol', '')
            
            # 프로토콜 번호를 이름으로 변환
            protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            if isinstance(protocol, int) or (isinstance(protocol, str) and protocol.isdigit()):
                protocol = protocol_map.get(int(protocol), str(protocol))
            
            #  위협 수준에 따른 대응 (함수명 일치 수정)
            if confidence >= 0.9:  # 🔴 치명적 위협
                action = "IP 영구 차단"
                self._critical_threat_response(source_ip, protocol)
            elif confidence >= 0.8:  # 🟠 높은 위협
                action = "IP 임시 차단 (30분)"
                self._high_threat_response(source_ip, protocol)
            elif confidence >= 0.7:  # 🟡 중간 위협
                action = "모니터링 강화 (누적 체크)"
                self._medium_threat_response(source_ip, protocol)
            else:  # 🟢 낮은 위협
                action = "모니터링 (누적 체크)"
                self._low_threat_response(source_ip, protocol)
            
            # 방어 조치 기록
            action_record = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": source_ip,
                "protocol": protocol,
                "confidence": confidence,
                "action": action
            }
            self.action_history.append(action_record)
            
            # 최대 기록 크기 제한
            if len(self.action_history) > self.action_history_max_size:
                # 앞에서 20%를 제거하여 빈번한 파일 쓰기 방지
                self.action_history = self.action_history[int(self.action_history_max_size * 0.2):]
            
            # 일정 크기마다 기록 저장
            if len(self.action_history) % 50 == 0:
                self._save_action_history()
            
            log_with_cache('INFO', f"방어 조치 실행: {action} - {source_ip}")
            return action
            
        except Exception as e:
            log_with_cache('ERROR', f"방어 조치 실행 중 오류: {str(e)}")
            log_with_cache('DEBUG', f"방어 조치 실행 중 오류: {str(e)}, 패킷 타입: {type(packet).__name__ if packet is not None else 'None'}")
            import traceback
            log_with_cache('DEBUG', traceback.format_exc())
            return "오류 발생"
    
    def _critical_threat_response(self, ip, protocol):
        """🔴 치명적 위협 대응 (신뢰도 ≥ 0.9) - IP 영구 차단"""
        try:
            # 사설 IP 보호 확인
            if self._is_private_ip(ip):
                log_with_cache('WARNING', f"사설 IP 영구 차단 시도 차단됨: {ip} (내부 네트워크 보호)")
                return
            
            # 1. IP 영구 차단
            self.blocker.block_ip(ip)
            log_with_cache('INFO', f"🔴 치명적 위협 - IP 영구 차단: {ip}")
            
            #  통계 업데이트
            if self.stats_callback:
                self.stats_callback('permanent_block')
            
            # 2. 관리자에게 긴급 알림
            alert_info = {
                "source_ip": ip,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "protocol": protocol,
                "confidence": 0.95,
                "action_taken": "IP 영구 차단 및 긴급 알림"
            }
            self.alert_system.send_alert(alert_info)
            
            #  통계 업데이트 (알림)
            if self.stats_callback:
                self.stats_callback('alerts')
            
            # 3. 누적 기록 초기화 (영구 차단되었으므로)
            if ip in self.threat_accumulation:
                del self.threat_accumulation[ip]
            
            log_with_cache('INFO', f"치명적 위협 대응 완료: {ip}")
            
        except Exception as e:
            log_with_cache('ERROR', f"치명적 위협 대응 중 오류: {str(e)}")
    
    def _is_private_ip(self, ip_address):
        """사설 IP 주소 확인 (차단 금지 대상)"""
        try:
            # 사설 IP 범위 확인
            private_ranges = [
                '127.',          # 루프백
                '10.',           # Class A 사설 IP
                '172.16.', '172.17.', '172.18.', '172.19.',  # Class B 사설 IP 시작
                '172.20.', '172.21.', '172.22.', '172.23.',
                '172.24.', '172.25.', '172.26.', '172.27.',
                '172.28.', '172.29.', '172.30.', '172.31.',  # Class B 사설 IP 끝
                '192.168.'       # Class C 사설 IP
            ]
            
            return any(ip_address.startswith(prefix) for prefix in private_ranges)
        except:
            return False
    
    def _high_threat_response(self, ip, protocol, is_accumulated=False):
        """🟠 높은 위협 대응 (신뢰도 0.8-0.9) - IP 임시 차단 30분"""
        try:
            # 사설 IP 보호 확인
            if self._is_private_ip(ip):
                log_with_cache('WARNING', f"사설 IP 임시 차단 시도 차단됨: {ip} (내부 네트워크 보호)")
                return
            
            # 1. 임시 IP 차단 (30분)
            self.blocker.block_ip(ip)
            log_with_cache('INFO', f"🟠 높은 위협 - IP 임시 차단 (30분): {ip}")
            
            #  통계 업데이트
            if self.stats_callback:
                self.stats_callback('temp_block')
                if is_accumulated:
                    self.stats_callback('accumulated_blocks')
            
            # 일정 시간 후 자동 해제를 위한 스레드 (백그라운드에서 실행)
            def unblock_later():
                import time
                time.sleep(1800)  # 30분
                self.blocker.unblock_ip(ip)
                log_with_cache('INFO', f"IP 차단 자동 해제 (30분 경과): {ip}")
            
            threading.Thread(target=unblock_later, daemon=True).start()
            
            # 2. 관리자에게 알림
            alert_info = {
                "source_ip": ip,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "protocol": protocol,
                "confidence": 0.85,
                "action_taken": "IP 임시 차단 (30분)" + (" (누적 패턴)" if is_accumulated else "")
            }
            self.alert_system.send_alert(alert_info)
            
            #  통계 업데이트 (알림)
            if self.stats_callback:
                self.stats_callback('alerts')
            
            # 3. 누적 기록 초기화
            if ip in self.threat_accumulation:
                del self.threat_accumulation[ip]
            
            log_with_cache('INFO', f"높은 위협 대응 완료: {ip}")
            
        except Exception as e:
            log_with_cache('ERROR', f"높은 위협 대응 중 오류: {str(e)}")
    
    def _medium_threat_response(self, ip, protocol):
        """🟡 중간 위협 대응 (신뢰도 0.7-0.8) - 모니터링 강화 + 누적 체크"""
        try:
            log_with_cache('INFO', f"🟡 중간 위협 감지: {ip} - 모니터링 강화")
            
            #  누적 체크 - 1분 내 3회 시 임시 차단
            should_block, block_type = self._check_and_update_accumulation(ip, 'medium')
            
            if should_block and block_type == 'temp_block':
                # 누적으로 인한 임시 차단 (30분)
                log_with_cache('WARNING', f"⚡ 누적 패턴 탐지! {ip} → 임시 차단 (30분)")
                self._high_threat_response(ip, protocol, is_accumulated=True)
                return
            
            #  통계 업데이트 (모니터링)
            if self.stats_callback:
                self.stats_callback('monitored')
            
            # 알림 전송
            alert_info = {
                "source_ip": ip,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "protocol": protocol,
                "confidence": 0.75,
                "action_taken": "모니터링 강화"
            }
            self.alert_system.send_alert(alert_info)
            
            #  통계 업데이트 (알림)
            if self.stats_callback:
                self.stats_callback('alerts')
            
        except Exception as e:
            log_with_cache('ERROR', f"중간 위협 대응 중 오류: {str(e)}")
    
    def _warning_block_response(self, ip, protocol):
        """⚠️ 경고 차단 대응 (누적 낮은 위협) - IP 경고 차단 10분"""
        try:
            # 사설 IP 보호 확인
            if self._is_private_ip(ip):
                log_with_cache('WARNING', f"사설 IP 경고 차단 시도 차단됨: {ip} (내부 네트워크 보호)")
                return
            
            # 1. 경고 차단 (10분)
            self.blocker.block_ip(ip)
            log_with_cache('INFO', f"⚠️ 누적 패턴 - IP 경고 차단 (10분): {ip}")
            
            #  통계 업데이트 (경고 차단 + 누적 차단)
            if self.stats_callback:
                self.stats_callback('warning_block')
                self.stats_callback('accumulated_blocks')
            
            # 10분 후 자동 해제
            def unblock_later():
                import time
                time.sleep(600)  # 10분
                self.blocker.unblock_ip(ip)
                log_with_cache('INFO', f"IP 경고 차단 해제 (10분 경과): {ip}")
            
            threading.Thread(target=unblock_later, daemon=True).start()
            
            # 2. 관리자에게 알림
            alert_info = {
                "source_ip": ip,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "protocol": protocol,
                "confidence": 0.65,
                "action_taken": "누적 패턴 탐지 - IP 경고 차단 (10분)"
            }
            self.alert_system.send_alert(alert_info)
            
            #  통계 업데이트 (알림)
            if self.stats_callback:
                self.stats_callback('alerts')
            
            # 3. 누적 기록 초기화
            if ip in self.threat_accumulation:
                del self.threat_accumulation[ip]
            
            log_with_cache('INFO', f"경고 차단 대응 완료: {ip}")
            
        except Exception as e:
            log_with_cache('ERROR', f"경고 차단 대응 중 오류: {str(e)}")
    
    def _low_threat_response(self, ip, protocol):
        """🟢 낮은 위협 대응 (신뢰도 < 0.7) - 모니터링 + 누적 체크"""
        try:
            log_with_cache('DEBUG', f"🟢 낮은 위협 감지: {ip} - 모니터링")
            
            #  누적 체크 - 5분 내 10회 시 경고 차단
            should_block, block_type = self._check_and_update_accumulation(ip, 'low')
            
            if should_block and block_type == 'warning_block':
                # 누적으로 인한 경고 차단 (10분)
                log_with_cache('WARNING', f"⚡ 반복 패턴 탐지! {ip} → 경고 차단 (10분)")
                self._warning_block_response(ip, protocol)
                return
            
            # 낮은 위협은 알림 안 보냄 (로그만)
            
        except Exception as e:
            log_with_cache('ERROR', f"낮은 위협 대응 중 오류: {str(e)}")
    
    def _monitoring_only(self, ip):
        """의심 활동 모니터링 (차단 안 함)"""
        log_with_cache('INFO', f"의심 활동 모니터링: {ip}")
    
    def _check_and_update_accumulation(self, ip, threat_level):
        """
        누적 위협 체크 및 업데이트
        
        Args:
            ip (str): IP 주소
            threat_level (str): 위협 수준 ('medium', 'low')
        
        Returns:
            tuple: (차단 필요 여부, 차단 유형)
                - (True, 'warning_block'): 경고 차단 필요 (10분)
                - (True, 'temp_block'): 임시 차단 필요 (30분)
                - (False, None): 차단 불필요
        """
        current_time = time.time()
        
        with self.accumulation_lock:
            # IP별 위협 기록 초기화
            if ip not in self.threat_accumulation:
                self.threat_accumulation[ip] = {
                    'medium_threats': [],
                    'low_threats': []
                }
            
            ip_record = self.threat_accumulation[ip]
            
            # 중간 위협 처리 (1분 내 3회)
            if threat_level == 'medium':
                # 오래된 기록 제거
                ip_record['medium_threats'] = [
                    ts for ts in ip_record['medium_threats']
                    if current_time - ts < self.medium_threat_time_window
                ]
                
                # 현재 위협 추가
                ip_record['medium_threats'].append(current_time)
                
                # 임계값 확인
                if len(ip_record['medium_threats']) >= self.medium_threat_count_threshold:
                    log_with_cache('WARNING', f"🚨 누적 중간 위협 탐지: {ip} - {len(ip_record['medium_threats'])}회 (1분 내)")
                    # 기록 초기화
                    ip_record['medium_threats'].clear()
                    return True, 'temp_block'  # 30분 임시 차단
                
                log_with_cache('INFO', f"중간 위협 누적: {ip} - {len(ip_record['medium_threats'])}/{self.medium_threat_count_threshold}회")
            
            # 낮은 위협 처리 (5분 내 10회)
            elif threat_level == 'low':
                # 오래된 기록 제거
                ip_record['low_threats'] = [
                    ts for ts in ip_record['low_threats']
                    if current_time - ts < self.low_threat_time_window
                ]
                
                # 현재 위협 추가
                ip_record['low_threats'].append(current_time)
                
                # 임계값 확인
                if len(ip_record['low_threats']) >= self.low_threat_count_threshold:
                    log_with_cache('WARNING', f"⚠️ 누적 낮은 위협 탐지: {ip} - {len(ip_record['low_threats'])}회 (5분 내)")
                    # 기록 초기화
                    ip_record['low_threats'].clear()
                    return True, 'warning_block'  # 10분 경고 차단
                
                log_with_cache('DEBUG', f"낮은 위협 누적: {ip} - {len(ip_record['low_threats'])}/{self.low_threat_count_threshold}회")
        
        return False, None
    
    def _check_basic_heuristics(self, packet):
        """기본적인 휴리스틱 검사"""
        try:
            # 유효한 패킷 확인
            if not isinstance(packet, dict):
                print(f"_check_basic_heuristics - 유효하지 않은 패킷 타입: {type(packet).__name__}")
                # 문자열을 딕셔너리로 변환 시도
                if isinstance(packet, str):
                    packet = {
                        'source': 'unknown',
                        'destination': 'unknown',
                        'protocol': 'unknown',
                        'length': len(packet) if packet else 0,
                        'info': packet,
                        'raw_data': packet
                    }
                else:
                    return False
                
            # 필수 필드 존재 확인
            if 'info' not in packet and 'protocol' not in packet:
                print(f"_check_basic_heuristics - 필수 필드 누락: {packet.keys()}")
                return False
                
            info = str(packet.get('info', '')).lower()
            protocol = str(packet.get('protocol', '')).lower()
            
            # 프로토콜 번호를 문자열로 변환
            if protocol == '6':  # TCP
                protocol = 'tcp'
            elif protocol == '17':  # UDP
                protocol = 'udp'
            elif protocol == '1':  # ICMP
                protocol = 'icmp'
            
            # 1. SYN 플러딩 검사
            if ('tcp' in protocol or protocol == '6') and 'syn' in info:
                # 실제 구현에서는 짧은 시간 내 다수의 SYN 패킷 검사 필요
                return True
            
            # 2. 비정상적인 패킷 크기
            if packet.get('length', 0) > 5000:
                return True
            
            # 3. 알려진 악성 포트 확인
            dest = packet.get('destination', '')
            if ':' in dest:
                try:
                    port = int(dest.split(':')[1])
                    if port in [4444, 31337, 1337]:  # 잘 알려진 악성 포트 예시
                        return True
                except:
                    pass
            
            return False
            
        except Exception as e:
            log_with_cache('ERROR', f"휴리스틱 검사 중 오류: {str(e)}")
            print(f"휴리스틱 검사 중 오류 발생: {str(e)}, 패킷 타입: {type(packet).__name__ if packet is not None else 'None'}")
            import traceback
            traceback.print_exc()
            return False
    
    def block_ip(self, ip_address):
        """
        IP 주소 차단 (BlockMaliciousTraffic의 래퍼 메서드)
        
        Args:
            ip_address (str): 차단할 IP 주소
            
        Returns:
            bool: 차단 성공 여부
        """
        return self.blocker.block_ip(ip_address)
    
    def unblock_ip(self, ip_address):
        """
        IP 주소 차단 해제 (BlockMaliciousTraffic의 래퍼 메서드)
        
        Args:
            ip_address (str): 차단 해제할 IP 주소
            
        Returns:
            bool: 해제 성공 여부
        """
        return self.blocker.unblock_ip(ip_address)
    
    def get_blocked_ips(self):
        """
        현재 차단된 IP 주소 목록 반환 (BlockMaliciousTraffic의 래퍼 메서드)
        
        Returns:
            list: 차단된 IP 주소 목록
        """
        return self.blocker.get_blocked_ips()
    
    def verify_firewall_rule(self, ip_address):
        """
        방화벽 규칙 검증 (BlockMaliciousTraffic의 래퍼 메서드)
        
        Args:
            ip_address (str): 확인할 IP 주소
            
        Returns:
            bool: 규칙 존재 여부
        """
        return self.blocker.verify_firewall_rule(ip_address)
    
    def _save_action_history(self):
        """방어 조치 기록 저장 (메모리 효율적 방식)"""
        try:
            # 이전 파일 백업
            history_file = 'defense_actions_history.json'
            backup_file = 'defense_actions_history.backup.json'
            
            if os.path.exists(history_file):
                # 백업 파일이 이미 있으면 삭제
                if os.path.exists(backup_file):
                    os.remove(backup_file)
                # 현재 파일을 백업으로 이동
                os.rename(history_file, backup_file)
            
            # 새 파일에 기록
            with open(history_file, 'w', encoding='utf-8') as f:
                json.dump(self.action_history, f, indent=2, ensure_ascii=False)
                
            # 로그 캐시 비우기
            flush_log_cache()
                
        except Exception as e:
            log_with_cache('ERROR', f"방어 조치 기록 저장 중 오류: {str(e)}")
            
    def _load_action_history(self):
        """방어 조치 기록 로드 (제한된 크기)"""
        try:
            history_file = 'defense_actions_history.json'
            if os.path.exists(history_file):
                with open(history_file, 'r', encoding='utf-8') as f:
                    history = json.load(f)
                    
                    # 최대 크기로 제한
                    if len(history) > self.action_history_max_size:
                        self.action_history = history[-self.action_history_max_size:]
                    else:
                        self.action_history = history
                    
                log_with_cache('INFO', f"방어 조치 기록 {len(self.action_history)}개 로드 완료")
            else:
                self.action_history = []
        except Exception as e:
            log_with_cache('ERROR', f"방어 조치 기록 로드 중 오류: {str(e)}")
            self.action_history = []

# 모듈 내보내기용 함수
def create_defense_manager(config_file='defense_config.json', mode="lightweight", stats_callback=None):
    """방어 메커니즘 관리자 생성"""
    return DefenseManager(config_file, mode=mode, stats_callback=stats_callback)

def register_to_packet_capture(defense_manager, packet_capture_core):
    """패킷 캡처 코어에 방어 메커니즘 등록"""
    return defense_manager.register_to_packet_capture(packet_capture_core)

# 프로그램 종료 시 로그 캐시 비우기
def cleanup():
    """프로그램 종료 시 정리 작업 수행"""
    flush_log_cache()
    
# 종료 핸들러 등록
import atexit
atexit.register(cleanup)

if __name__ == "__main__":
    # 모듈 테스트 코드
    print("방어 메커니즘 모듈 테스트")
    
    # 방어 관리자 생성
    defense_manager = create_defense_manager()
    
    # 테스트 패킷 생성
    test_packet = {
        "source": "192.168.1.100:1234",
        "destination": "192.168.1.1:80",
        "protocol": "TCP",
        "length": 60,
        "info": "SYN"
    }
    
    # 패킷 분석 및 방어 조치 테스트
    defense_manager.handle_packet(test_packet)
    
    print("방어 메커니즘 테스트 완료") 
    print("방어 메커니즘 테스트 완료") 