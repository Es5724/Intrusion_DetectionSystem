"""
포트 스캔 탐지 및 취약점 분석 모듈

이 모듈은 다양한 포트 스캔 패턴을 탐지하고, 취약점을 분석하여 개선 방안을 제시합니다.
"""

import time
import threading
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PortScanDetector:
    """
    고급 포트 스캔 탐지 시스템
    - 시간 기반 스캔 패턴 분석
    - 다양한 스캔 기법 탐지
    - 위협 수준별 분류
    """
    
    def __init__(self, config_file=None):
        """
        포트 스캔 탐지기 초기화
        
        Args:
            config_file (str): 설정 파일 경로
        """
        self.config = self._load_config(config_file)
        
        # 스캔 패턴 추적을 위한 데이터 구조
        self.ip_scan_history = defaultdict(lambda: {
            'ports_scanned': set(),
            'scan_timestamps': deque(maxlen=1000),
            'scan_types': defaultdict(int),
            'flags_patterns': defaultdict(int),
            'last_activity': None
        })
        
        # 시간 윈도우 설정
        self.time_windows = {
            'fast_scan': timedelta(seconds=10),      # 빠른 스캔 (10초)
            'normal_scan': timedelta(minutes=1),     # 일반 스캔 (1분)
            'slow_scan': timedelta(minutes=5),       # 느린 스캔 (5분)
            'stealth_scan': timedelta(minutes=30)    # 스텔스 스캔 (30분)
        }
        
        # 탐지 임계값
        self.thresholds = {
            'fast_scan_ports': 10,      # 10초 내 10개 포트
            'normal_scan_ports': 50,    # 1분 내 50개 포트
            'slow_scan_ports': 100,     # 5분 내 100개 포트
            'stealth_scan_ports': 200   # 30분 내 200개 포트
        }
        
        # 스캔 타입별 가중치
        self.scan_weights = {
            'syn_scan': 1.0,
            'connect_scan': 0.8,
            'fin_scan': 1.2,
            'null_scan': 1.3,
            'xmas_scan': 1.3,
            'ack_scan': 1.1,
            'udp_scan': 0.9
        }
        
        # 정리 스레드
        self.cleanup_thread = None
        self.running = True
        self._start_cleanup_thread()
    
    def _load_config(self, config_file):
        """설정 파일 로드"""
        default_config = {
            "detection_enabled": True,
            "log_level": "INFO",
            "cleanup_interval": 300,  # 5분마다 정리
            "max_history_age": 3600,  # 1시간 후 히스토리 삭제
            "alert_thresholds": {
                "critical": 0.9,
                "high": 0.8,
                "medium": 0.6,
                "low": 0.4
            }
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    default_config.update(config)
            except Exception as e:
                logger.error(f"설정 파일 로드 실패: {e}")
        
        return default_config
    
    def analyze_packet(self, packet_info: Dict) -> Tuple[bool, float, str]:
        """
        패킷을 분석하여 포트 스캔 여부를 판단
        
        Args:
            packet_info (Dict): 패킷 정보
            
        Returns:
            Tuple[bool, float, str]: (스캔 여부, 위험도, 스캔 타입)
        """
        try:
            source_ip = packet_info.get('source', '').split(':')[0]
            dest_port = self._extract_dest_port(packet_info)
            protocol = packet_info.get('protocol', '')
            flags = self._extract_tcp_flags(packet_info)
            
            if not source_ip or not dest_port:
                return False, 0.0, "invalid_packet"
            
            # 현재 시간
            current_time = datetime.now()
            
            # IP별 스캔 히스토리 업데이트
            ip_history = self.ip_scan_history[source_ip]
            ip_history['ports_scanned'].add(dest_port)
            ip_history['scan_timestamps'].append(current_time)
            ip_history['last_activity'] = current_time
            
            # 스캔 타입 분류
            scan_type = self._classify_scan_type(protocol, flags)
            ip_history['scan_types'][scan_type] += 1
            
            if flags:
                ip_history['flags_patterns'][flags] += 1
            
            # 스캔 패턴 분석
            is_scan, risk_score, scan_pattern = self._analyze_scan_pattern(source_ip, current_time)
            
            if is_scan:
                logger.warning(f"포트 스캔 탐지: {source_ip} -> 포트 {dest_port} ({scan_pattern})")
            
            return is_scan, risk_score, scan_pattern
            
        except Exception as e:
            logger.error(f"패킷 분석 중 오류: {e}")
            return False, 0.0, "analysis_error"
    
    def _extract_dest_port(self, packet_info: Dict) -> Optional[int]:
        """목적지 포트 추출"""
        try:
            dest = packet_info.get('destination', '')
            if ':' in dest:
                return int(dest.split(':')[1])
            
            # info 필드에서 포트 정보 추출 시도
            info = packet_info.get('info', '')
            if '→' in info:
                parts = info.split('→')
                if len(parts) > 1 and ':' in parts[1]:
                    return int(parts[1].split(':')[0].strip())
        except:
            pass
        return None
    
    def _extract_tcp_flags(self, packet_info: Dict) -> str:
        """TCP 플래그 추출"""
        info = packet_info.get('info', '').lower()
        flags = []
        
        if 'syn' in info:
            flags.append('SYN')
        if 'ack' in info:
            flags.append('ACK')
        if 'fin' in info:
            flags.append('FIN')
        if 'rst' in info:
            flags.append('RST')
        if 'psh' in info:
            flags.append('PSH')
        if 'urg' in info:
            flags.append('URG')
        
        return ','.join(flags)
    
    def _classify_scan_type(self, protocol: str, flags: str) -> str:
        """스캔 타입 분류"""
        protocol = str(protocol).lower()
        
        if protocol in ['6', 'tcp']:
            if flags == 'SYN':
                return 'syn_scan'
            elif flags == 'SYN,ACK':
                return 'connect_scan'
            elif flags == 'FIN':
                return 'fin_scan'
            elif not flags or flags == '':
                return 'null_scan'
            elif 'FIN' in flags and 'PSH' in flags and 'URG' in flags:
                return 'xmas_scan'
            elif flags == 'ACK':
                return 'ack_scan'
        elif protocol in ['17', 'udp']:
            return 'udp_scan'
        
        return 'unknown_scan'
    
    def _analyze_scan_pattern(self, source_ip: str, current_time: datetime) -> Tuple[bool, float, str]:
        """스캔 패턴 분석"""
        ip_history = self.ip_scan_history[source_ip]
        timestamps = list(ip_history['scan_timestamps'])
        
        if len(timestamps) < 2:
            return False, 0.0, "insufficient_data"
        
        # 각 시간 윈도우별 스캔 분석
        risk_scores = {}
        scan_patterns = []
        
        for window_name, window_duration in self.time_windows.items():
            cutoff_time = current_time - window_duration
            recent_scans = [t for t in timestamps if t >= cutoff_time]
            
            if len(recent_scans) >= self.thresholds.get(f"{window_name}_ports", 10):
                # 포트 수 기반 위험도 계산
                port_count = len(set(port for port in ip_history['ports_scanned'] 
                                   if any(t >= cutoff_time for t in timestamps)))
                
                base_risk = min(port_count / self.thresholds.get(f"{window_name}_ports", 10), 2.0)
                
                # 스캔 타입별 가중치 적용
                scan_type_weight = max(self.scan_weights.get(scan_type, 1.0) 
                                     for scan_type in ip_history['scan_types'].keys())
                
                risk_score = base_risk * scan_type_weight * 0.5
                risk_scores[window_name] = min(risk_score, 1.0)
                scan_patterns.append(f"{window_name}_{port_count}ports")
        
        if not risk_scores:
            return False, 0.0, "no_pattern"
        
        # 최고 위험도와 해당 패턴 반환
        max_risk = max(risk_scores.values())
        max_pattern = max(risk_scores.keys(), key=lambda k: risk_scores[k])
        
        is_scan = max_risk >= 0.4  # 최소 임계값
        pattern_name = f"{max_pattern}_{max(scan_patterns, key=len)}"
        
        return is_scan, max_risk, pattern_name
    
    def get_scan_statistics(self, source_ip: str) -> Dict:
        """특정 IP의 스캔 통계 조회"""
        if source_ip not in self.ip_scan_history:
            return {}
        
        ip_history = self.ip_scan_history[source_ip]
        current_time = datetime.now()
        
        stats = {
            'total_ports_scanned': len(ip_history['ports_scanned']),
            'scan_types': dict(ip_history['scan_types']),
            'flags_patterns': dict(ip_history['flags_patterns']),
            'last_activity': ip_history['last_activity'].isoformat() if ip_history['last_activity'] else None,
            'recent_activity': {}
        }
        
        # 시간 윈도우별 최근 활동
        for window_name, window_duration in self.time_windows.items():
            cutoff_time = current_time - window_duration
            recent_count = sum(1 for t in ip_history['scan_timestamps'] if t >= cutoff_time)
            stats['recent_activity'][window_name] = recent_count
        
        return stats
    
    def _start_cleanup_thread(self):
        """정리 스레드 시작"""
        def cleanup_worker():
            while self.running:
                try:
                    self._cleanup_old_data()
                    time.sleep(self.config.get('cleanup_interval', 300))
                except Exception as e:
                    logger.error(f"정리 스레드 오류: {e}")
        
        self.cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self.cleanup_thread.start()
    
    def _cleanup_old_data(self):
        """오래된 데이터 정리"""
        current_time = datetime.now()
        max_age = timedelta(seconds=self.config.get('max_history_age', 3600))
        cutoff_time = current_time - max_age
        
        ips_to_remove = []
        for ip, history in self.ip_scan_history.items():
            if history['last_activity'] and history['last_activity'] < cutoff_time:
                ips_to_remove.append(ip)
        
        for ip in ips_to_remove:
            del self.ip_scan_history[ip]
        
        if ips_to_remove:
            logger.info(f"정리 완료: {len(ips_to_remove)}개 IP 기록 삭제")
    
    def shutdown(self):
        """시스템 종료"""
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)


class VulnerabilityScanner:
    """
    취약점 스캔 및 분석 시스템
    """
    
    def __init__(self):
        """취약점 스캐너 초기화"""
        self.common_ports = {
            # 웹 서비스
            80: {'service': 'HTTP', 'risk': 'low', 'recommendations': ['HTTPS 사용', '보안 헤더 설정']},
            443: {'service': 'HTTPS', 'risk': 'low', 'recommendations': ['SSL/TLS 설정 확인', '인증서 유효성 검사']},
            8080: {'service': 'HTTP Proxy', 'risk': 'medium', 'recommendations': ['접근 제한', '인증 설정']},
            
            # 데이터베이스
            3306: {'service': 'MySQL', 'risk': 'high', 'recommendations': ['외부 접근 차단', '강력한 패스워드', '방화벽 설정']},
            5432: {'service': 'PostgreSQL', 'risk': 'high', 'recommendations': ['외부 접근 차단', '강력한 패스워드']},
            1433: {'service': 'MS SQL Server', 'risk': 'high', 'recommendations': ['외부 접근 차단', '최신 패치 적용']},
            
            # 원격 접속
            22: {'service': 'SSH', 'risk': 'medium', 'recommendations': ['키 기반 인증', '포트 변경', '접근 제한']},
            23: {'service': 'Telnet', 'risk': 'critical', 'recommendations': ['즉시 비활성화', 'SSH 사용']},
            3389: {'service': 'RDP', 'risk': 'high', 'recommendations': ['강력한 패스워드', 'NLA 활성화', 'VPN 사용']},
            
            # 파일 공유
            21: {'service': 'FTP', 'risk': 'high', 'recommendations': ['SFTP 사용', '익명 접근 차단']},
            445: {'service': 'SMB', 'risk': 'high', 'recommendations': ['최신 패치 적용', '불필요시 비활성화']},
            
            # 이메일
            25: {'service': 'SMTP', 'risk': 'medium', 'recommendations': ['인증 설정', '릴레이 차단']},
            110: {'service': 'POP3', 'risk': 'medium', 'recommendations': ['암호화 사용']},
            143: {'service': 'IMAP', 'risk': 'medium', 'recommendations': ['암호화 사용']},
            
            # 기타 위험 포트
            135: {'service': 'RPC', 'risk': 'high', 'recommendations': ['방화벽 차단']},
            139: {'service': 'NetBIOS', 'risk': 'high', 'recommendations': ['비활성화']},
            1080: {'service': 'SOCKS Proxy', 'risk': 'high', 'recommendations': ['접근 제한']},
            
            # 백도어/악성 포트
            4444: {'service': 'Backdoor', 'risk': 'critical', 'recommendations': ['즉시 차단', '시스템 검사']},
            31337: {'service': 'Backdoor', 'risk': 'critical', 'recommendations': ['즉시 차단', '시스템 검사']},
            1337: {'service': 'Backdoor', 'risk': 'critical', 'recommendations': ['즉시 차단', '시스템 검사']}
        }
        
        self.vulnerability_database = self._load_vulnerability_database()
    
    def _load_vulnerability_database(self):
        """취약점 데이터베이스 로드"""
        return {
            'open_ports': {
                'description': '불필요한 포트가 열려있음',
                'severity': 'medium',
                'cve_examples': ['CVE-2019-0708', 'CVE-2017-0144'],
                'mitigation': '불필요한 서비스 중지 및 방화벽 설정'
            },
            'weak_services': {
                'description': '취약한 서비스 실행 중',
                'severity': 'high',
                'cve_examples': ['CVE-2020-1472', 'CVE-2019-11510'],
                'mitigation': '서비스 업데이트 및 보안 설정 강화'
            },
            'backdoor_ports': {
                'description': '백도어 포트 탐지',
                'severity': 'critical',
                'cve_examples': ['CVE-2018-10933', 'CVE-2019-15846'],
                'mitigation': '즉시 시스템 검사 및 복구'
            }
        }
    
    def analyze_open_ports(self, open_ports: List[int], target_ip: str) -> Dict:
        """
        열린 포트 분석 및 취약점 평가
        
        Args:
            open_ports (List[int]): 열린 포트 목록
            target_ip (str): 대상 IP
            
        Returns:
            Dict: 취약점 분석 결과
        """
        analysis_result = {
            'target_ip': target_ip,
            'scan_time': datetime.now().isoformat(),
            'total_open_ports': len(open_ports),
            'risk_summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'services_found': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        for port in open_ports:
            port_info = self.common_ports.get(port, {
                'service': 'Unknown',
                'risk': 'medium',
                'recommendations': ['포트 용도 확인', '불필요시 차단']
            })
            
            service_info = {
                'port': port,
                'service': port_info['service'],
                'risk_level': port_info['risk'],
                'recommendations': port_info['recommendations']
            }
            
            analysis_result['services_found'].append(service_info)
            analysis_result['risk_summary'][port_info['risk']] += 1
            
            # 취약점 분류
            if port_info['risk'] == 'critical':
                vulnerability = {
                    'type': 'backdoor_ports',
                    'port': port,
                    'service': port_info['service'],
                    'severity': 'critical',
                    'description': f"포트 {port}에서 위험한 서비스 탐지: {port_info['service']}"
                }
                analysis_result['vulnerabilities'].append(vulnerability)
            
            # 권장사항 추가
            for recommendation in port_info['recommendations']:
                if recommendation not in analysis_result['recommendations']:
                    analysis_result['recommendations'].append(recommendation)
        
        # 전체 위험도 계산
        analysis_result['overall_risk'] = self._calculate_overall_risk(analysis_result['risk_summary'])
        
        return analysis_result
    
    def _calculate_overall_risk(self, risk_summary: Dict) -> str:
        """전체 위험도 계산"""
        if risk_summary['critical'] > 0:
            return 'critical'
        elif risk_summary['high'] > 2:
            return 'high'
        elif risk_summary['high'] > 0 or risk_summary['medium'] > 5:
            return 'medium'
        else:
            return 'low'
    
    def generate_security_report(self, scan_results: List[Dict]) -> str:
        """보안 보고서 생성"""
        if not scan_results:
            return "스캔 결과가 없습니다."
        
        report = []
        report.append("=" * 60)
        report.append("            보안 취약점 분석 보고서")
        report.append("=" * 60)
        report.append(f"생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"분석 대상: {len(scan_results)}개 시스템")
        report.append("")
        
        # 전체 통계
        total_ports = sum(result['total_open_ports'] for result in scan_results)
        total_vulnerabilities = sum(len(result['vulnerabilities']) for result in scan_results)
        
        report.append("[ 전체 통계 ]")
        report.append(f"- 총 열린 포트: {total_ports}개")
        report.append(f"- 총 취약점: {total_vulnerabilities}개")
        report.append("")
        
        # 각 시스템별 분석
        for i, result in enumerate(scan_results, 1):
            report.append(f"[ 시스템 {i}: {result['target_ip']} ]")
            report.append(f"열린 포트: {result['total_open_ports']}개")
            report.append(f"전체 위험도: {result['overall_risk'].upper()}")
            
            # 위험도별 통계
            risk_summary = result['risk_summary']
            report.append(f"위험도별 분포: 치명적({risk_summary['critical']}), 높음({risk_summary['high']}), 중간({risk_summary['medium']}), 낮음({risk_summary['low']})")
            
            # 주요 취약점
            if result['vulnerabilities']:
                report.append("주요 취약점:")
                for vuln in result['vulnerabilities'][:3]:  # 상위 3개만 표시
                    report.append(f"  - {vuln['description']}")
            
            # 권장사항
            if result['recommendations']:
                report.append("권장사항:")
                for rec in result['recommendations'][:3]:  # 상위 3개만 표시
                    report.append(f"  - {rec}")
            
            report.append("")
        
        return "\n".join(report)


class SecurityHardening:
    """
    보안 강화 및 자동 대응 시스템
    """
    
    def __init__(self):
        """보안 강화 시스템 초기화"""
        self.hardening_rules = self._load_hardening_rules()
        self.auto_response_enabled = True
    
    def _load_hardening_rules(self):
        """보안 강화 규칙 로드"""
        return {
            'firewall_rules': {
                'block_suspicious_ports': [4444, 31337, 1337, 6667, 6668, 6669],
                'limit_ssh_access': {'port': 22, 'max_attempts': 3},
                'block_port_scan': {'threshold': 10, 'window': 60}
            },
            'service_hardening': {
                'disable_unnecessary_services': ['telnet', 'ftp', 'rsh', 'rlogin'],
                'secure_configurations': {
                    'ssh': ['PasswordAuthentication no', 'PermitRootLogin no'],
                    'apache': ['ServerTokens Prod', 'ServerSignature Off'],
                    'nginx': ['server_tokens off']
                }
            },
            'network_security': {
                'enable_intrusion_detection': True,
                'log_all_connections': True,
                'rate_limiting': {'max_connections': 100, 'per_minute': True}
            }
        }
    
    def apply_emergency_response(self, threat_info: Dict) -> List[str]:
        """
        긴급 대응 조치 적용
        
        Args:
            threat_info (Dict): 위협 정보
            
        Returns:
            List[str]: 적용된 조치 목록
        """
        actions_taken = []
        
        if not self.auto_response_enabled:
            return ["자동 대응이 비활성화되어 있습니다."]
        
        try:
            threat_level = threat_info.get('risk_level', 'medium')
            source_ip = threat_info.get('source_ip', '')
            scan_type = threat_info.get('scan_type', '')
            
            # 위협 수준별 대응
            if threat_level in ['critical', 'high']:
                # 즉시 IP 차단
                if source_ip:
                    block_cmd = f"netsh advfirewall firewall add rule name=\"Block_{source_ip}\" dir=in action=block remoteip={source_ip}"
                    actions_taken.append(f"IP 차단: {source_ip}")
                
                # 포트 스캔 탐지 시 추가 조치
                if 'scan' in scan_type.lower():
                    # 포트 스캔 방지 규칙 강화
                    actions_taken.append("포트 스캔 방지 규칙 강화")
                    
                    # 로그 레벨 상승
                    actions_taken.append("로그 레벨 상승 (상세 모니터링 시작)")
            
            elif threat_level == 'medium':
                # 모니터링 강화
                actions_taken.append(f"모니터링 강화: {source_ip}")
                
                # 연결 제한 적용
                actions_taken.append("연결 제한 적용")
            
            # 공통 대응
            actions_taken.append("보안 이벤트 로그 기록")
            actions_taken.append("관리자 알림 전송")
            
        except Exception as e:
            logger.error(f"긴급 대응 중 오류: {e}")
            actions_taken.append(f"대응 중 오류 발생: {str(e)}")
        
        return actions_taken
    
    def generate_hardening_recommendations(self, vulnerability_analysis: Dict) -> List[str]:
        """
        취약점 분석 결과를 바탕으로 보안 강화 권장사항 생성
        
        Args:
            vulnerability_analysis (Dict): 취약점 분석 결과
            
        Returns:
            List[str]: 보안 강화 권장사항
        """
        recommendations = []
        
        # 열린 포트 기반 권장사항
        for service in vulnerability_analysis.get('services_found', []):
            port = service['port']
            service_name = service['service']
            risk_level = service['risk_level']
            
            if risk_level == 'critical':
                recommendations.append(f"[긴급] 포트 {port} ({service_name}) 즉시 차단 또는 비활성화")
            elif risk_level == 'high':
                recommendations.append(f"[높음] 포트 {port} ({service_name}) 접근 제한 및 보안 설정 강화")
            elif risk_level == 'medium':
                recommendations.append(f"[중간] 포트 {port} ({service_name}) 모니터링 및 정기 점검")
        
        # 일반적인 보안 강화 권장사항
        overall_risk = vulnerability_analysis.get('overall_risk', 'low')
        
        if overall_risk in ['critical', 'high']:
            recommendations.extend([
                "방화벽 규칙 강화 및 불필요한 서비스 중지",
                "침입 탐지 시스템 활성화",
                "정기적인 보안 패치 적용",
                "강력한 인증 정책 적용",
                "네트워크 세그멘테이션 고려"
            ])
        
        # 포트별 구체적 권장사항 추가
        recommendations.extend(vulnerability_analysis.get('recommendations', []))
        
        return list(set(recommendations))  # 중복 제거