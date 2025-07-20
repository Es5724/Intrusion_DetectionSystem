# -*- coding: utf-8 -*-

"""
네트워크 인터페이스 관리 모듈

TrafficGeneratorApp에서 사용되는 네트워크 인터페이스 관련 기능을 통합 관리
"""

import os
import sys
import socket
import subprocess
from scapy.all import conf

class NetworkInterfaceManager:
    """네트워크 인터페이스 관리 클래스"""
    
    def __init__(self):
        self._cached_interface = None
        self._cached_ip = None
        self._cache_valid = False
    
    def get_active_interface_and_ip(self, force_refresh=False):
        """활성 네트워크 인터페이스와 IP 주소를 가져옵니다."""
        
        # 캐시된 값이 유효하고 갱신을 강제하지 않는 경우
        if self._cache_valid and not force_refresh:
            return self._cached_interface, self._cached_ip
        
        try:
            # 1단계: 활성 IP 주소 확인
            active_ip = self._get_active_ip()
            if not active_ip:
                return self._fallback_interface()
            
            # 2단계: Scapy 기본 인터페이스 확인
            scapy_interface = self._get_scapy_interface()
            
            # 3단계: 인터페이스 검증 및 매칭
            interface = self._match_interface_to_ip(scapy_interface, active_ip)
            
            # 캐시 업데이트
            self._cached_interface = interface
            self._cached_ip = active_ip
            self._cache_valid = True
            
            return interface, active_ip
            
        except Exception as e:
            print(f"⚠️ 네트워크 인터페이스 확인 중 오류: {e}")
            return self._fallback_interface()
    
    def _get_active_ip(self):
        """현재 활성 IP 주소를 확인합니다."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return None
    
    def _get_scapy_interface(self):
        """Scapy 기본 인터페이스를 가져옵니다."""
        try:
            return conf.iface
        except Exception:
            return None
    
    def _match_interface_to_ip(self, scapy_interface, active_ip):
        """인터페이스와 IP 주소를 매칭합니다."""
        
        # Scapy 인터페이스가 유효한 경우 우선 사용
        if scapy_interface:
            return scapy_interface
        
        # psutil을 사용한 인터페이스 매칭 시도
        try:
            import psutil
            
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if (addr.family == socket.AF_INET and 
                        addr.address == active_ip):
                        return interface
                        
        except ImportError:
            print("⚠️ psutil이 설치되지 않아 인터페이스 매칭이 제한됩니다.")
        except Exception as e:
            print(f"⚠️ 인터페이스 매칭 중 오류: {e}")
        
        # 시스템 명령어를 사용한 인터페이스 확인 (최후 수단)
        return self._get_interface_from_system(active_ip)
    
    def _get_interface_from_system(self, active_ip):
        """시스템 명령어를 통해 인터페이스를 확인합니다."""
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['ipconfig'], 
                                      capture_output=True, text=True, timeout=5)
                # Windows ipconfig 출력 파싱은 복잡하므로 기본값 반환
                return "eth0"  # 임시 기본값
            else:  # Linux/Mac
                result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # "dev" 다음에 오는 인터페이스 이름 추출
                    for line in result.stdout.split('\n'):
                        if 'dev' in line:
                            parts = line.split()
                            dev_index = parts.index('dev')
                            if dev_index + 1 < len(parts):
                                return parts[dev_index + 1]
        except Exception as e:
            print(f"⚠️ 시스템 명령어 인터페이스 확인 실패: {e}")
        
        return None
    
    def _fallback_interface(self):
        """인터페이스 확인 실패 시 폴백 처리"""
        print("🔄 기본 인터페이스로 폴백")
        
        # localhost 폴백
        fallback_interface = conf.loopback_name or "lo"
        fallback_ip = "127.0.0.1"
        
        self._cached_interface = fallback_interface
        self._cached_ip = fallback_ip
        self._cache_valid = True
        
        return fallback_interface, fallback_ip
    
    def validate_target_connectivity(self, target_ip):
        """대상 IP와의 연결성을 검증합니다."""
        try:
            # Ping 테스트
            if os.name == 'nt':  # Windows
                result = subprocess.run(['ping', '-n', '1', '-w', '3000', target_ip], 
                                      capture_output=True, timeout=5)
            else:  # Linux/Mac
                result = subprocess.run(['ping', '-c', '1', '-W', '3', target_ip], 
                                      capture_output=True, timeout=5)
            
            return result.returncode == 0
            
        except Exception:
            # Ping 실패 시 소켓 연결 테스트
            return self._test_socket_connectivity(target_ip)
    
    def _test_socket_connectivity(self, target_ip):
        """소켓을 통한 연결성 테스트"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                result = s.connect_ex((target_ip, 80))  # HTTP 포트 테스트
                return result == 0
        except Exception:
            return False
    
    def get_default_gateway(self):
        """기본 게이트웨이 주소를 가져옵니다."""
        try:
            # Scapy 라우팅 테이블에서 기본 게이트웨이 확인
            for net, msk, gw, iface, addr, metric in conf.route.routes:
                if net == 0 and msk == 0:  # 기본 라우트
                    return gw
        except Exception:
            pass
        
        # 시스템 명령어를 통한 게이트웨이 확인
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['route', 'print', '0.0.0.0'], 
                                      capture_output=True, text=True, timeout=5)
                # Windows route 출력 파싱 (간단화)
                for line in result.stdout.split('\n'):
                    if '0.0.0.0' in line and 'Gateway' not in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]  # 게이트웨이 주소
            else:  # Linux/Mac
                result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'default via' in line:
                            parts = line.split()
                            via_index = parts.index('via')
                            if via_index + 1 < len(parts):
                                return parts[via_index + 1]
        except Exception as e:
            print(f"⚠️ 게이트웨이 확인 실패: {e}")
        
        # 기본값 반환
        return "192.168.1.1"
    
    def clear_cache(self):
        """캐시된 인터페이스 정보를 지웁니다."""
        self._cached_interface = None
        self._cached_ip = None
        self._cache_valid = False


# 전역 인스턴스 (싱글톤 패턴)
_interface_manager = None

def get_interface_manager():
    """NetworkInterfaceManager 싱글톤 인스턴스를 반환합니다."""
    global _interface_manager
    if _interface_manager is None:
        _interface_manager = NetworkInterfaceManager()
    return _interface_manager

def get_default_iface_and_ip():
    """기본 네트워크 인터페이스와 IP 주소를 가져옵니다. (호환성 함수)"""
    manager = get_interface_manager()
    return manager.get_active_interface_and_ip()

def get_default_gateway():
    """기본 게이트웨이 주소를 가져옵니다. (호환성 함수)"""
    manager = get_interface_manager()
    return manager.get_default_gateway() 