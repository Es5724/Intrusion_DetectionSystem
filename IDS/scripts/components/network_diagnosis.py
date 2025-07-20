# -*- coding: utf-8 -*-

"""
네트워크 패킷 전송 진단 도구

TrafficGeneratorApp에서 패킷 전송이 안 되는 문제를 진단하고 해결하는 도구
"""

import os
import sys
import subprocess
import socket
import time
import psutil
from scapy.all import *
import json


class NetworkDiagnostics:
    """네트워크 진단 클래스"""
    
    def __init__(self):
        self.results = {
            "network_interfaces": [],
            "routing_table": [],
            "connectivity_tests": {},
            "scapy_settings": {},
            "recommendations": []
        }
    
    def run_full_diagnosis(self, target_ip="127.0.0.1"):
        """전체 네트워크 진단 실행"""
        print("🔍 네트워크 패킷 전송 진단을 시작합니다...")
        print("=" * 60)
        
        # 1. 네트워크 인터페이스 진단
        print("1. 네트워크 인터페이스 진단")
        self.diagnose_network_interfaces()
        
        # 2. 라우팅 테이블 확인
        print("\n2. 라우팅 테이블 확인")
        self.check_routing_table()
        
        # 3. Scapy 설정 확인
        print("\n3. Scapy 설정 확인")
        self.check_scapy_settings()
        
        # 4. 연결성 테스트
        print(f"\n4. 대상 IP ({target_ip}) 연결성 테스트")
        self.test_connectivity(target_ip)
        
        # 5. 패킷 전송 테스트
        print(f"\n5. 패킷 전송 테스트")
        self.test_packet_transmission(target_ip)
        
        # 6. 권한 확인
        print(f"\n6. 권한 및 방화벽 확인")
        self.check_permissions_and_firewall()
        
        # 7. 추천사항 생성
        self.generate_recommendations()
        
        # 결과 저장
        self.save_results()
        
        print("\n" + "=" * 60)
        print("🎯 진단 완료! 결과를 확인하세요.")
        
        return self.results
    
    def diagnose_network_interfaces(self):
        """네트워크 인터페이스 진단"""
        interfaces = []
        
        # psutil로 네트워크 인터페이스 확인
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    "name": interface,
                    "addresses": [],
                    "is_up": False,
                    "is_loopback": False
                }
                
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4
                        interface_info["addresses"].append({
                            "type": "IPv4",
                            "address": addr.address,
                            "netmask": addr.netmask,
                            "broadcast": getattr(addr, 'broadcast', None)
                        })
                
                # 인터페이스 상태 확인
                try:
                    stats = psutil.net_if_stats()[interface]
                    interface_info["is_up"] = stats.isup
                    interface_info["speed"] = stats.speed
                    interface_info["mtu"] = stats.mtu
                except:
                    pass
                
                # 루프백 확인
                interface_info["is_loopback"] = "loopback" in interface.lower() or "127.0.0.1" in str(interface_info["addresses"])
                
                interfaces.append(interface_info)
                
                # 출력
                status = "🟢 UP" if interface_info["is_up"] else "🔴 DOWN"
                loop_status = " (Loopback)" if interface_info["is_loopback"] else ""
                print(f"   {interface}{loop_status}: {status}")
                
                for addr_info in interface_info["addresses"]:
                    print(f"     - {addr_info['type']}: {addr_info['address']}")
                
        except Exception as e:
            print(f"   ❌ 네트워크 인터페이스 확인 중 오류: {e}")
            
        self.results["network_interfaces"] = interfaces
    
    def check_routing_table(self):
        """라우팅 테이블 확인"""
        routes = []
        
        try:
            # Scapy 라우팅 테이블 확인
            print("   Scapy 라우팅 테이블:")
            for route in conf.route.routes:
                net, mask, gw, iface, addr, metric = route
                route_info = {
                    "network": net,
                    "netmask": mask,
                    "gateway": gw,
                    "interface": iface,
                    "address": addr,
                    "metric": metric
                }
                routes.append(route_info)
                
                # 기본 라우트 강조
                if net == 0 and mask == 0:
                    print(f"     🌐 기본 라우트: {gw} via {iface}")
                elif net != 0:
                    print(f"     📍 {net}/{mask} via {gw} ({iface})")
            
            # 기본 게이트웨이 확인
            default_gw = None
            for route in routes:
                if route["network"] == 0 and route["netmask"] == 0:
                    default_gw = route["gateway"]
                    break
            
            if default_gw:
                print(f"   ✅ 기본 게이트웨이: {default_gw}")
            else:
                print(f"   ❌ 기본 게이트웨이를 찾을 수 없습니다!")
                self.results["recommendations"].append("기본 게이트웨이가 설정되지 않았습니다. 네트워크 연결을 확인하세요.")
                
        except Exception as e:
            print(f"   ❌ 라우팅 테이블 확인 중 오류: {e}")
            
        self.results["routing_table"] = routes
    
    def check_scapy_settings(self):
        """Scapy 설정 확인"""
        settings = {}
        
        try:
            settings["default_interface"] = conf.iface
            settings["verbose_level"] = conf.verb
            settings["loopback_name"] = conf.loopback_name
            settings["route_count"] = len(conf.route.routes)
            
            print(f"   기본 인터페이스: {settings['default_interface']}")
            print(f"   Verbose 레벨: {settings['verbose_level']}")
            print(f"   루프백 이름: {settings['loopback_name']}")
            print(f"   라우트 수: {settings['route_count']}")
            
            # 문제점 확인
            if not settings["default_interface"]:
                print("   ⚠️  기본 인터페이스가 설정되지 않았습니다!")
                self.results["recommendations"].append("Scapy 기본 인터페이스가 설정되지 않았습니다.")
            
            if settings["verbose_level"] == 0:
                print("   ⚠️  Verbose가 비활성화되어 디버깅이 어렵습니다!")
                self.results["recommendations"].append("Scapy verbose를 1로 설정하여 디버깅 정보를 확인하세요.")
                
        except Exception as e:
            print(f"   ❌ Scapy 설정 확인 중 오류: {e}")
            
        self.results["scapy_settings"] = settings
    
    def test_connectivity(self, target_ip):
        """연결성 테스트"""
        tests = {}
        
        # 1. Ping 테스트
        print(f"   Ping 테스트 ({target_ip}):")
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['ping', '-n', '1', target_ip], 
                                      capture_output=True, text=True, timeout=5)
            else:  # Linux/Mac
                result = subprocess.run(['ping', '-c', '1', target_ip], 
                                      capture_output=True, text=True, timeout=5)
            
            ping_success = result.returncode == 0
            tests["ping"] = {
                "success": ping_success,
                "output": result.stdout if ping_success else result.stderr
            }
            
            if ping_success:
                print("     ✅ Ping 성공")
            else:
                print("     ❌ Ping 실패")
                print(f"     오류: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("     ⏰ Ping 타임아웃")
            tests["ping"] = {"success": False, "error": "timeout"}
        except Exception as e:
            print(f"     ❌ Ping 테스트 오류: {e}")
            tests["ping"] = {"success": False, "error": str(e)}
        
        # 2. 소켓 연결 테스트
        print(f"   소켓 연결 테스트:")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            # 일반적인 포트들 테스트
            test_ports = [80, 443, 22, 53]
            socket_results = {}
            
            for port in test_ports:
                try:
                    result = sock.connect_ex((target_ip, port))
                    socket_results[port] = result == 0
                    status = "✅ 열림" if result == 0 else "❌ 닫힘"
                    print(f"     포트 {port}: {status}")
                except:
                    socket_results[port] = False
                    print(f"     포트 {port}: ❌ 오류")
            
            sock.close()
            tests["socket"] = socket_results
            
        except Exception as e:
            print(f"     ❌ 소켓 테스트 오류: {e}")
            tests["socket"] = {"error": str(e)}
        
        # 3. DNS 해상도 테스트 (IP가 아닌 경우)
        if not self.is_ip_address(target_ip):
            print(f"   DNS 해상도 테스트:")
            try:
                resolved_ip = socket.gethostbyname(target_ip)
                print(f"     ✅ {target_ip} → {resolved_ip}")
                tests["dns"] = {"success": True, "resolved_ip": resolved_ip}
            except Exception as e:
                print(f"     ❌ DNS 해상도 실패: {e}")
                tests["dns"] = {"success": False, "error": str(e)}
        
        self.results["connectivity_tests"] = tests
    
    def test_packet_transmission(self, target_ip):
        """패킷 전송 테스트"""
        print(f"   Raw 소켓 테스트:")
        
        # 1. UDP 소켓 테스트
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b"TEST_PACKET", (target_ip, 12345))
            sock.close()
            print("     ✅ UDP 소켓 전송 성공")
        except Exception as e:
            print(f"     ❌ UDP 소켓 전송 실패: {e}")
        
        # 2. Scapy 패킷 전송 테스트
        print(f"   Scapy 패킷 전송 테스트:")
        try:
            # verbose=1로 설정하여 전송 정보 확인
            original_verb = conf.verb
            conf.verb = 1
            
            packet = IP(dst=target_ip)/UDP(dport=12345)/Raw(b"SCAPY_TEST")
            
            # 기본 인터페이스 사용
            if conf.iface:
                print(f"     사용 인터페이스: {conf.iface}")
                send(packet, verbose=1)
                print("     ✅ Scapy 패킷 전송 성공")
            else:
                print("     ❌ Scapy 기본 인터페이스가 없습니다!")
                
            # verbose 레벨 복원
            conf.verb = original_verb
            
        except Exception as e:
            print(f"     ❌ Scapy 패킷 전송 실패: {e}")
            conf.verb = original_verb
    
    def check_permissions_and_firewall(self):
        """권한 및 방화벽 확인"""
        
        # 1. 관리자 권한 확인
        print("   권한 확인:")
        try:
            if os.name == 'nt':  # Windows
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if is_admin:
                    print("     ✅ 관리자 권한으로 실행 중")
                else:
                    print("     ⚠️  일반 사용자 권한으로 실행 중")
                    self.results["recommendations"].append("패킷 전송을 위해 관리자 권한으로 실행하세요.")
            else:  # Linux/Mac
                if os.getuid() == 0:
                    print("     ✅ Root 권한으로 실행 중")
                else:
                    print("     ⚠️  일반 사용자 권한으로 실행 중")
                    self.results["recommendations"].append("패킷 전송을 위해 sudo로 실행하세요.")
        except Exception as e:
            print(f"     ❌ 권한 확인 오류: {e}")
        
        # 2. Windows 방화벽 확인 (Windows만)
        if os.name == 'nt':
            print("   방화벽 확인:")
            try:
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'], 
                                      capture_output=True, text=True)
                if "ON" in result.stdout:
                    print("     ⚠️  Windows 방화벽이 활성화되어 있습니다")
                    self.results["recommendations"].append("Windows 방화벽에서 Python/Scapy를 허용하세요.")
                else:
                    print("     ✅ Windows 방화벽 상태 확인됨")
            except Exception as e:
                print(f"     ❌ 방화벽 확인 오류: {e}")
    
    def generate_recommendations(self):
        """추천사항 생성"""
        print("\n🎯 추천사항:")
        
        # 기본 추천사항들
        basic_recommendations = [
            "TrafficGeneratorApp.py에서 conf.verb = 1로 설정하여 디버깅 활성화",
            "패킷 전송 오류 시 상세 로그를 GUI에 표시하도록 수정",
            "네트워크 인터페이스 자동 선택 로직 개선",
            "대상 IP 연결성 사전 확인 기능 추가"
        ]
        
        for rec in basic_recommendations:
            self.results["recommendations"].append(rec)
        
        # 결과 출력
        for i, rec in enumerate(self.results["recommendations"], 1):
            print(f"   {i}. {rec}")
    
    def save_results(self):
        """진단 결과 저장"""
        try:
            with open("network_diagnosis_results.json", "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"\n💾 진단 결과가 'network_diagnosis_results.json'에 저장되었습니다.")
        except Exception as e:
            print(f"❌ 결과 저장 오류: {e}")
    
    def is_ip_address(self, address):
        """IP 주소 여부 확인"""
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False


def main():
    """메인 함수"""
    import argparse
    
    parser = argparse.ArgumentParser(description="네트워크 패킷 전송 진단 도구")
    parser.add_argument("--target", "-t", default="127.0.0.1", 
                       help="테스트할 대상 IP (기본값: 127.0.0.1)")
    args = parser.parse_args()
    
    # 진단 실행
    diagnostics = NetworkDiagnostics()
    results = diagnostics.run_full_diagnosis(args.target)
    
    print(f"\n📊 진단 완료!")
    print(f"📁 상세 결과: network_diagnosis_results.json")


if __name__ == "__main__":
    main() 