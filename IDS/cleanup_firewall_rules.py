# -*- coding: utf-8 -*-
"""
방화벽 규칙 정리 스크립트

중복된 IDS 방화벽 규칙을 정리하고, 올바른 형식(_IN/_OUT)으로 재생성합니다.
"""

import subprocess
import sys
import os

def check_admin():
    """관리자 권한 확인"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_ids_firewall_rules():
    """모든 IDS 방화벽 규칙 가져오기"""
    command = 'netsh advfirewall firewall show rule name=all | findstr "IDS_Block"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    rules = []
    if result.stdout:
        for line in result.stdout.split('\n'):
            if 'Rule Name:' in line:
                rule_name = line.split('Rule Name:')[1].strip()
                if rule_name:
                    rules.append(rule_name)
    
    return rules

def delete_all_ids_rules():
    """모든 IDS 방화벽 규칙 삭제"""
    rules = get_ids_firewall_rules()
    
    if not rules:
        print("❌ 삭제할 IDS 방화벽 규칙이 없습니다.")
        return 0
    
    print(f"\n📋 총 {len(rules)}개의 IDS 방화벽 규칙을 찾았습니다.\n")
    
    deleted_count = 0
    unique_rules = set(rules)  # 중복 제거
    
    for rule_name in unique_rules:
        try:
            command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ 삭제 완료: {rule_name}")
                deleted_count += 1
            else:
                print(f"⚠️ 삭제 실패: {rule_name}")
        except Exception as e:
            print(f"❌ 오류: {rule_name} - {str(e)}")
    
    return deleted_count

def recreate_rules_from_history():
    """차단 기록에서 규칙 재생성"""
    import json
    
    history_file = 'blocked_ips_history.json'
    
    if not os.path.exists(history_file):
        print(f"\n⚠️ 차단 기록 파일을 찾을 수 없습니다: {history_file}")
        return 0
    
    try:
        with open(history_file, 'r') as f:
            data = json.load(f)
        
        blocked_ips = data.get('blocked_ips', [])
        
        if not blocked_ips:
            print("\n✅ 재생성할 차단 IP가 없습니다.")
            return 0
        
        print(f"\n📋 {len(blocked_ips)}개의 차단 IP를 재생성합니다...\n")
        
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from modules.defense_mechanism import BlockMaliciousTraffic
        
        blocker = BlockMaliciousTraffic()
        recreated_count = 0
        
        for ip in blocked_ips:
            if blocker.block_ip(ip):
                print(f"✅ 재생성 완료: {ip}")
                recreated_count += 1
            else:
                print(f"❌ 재생성 실패: {ip}")
        
        return recreated_count
        
    except Exception as e:
        print(f"\n❌ 규칙 재생성 중 오류: {str(e)}")
        import traceback
        traceback.print_exc()
        return 0

def main():
    """메인 함수"""
    print("\n" + "="*60)
    print("  IDS 방화벽 규칙 정리 도구")
    print("="*60)
    
    # 관리자 권한 확인
    if not check_admin():
        print("\n⚠️ 경고: 관리자 권한이 필요합니다!")
        print("   이 스크립트를 관리자 권한으로 실행하세요.\n")
        input("아무 키나 눌러 종료...")
        return
    
    print("\n✅ 관리자 권한 확인 완료\n")
    
    # 현재 규칙 표시
    print("="*60)
    print("현재 IDS 방화벽 규칙")
    print("="*60)
    rules = get_ids_firewall_rules()
    for rule in set(rules):
        print(f"  - {rule}")
    print("="*60)
    
    # 사용자 확인
    print(f"\n⚠️ 경고: 모든 IDS 방화벽 규칙({len(set(rules))}개)을 삭제합니다.")
    choice = input("계속하시겠습니까? (y/n): ")
    
    if choice.lower() != 'y':
        print("\n❌ 작업이 취소되었습니다.")
        input("\n아무 키나 눌러 종료...")
        return
    
    # 1단계: 모든 규칙 삭제
    print("\n" + "="*60)
    print("1단계: 기존 규칙 삭제")
    print("="*60)
    deleted_count = delete_all_ids_rules()
    print(f"\n✅ {deleted_count}개의 규칙을 삭제했습니다.")
    
    # 2단계: 차단 기록에서 재생성
    print("\n" + "="*60)
    print("2단계: 차단 기록에서 규칙 재생성")
    print("="*60)
    recreated_count = recreate_rules_from_history()
    print(f"\n✅ {recreated_count}개의 규칙을 재생성했습니다.")
    
    # 최종 결과
    print("\n" + "="*60)
    print("정리 완료!")
    print("="*60)
    print(f"  삭제: {deleted_count}개")
    print(f"  재생성: {recreated_count}개")
    print("="*60 + "\n")
    
    input("아무 키나 눌러 종료...")

if __name__ == "__main__":
    main()
