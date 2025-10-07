# -*- coding: utf-8 -*-

"""
통합 설정 파일 로더

YAML 기반의 통합 설정 파일을 로드하고 관리합니다.
"""

import os
import yaml
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger('ConfigLoader')


class ConfigLoader:
    """
    통합 설정 파일 로더 클래스
    
    YAML 설정 파일을 로드하고, 하위 호환성을 위해
    기존 JSON 설정도 지원합니다.
    
    Features:
        - YAML 및 JSON 포맷 지원
        - 중첩된 설정 접근 (점 표기법)
        - 기본값 설정
        - 설정 검증
        - 핫 리로드 (파일 변경 감지)
    
    Example:
        >>> config = ConfigLoader('config/unified_config.yaml')
        >>> config.load()
        >>> threshold = config.get('defense.threat_thresholds.high', 0.9)
        >>> print(threshold)  # 0.9
    """
    
    def __init__(self, config_path: str = 'config/unified_config.yaml'):
        """
        ConfigLoader 초기화
        
        Args:
            config_path: 설정 파일 경로
        """
        self.config_path = Path(config_path)
        self.config_data: Dict[str, Any] = {}
        self.last_modified: Optional[float] = None
        
        logger.info(f"ConfigLoader 생성됨: {config_path}")
    
    def load(self) -> bool:
        """
        설정 파일 로드
        
        Returns:
            bool: 로드 성공 여부
        """
        try:
            if not self.config_path.exists():
                logger.error(f"설정 파일이 없습니다: {self.config_path}")
                return False
            
            # 파일 확장자 확인
            if self.config_path.suffix in ['.yaml', '.yml']:
                self.config_data = self._load_yaml()
            elif self.config_path.suffix == '.json':
                self.config_data = self._load_json()
            else:
                logger.error(f"지원하지 않는 파일 형식: {self.config_path.suffix}")
                return False
            
            # 마지막 수정 시간 저장
            self.last_modified = self.config_path.stat().st_mtime
            
            logger.info(f"✅ 설정 파일 로드 완료: {self.config_path}")
            return True
            
        except Exception as e:
            logger.error(f"설정 파일 로드 실패: {e}")
            return False
    
    def _load_yaml(self) -> Dict[str, Any]:
        """YAML 파일 로드"""
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    
    def _load_json(self) -> Dict[str, Any]:
        """JSON 파일 로드"""
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        설정 값 조회 (점 표기법 지원)
        
        Args:
            key: 설정 키 (예: "defense.threat_thresholds.high")
            default: 키가 없을 때 반환할 기본값
        
        Returns:
            Any: 설정 값 또는 기본값
        
        Example:
            >>> config.get('defense.auto_block.enabled', True)
            True
        """
        try:
            keys = key.split('.')
            value = self.config_data
            
            for k in keys:
                if isinstance(value, dict):
                    value = value.get(k)
                else:
                    return default
                
                if value is None:
                    return default
            
            return value
            
        except Exception as e:
            logger.warning(f"설정 조회 실패 ({key}): {e}")
            return default
    
    def set(self, key: str, value: Any) -> bool:
        """
        설정 값 수정 (메모리 내)
        
        Args:
            key: 설정 키
            value: 새로운 값
        
        Returns:
            bool: 수정 성공 여부
        
        Note:
            이 메서드는 메모리 내 설정만 수정합니다.
            파일에 저장하려면 save() 메서드를 호출하세요.
        """
        try:
            keys = key.split('.')
            data = self.config_data
            
            # 마지막 키 전까지 탐색
            for k in keys[:-1]:
                if k not in data:
                    data[k] = {}
                data = data[k]
            
            # 마지막 키에 값 설정
            data[keys[-1]] = value
            return True
            
        except Exception as e:
            logger.error(f"설정 수정 실패 ({key}): {e}")
            return False
    
    def save(self, backup: bool = True) -> bool:
        """
        설정 파일 저장
        
        Args:
            backup: 기존 파일을 백업할지 여부
        
        Returns:
            bool: 저장 성공 여부
        """
        try:
            # 백업 생성
            if backup and self.config_path.exists():
                backup_path = self.config_path.with_suffix('.bak')
                self.config_path.rename(backup_path)
                logger.info(f"기존 설정 백업: {backup_path}")
            
            # 파일 저장
            if self.config_path.suffix in ['.yaml', '.yml']:
                with open(self.config_path, 'w', encoding='utf-8') as f:
                    yaml.dump(self.config_data, f, default_flow_style=False, allow_unicode=True)
            elif self.config_path.suffix == '.json':
                with open(self.config_path, 'w', encoding='utf-8') as f:
                    json.dump(self.config_data, f, indent=4, ensure_ascii=False)
            
            logger.info(f"✅ 설정 파일 저장 완료: {self.config_path}")
            return True
            
        except Exception as e:
            logger.error(f"설정 파일 저장 실패: {e}")
            return False
    
    def reload_if_modified(self) -> bool:
        """
        파일이 수정되었으면 다시 로드
        
        Returns:
            bool: 리로드 여부
        """
        try:
            if not self.config_path.exists():
                return False
            
            current_mtime = self.config_path.stat().st_mtime
            
            if self.last_modified is None or current_mtime > self.last_modified:
                logger.info("설정 파일 변경 감지, 리로드 중...")
                return self.load()
            
            return False
            
        except Exception as e:
            logger.error(f"설정 파일 리로드 실패: {e}")
            return False
    
    def get_all(self) -> Dict[str, Any]:
        """
        전체 설정 반환
        
        Returns:
            Dict: 전체 설정 딕셔너리
        """
        return self.config_data.copy()
    
    def validate(self) -> bool:
        """
        설정 검증
        
        Returns:
            bool: 검증 통과 여부
        """
        required_keys = [
            'system',
            'defense',
            'monitoring'
        ]
        
        for key in required_keys:
            if key not in self.config_data:
                logger.error(f"필수 설정 누락: {key}")
                return False
        
        logger.info("✅ 설정 검증 통과")
        return True
    
    def __repr__(self) -> str:
        """문자열 표현"""
        return f"ConfigLoader('{self.config_path}', loaded={bool(self.config_data)})"


# 전역 설정 인스턴스 (싱글톤)
_global_config: Optional[ConfigLoader] = None


def get_config(config_path: str = 'config/unified_config.yaml') -> ConfigLoader:
    """
    전역 설정 인스턴스 반환 (싱글톤)
    
    Args:
        config_path: 설정 파일 경로
    
    Returns:
        ConfigLoader: 설정 로더 인스턴스
    """
    global _global_config
    
    if _global_config is None:
        _global_config = ConfigLoader(config_path)
        _global_config.load()
    
    return _global_config


# 하위 호환성을 위한 JSON 설정 마이그레이션 함수
def migrate_json_to_yaml(
    json_files: Dict[str, str],
    yaml_output: str = 'config/unified_config.yaml'
) -> bool:
    """
    기존 JSON 설정 파일들을 YAML로 마이그레이션
    
    Args:
        json_files: JSON 파일 경로 딕셔너리 (키: 섹션명, 값: 파일경로)
        yaml_output: 출력 YAML 파일 경로
    
    Returns:
        bool: 마이그레이션 성공 여부
    
    Example:
        >>> migrate_json_to_yaml({
        ...     'defense': 'defense_config.json',
        ...     'alerts': 'security_alerts.json'
        ... })
    """
    try:
        merged_config = {}
        
        for section, json_path in json_files.items():
            if os.path.exists(json_path):
                with open(json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    merged_config[section] = data
                logger.info(f"✅ {json_path} 로드 완료")
            else:
                logger.warning(f"파일이 없습니다: {json_path}")
        
        # YAML로 저장
        output_path = Path(yaml_output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(merged_config, f, default_flow_style=False, allow_unicode=True)
        
        logger.info(f"✅ 마이그레이션 완료: {yaml_output}")
        return True
        
    except Exception as e:
        logger.error(f"마이그레이션 실패: {e}")
        return False


if __name__ == '__main__':
    # 테스트 코드
    print("=" * 60)
    print("ConfigLoader 테스트")
    print("=" * 60)
    
    # 설정 로드
    config = get_config('config/unified_config.yaml')
    
    if config.config_data:
        print("\n✅ 설정 로드 성공")
        
        # 설정 조회 테스트
        print("\n설정 조회 테스트:")
        print(f"  시스템 이름: {config.get('system.name')}")
        print(f"  시스템 버전: {config.get('system.version')}")
        print(f"  방어 모드: {config.get('defense.auto_block.enabled')}")
        print(f"  High 임계값: {config.get('defense.threat_thresholds.high')}")
        print(f"  RL 활성화: {config.get('machine_learning.reinforcement_learning.enabled')}")
        
        # 기본값 테스트
        print(f"\n존재하지 않는 키 (기본값): {config.get('nonexistent.key', 'DEFAULT')}")
        
        # 검증 테스트
        print(f"\n검증: {'통과' if config.validate() else '실패'}")
        
        print("\n✅ 모든 테스트 완료!")
    else:
        print("\n❌ 설정 로드 실패")







