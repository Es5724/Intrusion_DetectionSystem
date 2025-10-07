# 반응형 AI 에이전트 취약점 자동진단 시스템 - 설치 가이드

##  목차
1. [스템 요구사항](#시스템-요구사항)
2. [자동 설치 (권장)](#자동-설치-권장)
3. [수동 설치](#수동-설치)
4. [설치 확인](#설치-확인)
5. [문제 해결](#문제-해결)

##  시스템 요구사항

### 최소 요구사항 (Lightweight 모드)
- **OS**: Windows 10+, Ubuntu 18.04+, macOS 10.15+
- **Python**: 3.8 이상
- **메모리**: 4GB RAM (권장: 8GB+)
- **디스크**: 2GB 여유 공간
- **네트워크**: 관리자 권한 (패킷 캡처)

### 권장 요구사항 (Performance 모드)
- **OS**: Windows 10+ / Ubuntu 20.04+
- **Python**: 3.9 이상
- **메모리**: 8GB RAM 이상
- **디스크**: 5GB 여유 공간
- **추가**: Suricata IDS 설치

##  자동 설치 (권장)

### Windows

1. **관리자 권한으로 실행**
   ```cmd
   setup_and_run.bat
   ```
   - 우클릭 → "관리자 권한으로 실행" 선택

2. **자동 설치 프로세스**
   - Python 버전 확인
   - pip 업그레이드
   - 필수 패키지 자동 설치
   - 디렉토리 생성
   - Npcap 설치 확인 (패킷 캡처용)
   - Suricata 설치 옵션 (Performance 모드용)

3. **실행 모드 선택**
   ```
   1. 일반 실행 (모드 선택 메뉴)
   2. 경량 모드 (RF만 사용, 350MB)
   3. 고성능 모드 (RF + Suricata, 400-450MB)
   4. 디버그 모드
   5. 시스템 테스트
   6. 종료
   ```

### Linux/macOS

1. **실행 권한 부여**
   ```bash
   chmod +x setup_and_run.sh
   ```

2. **자동 설치 실행**
   ```bash
   sudo ./setup_and_run.sh
   ```

##  수동 설치

### 1단계: Python 설치 확인
```bash
python --version
# Python 3.8 이상 필요
```

Python이 없다면:
- Windows: https://python.org 에서 다운로드
- Linux: `sudo apt install python3 python3-pip`
- macOS: `brew install python3`

### 2단계: 필수 패키지 설치

#### 방법 A: requirements.txt 사용 (권장)
```bash
pip install -r IDS/requirements.txt
```

#### 방법 B: 개별 설치
```bash
# 핵심 라이브러리
pip install colorama pandas numpy scikit-learn torch joblib

# 네트워크 패킷 캡처
pip install scapy psutil

# 웹 서버 및 API
pip install flask flask-cors apscheduler

# 설정 파일 관리
pip install pyyaml

# 테스트 도구 (선택)
pip install pytest pytest-cov pytest-mock
```

### 3단계: Npcap 설치 (Windows, 필수)

패킷 캡처를 위해 Npcap이 필요합니다:

1. https://npcap.com/#download 에서 다운로드
2. 설치 시 **"WinPcap API-compatible Mode"** 체크
3. 재부팅 (권장)

### 4단계: Suricata 설치 (선택, Performance 모드용)

#### Windows
1. https://suricata.io/download/ 에서 Windows MSI 다운로드
2. 설치 실행
3. PATH 환경변수 자동 추가 확인
4. 확인: `suricata --version`

#### Linux (Ubuntu/Debian)
```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata
```

#### Linux (CentOS/RHEL)
```bash
sudo yum install epel-release
sudo yum install suricata
```

#### macOS
```bash
brew install suricata
```

### 5단계: 디렉토리 구조 확인

```bash
mkdir -p logs
mkdir -p IDS/config
mkdir -p IDS/rules
mkdir -p IDS/tests
```

### 6단계: 실행

```bash
cd IDS
python IPSAgent_RL.py
```

## ✅ 설치 확인

### 1. 기본 모듈 확인
```python
python -c "import torch, sklearn, scapy, flask, yaml; print('✓ 모든 모듈 정상')"
```

### 2. Npcap 확인 (Windows)
```cmd
dir "C:\Windows\System32\Npcap\wpcap.dll"
```

### 3. Suricata 확인
```bash
suricata --version
```

### 4. 시스템 테스트 실행
```bash
cd IDS

# Suricata 통합 테스트
python test_suricata_integration.py

# 시스템 관리 테스트
python test_system_management.py

# 반응형 AI 시스템 테스트
python test_reactive_ai_system.py
```

##  문제 해결

### "Python을 찾을 수 없습니다"
**원인**: Python이 설치되지 않았거나 PATH에 없음  
**해결**:
1. Python 재설치 시 "Add Python to PATH" 체크
2. 수동 PATH 추가:
   ```cmd
   setx PATH "%PATH%;C:\Python39"
   ```

### "관리자 권한이 필요합니다"
**원인**: 패킷 캡처는 관리자 권한 필요  
**해결**:
- Windows: 우클릭 → "관리자 권한으로 실행"
- Linux/macOS: `sudo` 사용

### "torch 설치 실패"
**원인**: PyTorch는 용량이 크고 시간이 오래 걸림  
**해결**:
```bash
# CPU 버전 (더 가벼움)
pip install torch --index-url https://download.pytorch.org/whl/cpu

# CUDA 버전 (GPU 있을 경우)
pip install torch --index-url https://download.pytorch.org/whl/cu118
```

### "Npcap 오류: 패킷을 캡처할 수 없습니다"
**원인**: Npcap 설치 안됨 또는 권한 부족  
**해결**:
1. Npcap 재설치 (WinPcap 호환 모드 체크)
2. 컴퓨터 재시작
3. 관리자 권한으로 실행

### "Suricata가 설치되었지만 인식되지 않습니다"
**원인**: PATH 환경변수 미설정  
**해결**:
```cmd
# Windows
setx PATH "%PATH%;C:\Program Files\Suricata" /M

# Linux/macOS
export PATH=$PATH:/usr/local/bin/suricata
```

### "메모리 부족 오류"
**원인**: PyTorch + scikit-learn이 많은 메모리 사용  
**해결**:
1. 다른 프로그램 종료
2. 경량 모드 사용
3. 가상 메모리 증가:
   - Windows: 시스템 속성 → 고급 → 성능 설정 → 가상 메모리

### "KISTI RF 모델 파일이 없습니다"
**원인**: 사전 학습된 모델 파일 누락  
**해결**: 자동으로 해결됨
- 시스템이 첫 실행 시 자동으로 모델 초기화
- 1시간 후 자동 재학습 시작

### "Suricata 규칙 파일 오류"
**원인**: 규칙 파일 자동 생성 실패  
**해결**:
```bash
mkdir -p IDS/rules
# 시스템이 자동으로 기본 규칙 생성
```

##  추가 도움말

### 로그 확인
```bash
# 시스템 로그
tail -f logs/ids_debug.log

# 방어 로그
tail -f logs/defense_actions.log

# Suricata 로그
tail -f suricata.log
```

### 설정 파일 위치
- **통합 설정**: `IDS/config/unified_config.yaml`
- **Suricata 설정**: `IDS/config/suricata.yaml`
- **Suricata 규칙**: `IDS/rules/suricata.rules`

### 성능 최적화 팁
1. **경량 모드 사용**: 일반 PC 환경
2. **고성능 모드**: 서버 환경, 8GB+ RAM
3. **PyTorch CPU 버전**: GPU 없으면 CPU 버전 사용
4. **패킷 수 제한**: `--max-packets 10000` 옵션

##  빠른 시작 체크리스트

- [ ] Python 3.8+ 설치 확인
- [ ] 관리자 권한 확보
- [ ] `setup_and_run.bat` 실행 (Windows)
- [ ] `setup_and_run.sh` 실행 (Linux/macOS)
- [ ] Npcap 설치 완료
- [ ] Suricata 설치 (선택, Performance 모드)
- [ ] 시스템 테스트 실행
- [ ] 실행 모드 선택 (1-6)
- [ ] 실시간 대시보드 확인

**축하합니다! 설치가 완료되었습니다!** 🎉

