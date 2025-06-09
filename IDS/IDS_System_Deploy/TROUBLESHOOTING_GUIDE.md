# 🔧 IDS 시스템 설치 문제 해결 가이드

## 📋 **목차**
1. [파이썬 설치 문제](#파이썬-설치-문제)
2. [패키지 설치 오류](#패키지-설치-오류)
3. [PyQt6 관련 오류](#pyqt6-관련-오류)
4. [torch/numpy 설치 오류](#torchnumpy-설치-오류)
5. [PyInstaller 빌드 오류](#pyinstaller-빌드-오류)
6. [실행 시 오류](#실행-시-오류)

---

## 🐍 **파이썬 설치 문제**

### 문제 1: "python is not recognized as internal or external command"
**원인**: 파이썬이 설치되지 않았거나 PATH에 등록되지 않음

**해결책**:
```cmd
# 1. Python Launcher 확인
py --version

# 2. 파이썬 재설치 (PATH 체크 필수!)
https://www.python.org/downloads/
⚠️ 설치 시 "Add Python to PATH" 체크!
```

### 문제 2: 파이썬 버전 호환성
**원인**: 너무 오래된 파이썬 버전 (3.7 이하)

**해결책**:
- **권장**: Python 3.8 ~ 3.11
- **피해야 할 버전**: 3.12+ (일부 패키지 호환성 문제)

---

## 📦 **패키지 설치 오류**

### 문제 1: "error: Microsoft Visual C++ 14.0 is required"
**원인**: Visual C++ 컴파일러 누락

**해결책**:
```cmd
# Visual C++ Redistributable 설치
https://aka.ms/vs/17/release/vc_redist.x64.exe
```

### 문제 2: 패키지 다운로드 타임아웃
**원인**: 네트워크 연결 문제 또는 방화벽

**해결책**:
```cmd
# 1. 타임아웃 늘리기
pip install --timeout 600 package_name

# 2. 다른 인덱스 서버 사용
pip install -i https://pypi.python.org/simple/ package_name

# 3. 캐시 무시
pip install --no-cache-dir package_name
```

### 문제 3: 권한 오류 (Permission denied)
**해결책**:
```cmd
# 1. 사용자 디렉토리에 설치
pip install --user package_name

# 2. 관리자 권한으로 실행
우클릭 → "관리자 권한으로 실행"
```

---

## 🖼️ **PyQt6 관련 오류**

### 문제 1: "ImportError: DLL load failed"
**원인**: Qt 라이브러리 충돌 또는 누락

**해결책**:
```cmd
# 1. 기존 Qt 패키지 완전 제거
pip uninstall PyQt6 PyQt6-Qt6 PyQt6-sip PySide6 -y

# 2. 재설치
pip install PyQt6

# 3. 시스템 재부팅
```

### 문제 2: PyQt6 vs PySide6 충돌
**해결책**:
```cmd
# 하나만 사용하도록 정리
pip uninstall PySide6 -y
pip install PyQt6
```

---

## 🔢 **torch/numpy 설치 오류**

### 문제 1: numpy 컴파일 오류
**해결책**:
```cmd
# 1. 미리 컴파일된 휠 사용
pip install numpy --only-binary=all

# 2. 구버전 사용
pip install numpy==1.21.6
```

### 문제 2: torch 설치 실패
**해결책**:
```cmd
# 1. CPU 버전 설치 (더 안정적)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu

# 2. 구버전 사용
pip install torch==1.12.1
```

---

## 🛠️ **PyInstaller 빌드 오류**

### 문제 1: "No module named 'XXX'"
**원인**: Hidden import 누락

**해결책**:
```python
# spec 파일에 추가
hiddenimports=['missing_module_name']
```

### 문제 2: 빌드된 exe가 실행되지 않음
**해결책**:
```cmd
# 1. 콘솔 모드로 빌드하여 오류 확인
pyinstaller --onefile --console your_script.py

# 2. 필요한 데이터 파일 포함
pyinstaller --add-data "config.json;." your_script.py
```

---

## 🚀 **실행 시 오류**

### 문제 1: "Access denied" (네트워크 기능)
**해결책**:
- 관리자 권한으로 실행
- 방화벽/백신 예외 설정

### 문제 2: GUI 화면이 나타나지 않음
**해결책**:
```cmd
# 1. 디스플레이 스케일링 확인
Windows 설정 → 디스플레이 → 배율 100%로 변경

# 2. 호환성 모드로 실행
exe 우클릭 → 속성 → 호환성 → Windows 10 모드
```

---

## 🆘 **긴급 해결법**

### 모든 것이 실패할 때:
```cmd
# 1. Python 완전 재설치
# - 기존 Python 완전 제거
# - Python 3.9.13 버전 설치 (가장 안정적)
# - "Add to PATH" 반드시 체크

# 2. 가상환경 생성
python -m venv ids_env
ids_env\Scripts\activate.bat

# 3. 패키지 하나씩 설치
pip install PyQt6
pip install pandas
pip install numpy
pip install matplotlib
pip install scikit-learn
pip install pyinstaller

# 4. 테스트
python IDS_Training_Data_Generator.py
```

---

## 📞 **추가 도움**

### 로그 수집:
```cmd
# 상세한 오류 로그 생성
pip install -r requirements_exe.txt -v > install_log.txt 2>&1
```

### 시스템 정보 확인:
```cmd
# Python 환경 정보
python -c "import sys; print(sys.version)"
python -c "import platform; print(platform.platform())"
pip list > installed_packages.txt
```

---

**💡 팁**: 문제가 계속 발생하면 `install_and_run_fixed.bat`를 사용하세요. 자동으로 여러 해결책을 시도합니다! 