# 📁 IDS 시스템 배포를 위한 필수 파일 목록

## 🚀 **install_and_run_fixed.bat 실행을 위한 필수 파일**

### ✅ **핵심 필수 파일 (반드시 같은 폴더에 있어야 함)**

```
📦 IDS_System_Folder/
├── 📄 install_and_run_fixed.bat         [메인 설치 스크립트]
├── 📄 requirements_safe.txt              [패키지 목록 - 우선순위]
├── 📄 requirements_exe.txt               [패키지 목록 - 대안]
├── 📄 IDS_Training_Data_Generator.py     [메인 파이썬 파일]
├── 📄 IDS_TrainingDataGenerator.spec     [PyInstaller 설정]
├── 📄 defense_config.json                [시스템 설정]
├── 📁 scripts/                           [필수 모듈들]
│   ├── 📁 components/
│   │   ├── 📄 packet_collector.py
│   │   ├── 📄 TrafficGeneratorApp.py
│   │   └── 📄 DataPreprocessingApp.py
│   └── ...
├── 📁 modules/                           [핵심 모듈들]
│   ├── 📄 __init__.py
│   ├── 📄 defense_mechanism.py
│   ├── 📄 threat_alert_system.py
│   └── ...
└── 📁 data_set/                         🔸 [선택사항 - 있으면 복사됨]
```

---

## 🔍 **파일별 역할 설명**

### **1. 설치 스크립트**
- `install_and_run_fixed.bat` - 메인 설치 및 빌드 스크립트
- `install_and_run.bat` - 기본 설치 스크립트 (백업용)

### **2. 패키지 요구사항**
- `requirements_safe.txt` - **우선 사용** (호환성 높은 버전)
- `requirements_exe.txt` - 대안 패키지 목록

### **3. Python 소스 파일**
- `IDS_Training_Data_Generator.py` - **메인 실행 파일**
- `IDSAgent.py` - 콘솔 버전 (선택사항)

### **4. PyInstaller 설정**
- `IDS_TrainingDataGenerator.spec` - exe 빌드 설정
- `IDSAgent.spec` - 콘솔 버전 빌드 설정

### **5. 설정 파일**
- `defense_config.json` - 방어 시스템 설정

### **6. 필수 모듈 디렉토리**
- `scripts/` - GUI 컴포넌트들
- `modules/` - 핵심 기능 모듈들

---

## ⚡ **최소 배포 패키지**

### **절대 필수 (7개 파일)**
```
✅ install_and_run_fixed.bat
✅ requirements_safe.txt  
✅ IDS_Training_Data_Generator.py
✅ IDS_TrainingDataGenerator.spec
✅ defense_config.json
✅ scripts/ (전체 폴더)
✅ modules/ (전체 폴더)
```

### **권장 추가 파일**
```
📋 TROUBLESHOOTING_GUIDE.md    - 문제 해결 가이드
📋 requirements_exe.txt         - 대안 패키지 목록
📋 README_FIRST.txt            - 사용법 안내
```

---

##  **각 bat 파일별 필요 파일**

### **install_and_run_fixed.bat**
```
필수: requirements_safe.txt 또는 requirements_exe.txt
필수: IDS_Training_Data_Generator.py
권장: IDS_TrainingDataGenerator.spec
선택: defense_config.json, data_set/
```

### **build_exe.bat**
```
필수: requirements_exe.txt
필수: IDS_TrainingDataGenerator.spec
선택: defense_config.json, data_set/
```

### **create_package_v2.bat**
```
필수: IDS_Training_Data_Generator.py
권장: 모든 관련 파일들 (자동으로 찾아서 복사)
```

---

##  **자주 발생하는 파일 누락 문제**

### **1. "requirements file not found" 오류**
```
해결: requirements_safe.txt 또는 requirements_exe.txt 추가
```

### **2. "No main Python file found" 오류**
```
해결: IDS_Training_Data_Generator.py 파일 확인
```

### **3. "ImportError: No module named 'scripts'" 오류**
```
해결: scripts/ 폴더 전체 복사
```

### **4. "ImportError: No module named 'modules'" 오류**  
```
해결: modules/ 폴더 전체 복사
```

---

##  **완벽한 배포 패키지 생성법**

### **방법 1: 자동 생성 (권장)**
```cmd
create_package_v2.bat
```
실행하면 `IDS_System_v2.0` 폴더에 모든 필요 파일 자동 복사

### **방법 2: 수동 복사**
```
1. 새 폴더 생성
2. 위의 "절대 필수" 파일들 복사  
3. scripts/, modules/ 폴더 전체 복사
4. 압축하여 배포
```

---

##  **배포 시 주의사항**

1. **폴더 구조 유지** - 상대 경로로 동작하므로 구조 변경 금지
2. **한글 경로 피하기** - 영문 경로에서 실행 권장  
3. **관리자 권한** - 네트워크 기능을 위해 필수
4. **인터넷 연결** - 패키지 다운로드를 위해 필요
5. **백신 예외 설정** - PyInstaller 생성 파일이 오탐될 수 있음

---

**✨ 요약: install_and_run_fixed.bat + requirements_safe.txt + IDS_Training_Data_Generator.py + scripts/ + modules/ = 최소 실행 가능!** 