@echo off
chcp 65001 > nul
echo.
echo ================================================================
echo  반응형 AI 에이전트 취약점 자동진단 시스템 설치 및 실행
echo ================================================================
echo.
echo  버전: 2.0 (반응형 AI + 자동 취약점 진단)
echo  모드: Lightweight / Performance (Suricata 통합)
echo ================================================================
echo.

:: 관리자 권한 확인
net session >nul 2>&1
if %errorLevel% == 0 (
    echo  관리자 권한으로 실행 중입니다.
) else (
    echo  관리자 권한이 필요합니다.
    echo 우클릭 후 "관리자 권한으로 실행"을 선택해주세요.
    pause
    exit /b 1
)

echo.
echo  Python 설치 확인 중...
python --version >nul 2>&1
if %errorLevel% == 0 (
    python --version
    echo  Python이 설치되어 있습니다.
) else (
    echo  Python이 설치되어 있지 않습니다.
    echo Python 3.8 이상을 설치해주세요: https://python.org
    pause
    exit /b 1
)

echo.
echo ================================================================
echo  필수 패키지 설치 시작
echo ================================================================
echo.
echo  설치할 패키지:
echo   - 핵심: colorama, pandas, numpy, scikit-learn, torch, joblib
echo   - 네트워크: scapy, psutil
echo   - 웹/API: flask, flask-cors, apscheduler
echo   - 설정: pyyaml
echo   - 테스트: pytest, pytest-cov, pytest-mock
echo.

:: pip 업그레이드
echo  [1/2] pip 업그레이드 중...
python -m pip install --upgrade pip >nul 2>&1
if %errorLevel% == 0 (
    echo   pip 업그레이드 완료
) else (
    echo   경고: pip 업그레이드 실패
)

:: requirements.txt가 있는지 확인하고 설치
echo.
echo  [2/2] Python 패키지 설치 중...
if exist IDS\requirements.txt (
    echo   IDS\requirements.txt 발견 - 자동 설치 시작
    pip install -r IDS\requirements.txt --quiet
    if %errorLevel% == 0 (
        echo   패키지 설치 완료
    ) else (
        echo   경고: 일부 패키지 설치 실패 (시스템은 계속 작동할 수 있습니다)
    )
) else if exist requirements.txt (
    echo   requirements.txt 발견 - 자동 설치 시작
    pip install -r requirements.txt --quiet
    if %errorLevel% == 0 (
        echo   패키지 설치 완료
    ) else (
        echo   경고: 일부 패키지 설치 실패
    )
) else (
    echo   requirements.txt 없음 - 개별 설치 시작
    echo   [1/3] 핵심 패키지 설치 중...
    pip install colorama pandas numpy scikit-learn torch joblib scapy psutil --quiet
    echo   [2/3] 웹 서버 및 API 설치 중...
    pip install flask flask-cors apscheduler --quiet
    echo   [3/3] 설정 및 테스트 도구 설치 중...
    pip install pyyaml pytest pytest-cov pytest-mock --quiet
    echo   패키지 설치 완료
)

echo.
echo ================================================================
echo  패키지 설치 완료!
echo ================================================================
echo.

:: 필수 디렉토리 생성
echo  필수 디렉토리 확인 및 생성 중...
if not exist "logs" mkdir logs
if not exist "IDS\config" mkdir IDS\config
if not exist "IDS\rules" mkdir IDS\rules
if not exist "IDS\tests" mkdir IDS\tests
echo  디렉토리 생성 완료

:: 필수 파일 확인
echo.
echo  필수 파일 확인 중...
if exist "IDS\kisti_random_forest_model.pkl" (
    echo   KISTI RF 모델: 존재
) else (
    echo   경고: KISTI RF 모델 파일이 없습니다.
    echo   경로: IDS\kisti_random_forest_model.pkl
    echo   시스템이 자동으로 모델을 학습할 것입니다.
)

if exist "IDS\defense_policy_agent.pth" (
    echo   RL 에이전트 모델: 존재
) else (
    echo   경고: RL 에이전트 모델 파일이 없습니다.
    echo   경로: IDS\defense_policy_agent.pth
    echo   시스템이 자동으로 모델을 초기화할 것입니다.
)

if exist "IDS\config\unified_config.yaml" (
    echo   통합 설정 파일: 존재
) else (
    echo   정보: 통합 설정 파일이 없습니다.
    echo   시스템이 기본 설정으로 자동 생성할 것입니다.
)

:: Npcap 설치 확인
echo.
echo  Npcap/WinPcap 설치 확인 중...
if exist "C:\Windows\System32\Npcap\wpcap.dll" (
    echo   Npcap이 설치되어 있습니다.
) else if exist "C:\Windows\System32\wpcap.dll" (
    echo   WinPcap이 설치되어 있습니다.
) else (
    echo.
    echo   경고: Npcap/WinPcap이 설치되어 있지 않습니다.
    echo   패킷 캡처를 위해 Npcap 설치가 필요합니다.
    echo.
    echo   자동 설치를 시작하시겠습니까?
    set /p install_npcap="Npcap 설치? (y/n): "
    
    if /i "%install_npcap%"=="y" (
        echo.
        echo   Npcap 다운로드 페이지를 엽니다...
        start https://npcap.com/#download
        echo.
        echo   다운로드 후 설치 프로그램을 실행하고
        echo   "WinPcap API-compatible Mode" 옵션을 체크하세요.
        echo.
        pause
    ) else (
        echo.
        echo   경고: Npcap 없이는 패킷 캡처를 할 수 없습니다.
        echo   시스템이 제대로 작동하지 않을 수 있습니다.
        echo.
    )
)

:: 수리카타 설치 확인 및 설치 옵션
echo.
echo ================================================================
echo      수리카타(Suricata) 설치 확인 및 설정
echo ================================================================
echo.

:: 수리카타 설치 확인
suricata --version >nul 2>&1
if %errorLevel% == 0 (
    echo  수리카타가 이미 설치되어 있습니다.
    suricata --version
    set SURICATA_INSTALLED=1
) else (
    echo  수리카타가 설치되어 있지 않습니다.
    echo  수리카타는 고성능 모드에 필요한 선택사항입니다.
    echo.
    set /p install_suricata="수리카타를 지금 설치하시겠습니까? (y/n): "
    
    if /i "%install_suricata%"=="y" (
        call :install_suricata
    ) else (
        echo   수리카타 없이 계속 진행합니다. 경량 모드만 사용 가능합니다.
        set SURICATA_INSTALLED=0
    )
)

echo.
echo ================================================================
echo      반응형 AI 에이전트 실행 옵션
echo ================================================================
echo.
echo  1. 일반 실행 (모드 선택 메뉴 표시)
echo  2. 경량 모드로 바로 실행 (RF 탐지만 사용)
if "%SURICATA_INSTALLED%"=="1" (
    echo  3. 고성능 모드로 바로 실행 (RF + Suricata 이중 검증)
) else (
    echo  3. 고성능 모드 (수리카타 필요 - 현재 사용 불가)
)
echo  4. 디버그 모드로 실행
echo  5. 시스템 테스트 실행
echo  6. 종료
echo.

:menu
set /p choice="선택하세요 (1-6): "

if "%choice%"=="1" (
    echo.
    echo  일반 모드로 실행 중...
    echo  - 반응형 AI 에이전트 활성화
    echo  - 온라인 RL 학습 활성화
    echo  - 자동 취약점 스캐너 활성화
    echo.
    cd IDS
    python IPSAgent_RL.py
) else if "%choice%"=="2" (
    echo.
    echo  경량 모드로 실행 중...
    echo  - Random Forest 위협 탐지 (F1=0.95)
    echo  - Conservative RL 에이전트
    echo  - 메모리 사용량: ~350MB
    echo.
    cd IDS
    python IPSAgent_RL.py --mode lightweight --no-menu
) else if "%choice%"=="3" (
    if "%SURICATA_INSTALLED%"=="1" (
        echo.
        echo  고성능 모드로 실행 중...
        echo  - Random Forest + Suricata 이중 검증
        echo  - Conservative RL 에이전트
        echo  - 메모리 사용량: ~400-450MB
        echo.
        cd IDS
        python IPSAgent_RL.py --mode performance --no-menu
    ) else (
        echo.
        echo  수리카타가 설치되지 않아 고성능 모드를 사용할 수 없습니다.
        echo  스크립트를 다시 실행하여 수리카타를 설치해주세요.
        echo.
        pause
        goto menu
    )
) else if "%choice%"=="4" (
    echo.
    echo  디버그 모드로 실행 중...
    echo  - 상세 로그 출력
    echo  - 에러 추적 활성화
    echo.
    cd IDS
    python IPSAgent_RL.py --debug
) else if "%choice%"=="5" (
    echo.
    echo  시스템 테스트 실행 중...
    echo.
    cd IDS
    echo  [1/3] Suricata 통합 테스트...
    python test_suricata_integration.py
    echo.
    echo  [2/3] 시스템 관리 테스트...
    python test_system_management.py
    echo.
    echo  [3/3] 반응형 AI 시스템 테스트...
    python test_reactive_ai_system.py
    echo.
    echo  테스트 완료!
    cd ..
    pause
    goto menu
) else if "%choice%"=="6" (
    echo.
    echo  종료합니다.
    exit /b 0
) else (
    echo.
    echo  잘못된 선택입니다. 1-6 중에서 선택해주세요.
    echo.
    pause
    goto menu
)

echo.
echo ================================================================
echo  프로그램이 종료되었습니다.
echo ================================================================
echo.
pause
exit /b 0

:install_suricata
echo.
echo ================================================================
echo      수리카타 자동 설치 시작
echo ================================================================
echo.

:: 임시 디렉토리 생성
if not exist "temp_suricata" mkdir temp_suricata
cd temp_suricata

echo  수리카타 설치 파일 다운로드 중...
echo  다운로드가 시작되면 잠시 기다려주세요...

:: PowerShell을 사용하여 수리카타 다운로드
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.2-1-64bit.msi' -OutFile 'Suricata-installer.msi' -UseBasicParsing}" 2>nul

if exist "Suricata-installer.msi" (
    echo  다운로드 완료!
    echo.
    echo  수리카타 설치 중...
    echo  설치 창이 나타나면 기본 설정으로 설치를 진행해주세요.
    
    :: MSI 설치 실행
    msiexec /i "Suricata-installer.msi" /passive /norestart
    
    echo  수리카타 설치 완료!
    
) else (
    echo  다운로드에 실패했습니다.
    echo  수동 설치 방법:
    echo    1. https://suricata.io/download/ 에서 Windows 버전 다운로드
    echo    2. 다운로드한 MSI 파일을 실행하여 설치
    echo    3. 이 스크립트를 다시 실행
    cd ..
    rmdir /s /q temp_suricata >nul 2>&1
    set SURICATA_INSTALLED=0
    pause
    goto :eof
)

:: 임시 파일 정리
cd ..
rmdir /s /q temp_suricata >nul 2>&1

:: 환경 변수 설정
echo.
echo 🔧 환경 변수 설정 중...

:: 일반적인 설치 경로들 확인
set SURICATA_PATH=""
if exist "C:\Program Files\Suricata\suricata.exe" (
    set SURICATA_PATH="C:\Program Files\Suricata"
) else if exist "C:\Program Files (x86)\Suricata\suricata.exe" (
    set SURICATA_PATH="C:\Program Files (x86)\Suricata"
) else (
    echo  수리카타 설치 경로를 찾을 수 없습니다.
    echo  수동으로 PATH 환경 변수에 수리카타 경로를 추가해주세요.
    set SURICATA_INSTALLED=0
    pause
    goto :eof
)

:: PATH에 수리카타 경로 추가
echo  시스템 PATH에 수리카타 경로 추가 중...
setx PATH "%PATH%;%SURICATA_PATH%" /M >nul 2>&1

:: 설치 확인
echo.
echo  설치 확인 중...
timeout /t 3 /nobreak >nul

:: 새로운 환경에서 수리카타 확인
"%SURICATA_PATH%\suricata.exe" --version >nul 2>&1
if %errorLevel% == 0 (
    echo  수리카타 설치 및 설정 완료!
    "%SURICATA_PATH%\suricata.exe" --version
    set SURICATA_INSTALLED=1
    
    echo.
    echo  축하합니다! 이제 고성능 모드를 사용할 수 있습니다.
    echo  설정을 완전히 적용하려면 명령 프롬프트를 재시작하는 것이 좋습니다.
    
) else (
    echo  설치는 완료되었지만 설정에 문제가 있습니다.
    echo  컴퓨터를 재시작한 후 다시 시도해주세요.
    set SURICATA_INSTALLED=0
)

echo.
pause
goto :eof 