@echo off
chcp 65001 > nul
echo.
echo ================================================================
echo  Git 파일 상태 확인 도구
echo ================================================================
echo.

echo  중요 파일 상태 확인 중...
echo.

:: requirements.txt 확인
echo [1] requirements.txt 파일:
if exist requirements.txt (
    echo   ✓ 루트 requirements.txt 존재
    git ls-files requirements.txt >nul 2>&1
    if %errorLevel% == 0 (
        echo   ✓ Git에 추가됨
    ) else (
        echo   ✗ Git에 추가 안됨 - 'git add requirements.txt' 실행 필요
    )
) else (
    echo   ✗ 루트 requirements.txt 없음
)

echo.
if exist IDS\requirements.txt (
    echo   ✓ IDS\requirements.txt 존재
    git ls-files IDS/requirements.txt >nul 2>&1
    if %errorLevel% == 0 (
        echo   ✓ Git에 추가됨
    ) else (
        echo   ✗ Git에 추가 안됨 - 'git add IDS/requirements.txt' 실행 필요
    )
) else (
    echo   ✗ IDS\requirements.txt 없음
)

echo.
echo [2] setup_and_run.bat 파일:
if exist setup_and_run.bat (
    echo   ✓ setup_and_run.bat 존재
    git ls-files setup_and_run.bat >nul 2>&1
    if %errorLevel% == 0 (
        echo   ✓ Git에 추가됨
    ) else (
        echo   ✗ Git에 추가 안됨 - 'git add setup_and_run.bat' 실행 필요
    )
) else (
    echo   ✗ setup_and_run.bat 없음
)

echo.
echo [3] README.md 파일:
if exist README.md (
    echo   ✓ README.md 존재
    git ls-files README.md >nul 2>&1
    if %errorLevel% == 0 (
        echo   ✓ Git에 추가됨
    ) else (
        echo   ✗ Git에 추가 안됨 - 'git add README.md' 실행 필요
    )
) else (
    echo   ✗ README.md 없음
)

echo.
echo [4] INSTALLATION_GUIDE.md 파일:
if exist INSTALLATION_GUIDE.md (
    echo   ✓ INSTALLATION_GUIDE.md 존재
    git ls-files INSTALLATION_GUIDE.md >nul 2>&1
    if %errorLevel% == 0 (
        echo   ✓ Git에 추가됨
    ) else (
        echo   ✗ Git에 추가 안됨 - 'git add INSTALLATION_GUIDE.md' 실행 필요
    )
) else (
    echo   ✗ INSTALLATION_GUIDE.md 없음
)

echo.
echo ================================================================
echo  .gitignore 확인
echo ================================================================
echo.

echo  .gitignore에서 requirements.txt 예외 처리 확인:
findstr /C:"!requirements.txt" .gitignore >nul 2>&1
if %errorLevel% == 0 (
    echo   ✓ requirements.txt 예외 처리됨
) else (
    echo   ✗ requirements.txt 예외 처리 안됨
    echo   .gitignore에 다음 줄 추가 필요:
    echo   !requirements.txt
    echo   !IDS/requirements.txt
)

echo.
echo ================================================================
echo  권장 Git 명령어
echo ================================================================
echo.
echo  1. 중요 파일 추가:
echo     git add requirements.txt
echo     git add IDS/requirements.txt
echo     git add setup_and_run.bat
echo     git add README.md
echo     git add INSTALLATION_GUIDE.md
echo     git add .gitignore
echo.
echo  2. 커밋:
echo     git commit -m "Update: requirements.txt 및 설치 스크립트 수정"
echo.
echo  3. 푸시:
echo     git push origin main
echo.

pause

