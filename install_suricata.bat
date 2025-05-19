@echo off
echo ===================================================
echo 수리카타(Suricata) 설치 스크립트
echo ===================================================
echo.

echo 설치 디렉토리 생성 중...
mkdir C:\Suricata 2>nul
cd C:\Suricata

echo 수리카타 다운로드 중...
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.1-1-64bit.msi' -OutFile 'Suricata-7.0.1-1-64bit.msi'}"

echo 다운로드가 완료되었습니다. 설치를 시작합니다...
msiexec /i Suricata-7.0.1-1-64bit.msi /quiet

echo 환경 변수 설정...
setx SURICATA_PATH "C:\Program Files\Suricata\suricata.exe" /M

echo 기본 규칙 다운로드 중...
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://rules.emergingthreats.net/open/suricata-7.0.1/emerging.rules.tar.gz' -OutFile 'emerging.rules.tar.gz'}"

echo 설치가 완료되었습니다.
echo.
echo ===================================================
echo 설치 후 작업:
echo 1. 'modules/suricata_manager.py' 파일이 정상적으로 임포트되는지 확인하세요.
echo 2. 환경 변수 SURICATA_PATH가 올바르게 설정되었는지 확인하세요.
echo 3. 프로그램을 재시작하여 고성능 모드를 테스트하세요.
echo ===================================================
echo.
pause 