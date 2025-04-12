   @echo off
   setlocal

   set "script_path=Intrusion_DetectionSystem\scripts\MainApp.py"
   set "python_exe=python"  REM Python 실행 파일 경로를 지정합니다.

   REM 관리자 권한으로 실행
   powershell -Command "Start-Process '%python_exe%' -ArgumentList '%script_path%' -Verb RunAs"

   endlocal