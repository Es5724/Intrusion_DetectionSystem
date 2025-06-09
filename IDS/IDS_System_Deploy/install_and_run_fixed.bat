@echo off
chcp 65001 >nul
title IDS System Installer (Enhanced)
color 0F
echo ========================================
echo    IDS System Auto Installer v2.0
echo ========================================

REM Check Administrator Privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with Administrator privileges
) else (
    echo [ERROR] Administrator privileges required
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo.
echo ========================================
echo 1. SYSTEM DIAGNOSIS
echo ========================================

REM Check Windows version
echo Checking Windows version...
ver
echo.

REM Check Python installation with detailed info
echo Checking Python installation...
python --version >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Python installed
    python --version
    python -c "import sys; print('Python path:', sys.executable)"
    python -c "import sys; print('Python paths:', sys.path[:3])"
) else (
    echo [ERROR] Python not installed or not in PATH
    echo.
    echo SOLUTION OPTIONS:
    echo 1. Install Python from: https://www.python.org/downloads/
    echo 2. Make sure to check "Add Python to PATH" during installation
    echo 3. Or run: py --version (if Python Launcher is available)
    
    REM Try Python Launcher
    py --version >nul 2>&1
    if %errorLevel% == 0 (
        echo [INFO] Python Launcher found, using 'py' instead of 'python'
        set PYTHON_CMD=py
    ) else (
        pause
        exit /b 1
    )
)

if not defined PYTHON_CMD set PYTHON_CMD=python

echo.
echo Checking pip...
%PYTHON_CMD% -m pip --version
if %errorLevel% neq 0 (
    echo [ERROR] pip not found
    echo Installing pip...
    %PYTHON_CMD% -m ensurepip --upgrade
)

echo.
echo ========================================
echo 2. ENVIRONMENT PREPARATION
echo ========================================

echo Upgrading pip...
%PYTHON_CMD% -m pip install --upgrade pip
if %errorLevel% neq 0 (
    echo [WARNING] pip upgrade failed, continuing with current version
)

echo.
echo Checking Visual C++ Redistributable...
REM This is important for numpy, pandas, torch
if exist "C:\Program Files\Microsoft Visual Studio\2022" (
    echo [OK] Visual Studio 2022 found
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019" (
    echo [OK] Visual Studio 2019 found  
) else if exist "C:\Windows\System32\msvcp140.dll" (
    echo [OK] Visual C++ Redistributable found
) else (
    echo [WARNING] Visual C++ Redistributable may be missing
    echo This could cause issues with numpy, pandas, torch
    echo Download from: https://aka.ms/vs/17/release/vc_redist.x64.exe
)

echo.
echo ========================================
echo 3. PACKAGE INSTALLATION
echo ========================================

if exist "requirements_safe.txt" (
    echo Using safe requirements file...
    set REQUIREMENTS_FILE=requirements_safe.txt
) else if exist "requirements_exe.txt" (
    echo Using original requirements file...
    set REQUIREMENTS_FILE=requirements_exe.txt
) else (
    echo [ERROR] No requirements file found
    echo Creating minimal requirements...
    echo PyQt6^>=6.5.0> temp_requirements.txt
    echo pandas^>=2.0.0>> temp_requirements.txt
    echo numpy^>=1.21.0>> temp_requirements.txt
    echo matplotlib^>=3.5.0>> temp_requirements.txt
    echo scikit-learn^>=1.2.0>> temp_requirements.txt
    echo pyinstaller^>=5.0.0>> temp_requirements.txt
    set REQUIREMENTS_FILE=temp_requirements.txt
)

echo Installing packages with timeout and retry...
echo This may take 5-10 minutes...

REM Try installing with different strategies
echo.
echo Strategy 1: Normal installation
%PYTHON_CMD% -m pip install -r %REQUIREMENTS_FILE% --timeout 300
if %errorLevel% == 0 (
    echo [SUCCESS] All packages installed successfully
    goto :build_phase
)

echo.
echo Strategy 2: Installation with --user flag
%PYTHON_CMD% -m pip install -r %REQUIREMENTS_FILE% --user --timeout 300
if %errorLevel% == 0 (
    echo [SUCCESS] Packages installed in user directory
    goto :build_phase
)

echo.
echo Strategy 3: Installation without cache
%PYTHON_CMD% -m pip install -r %REQUIREMENTS_FILE% --no-cache-dir --timeout 300
if %errorLevel% == 0 (
    echo [SUCCESS] Packages installed without cache
    goto :build_phase
)

echo.
echo Strategy 4: Installing packages one by one...
for /f "tokens=*" %%i in (%REQUIREMENTS_FILE%) do (
    echo Installing %%i...
    %PYTHON_CMD% -m pip install "%%i" --timeout 120
    if %errorLevel% neq 0 (
        echo [WARNING] Failed to install %%i, trying without version constraint...
        for /f "tokens=1 delims=>=" %%j in ("%%i") do (
            %PYTHON_CMD% -m pip install "%%j"
        )
    )
)

:build_phase
echo.
echo ========================================
echo 4. VERIFICATION
echo ========================================

echo Verifying critical packages...
%PYTHON_CMD% -c "import PyQt6; print('PyQt6: OK')" 2>nul || echo [WARNING] PyQt6 not available
%PYTHON_CMD% -c "import pandas; print('pandas: OK')" 2>nul || echo [WARNING] pandas not available
%PYTHON_CMD% -c "import numpy; print('numpy: OK')" 2>nul || echo [WARNING] numpy not available
%PYTHON_CMD% -c "import sklearn; print('scikit-learn: OK')" 2>nul || echo [WARNING] scikit-learn not available

echo.
echo ========================================
echo 5. BUILDING APPLICATION
echo ========================================

if not exist "dist" mkdir dist

echo Checking for PyInstaller...
%PYTHON_CMD% -c "import PyInstaller; print('PyInstaller available')" 2>nul
if %errorLevel% neq 0 (
    echo Installing PyInstaller...
    %PYTHON_CMD% -m pip install pyinstaller
)

REM Try building with fallback options
if exist "IDS_TrainingDataGenerator.spec" (
    echo Building with spec file...
    %PYTHON_CMD% -m PyInstaller --clean IDS_TrainingDataGenerator.spec
) else if exist "IDS_Training_Data_Generator.py" (
    echo Building with simple method...
    %PYTHON_CMD% -m PyInstaller --onefile --windowed --name "IDS_TrainingDataGenerator" IDS_Training_Data_Generator.py
) else (
    echo [ERROR] No main Python file found
    echo Looking for available Python files...
    dir *.py
    pause
    exit /b 1
)

echo.
echo ========================================
echo 6. FINAL SETUP
echo ========================================

echo Copying configuration files...
if exist "defense_config.json" copy "defense_config.json" "dist\" >nul
if exist "data_set" xcopy "data_set" "dist\data_set\" /e /i /y >nul

echo.
echo ========================================
echo INSTALLATION COMPLETE!
echo ========================================

if exist "dist\IDS_TrainingDataGenerator.exe" (
    echo [SUCCESS] Application built successfully!
    echo Location: dist\IDS_TrainingDataGenerator.exe
    echo.
    echo Do you want to run the application now? (y/n)
    set /p run_app="Choice: "
    if /i "%run_app%"=="y" (
        start "" "dist\IDS_TrainingDataGenerator.exe"
    )
) else (
    echo [ERROR] Application build failed
    echo Check the error messages above
    echo.
    echo TROUBLESHOOTING TIPS:
    echo 1. Make sure you have stable internet connection
    echo 2. Disable antivirus temporarily during installation
    echo 3. Try running as administrator
    echo 4. Install Visual C++ Redistributable
    echo 5. Use Windows built-in Python instead of Anaconda
)

if exist "temp_requirements.txt" del "temp_requirements.txt"

echo.
echo Press any key to exit...
pause >nul 