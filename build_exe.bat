@echo off
setlocal
cd /d "%~dp0"

echo Building Veyra Scan...
echo.

python -c "import sys" >nul 2>nul
if errorlevel 1 (
    py -3 -c "import sys" >nul 2>nul
    if errorlevel 1 (
        echo Python not found. Install Python 3.10+ and try again.
        pause
        exit /b 1
    )
    set "PY=py -3"
) else (
    set "PY=python"
)

%PY% -m pip install --upgrade pip
if errorlevel 1 goto fail
%PY% -m pip install -r requirements.txt
if errorlevel 1 goto fail
%PY% -m pip install pyinstaller
if errorlevel 1 goto fail

if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist "Veyra Scan.spec" del /q "Veyra Scan.spec"

%PY% -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin --name "Veyra Scan" --add-data "xien_control\anime_background.png;xien_control" main.py
if errorlevel 1 goto fail

echo.
echo Build finished.
echo Output:
echo dist\Veyra Scan.exe
echo.
pause
exit /b 0

:fail
echo.
echo Build failed. Read the error above.
pause
exit /b 1
