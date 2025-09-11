@echo off
REM Security Compliance Dashboard Launcher for Windows
REM Cross-platform dashboard for security findings visualization

echo 🔒 Starting Security Compliance Dashboard...

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python from https://python.org/downloads/
    pause
    exit /b 1
)

REM Check if dependencies are installed
python -c "import streamlit, plotly, pandas" >nul 2>&1
if errorlevel 1 (
    echo Installing required dependencies...
    pip install -r scripts\requirements.txt
    if errorlevel 1 (
        echo Error: Failed to install dependencies
        pause
        exit /b 1
    )
)

REM Change to script directory
cd /d "%~dp0"

REM Launch the dashboard
echo Starting Streamlit dashboard...
streamlit run scripts\security_dashboard.py --server.port 8501 --server.headless false

echo.
echo Dashboard is running at: http://localhost:8501
echo Press Ctrl+C to stop the dashboard
pause