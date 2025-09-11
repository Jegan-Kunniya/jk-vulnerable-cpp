#!/bin/bash
# Security Compliance Dashboard Launcher

echo "🔒 Starting Security Compliance Dashboard..."

# Check if dependencies are installed
python3 -c "import streamlit, plotly, pandas" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing required dependencies..."
    pip install -r scripts/requirements.txt
fi

# Launch the dashboard
cd "$(dirname "$0")"
streamlit run scripts/security_dashboard.py --server.port 8501 --server.headless false

echo "Dashboard is running at: http://localhost:8501"