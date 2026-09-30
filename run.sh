#!/usr/bin/env bash
# ==============================================================================
# Home-Care Device Fleet Monitoring System - Startup Script
# Operational device support only — does not provide medical advice.
# ==============================================================================

set -e

echo "========================================================================"
echo "🛡️  STARTING HOME-CARE DEVICE FLEET MONITORING PROTOTYPE"
echo "========================================================================"

echo "1. Checking Python dependencies..."
python -m pip install -r requirements.txt

echo "2. Seeding database with 500+ realistic fleet devices..."
python data_generator.py

echo "3. Running empirical experiment benchmark & baseline evaluation..."
python experiment_analysis.py

echo "4. Running automated verification test suite..."
python -m pytest tests/ -q

echo "========================================================================"
echo "🚀 Starting FastAPI Backend on port 8000 and Streamlit Dashboard on 8501"
echo "========================================================================"
echo "FastAPI API URL:     http://localhost:8000"
echo "Swagger Docs URL:    http://localhost:8000/docs"
echo "Streamlit Dashboard: http://localhost:8501"
echo "========================================================================"

# Launch FastAPI in background
uvicorn app.main:app --host 0.0.0.0 --port 8000 &
FASTAPI_PID=$!

# Launch Streamlit
streamlit run dashboard.py --server.port 8501 --server.headless true

# Trap kill signals
trap "kill $FASTAPI_PID" EXIT
