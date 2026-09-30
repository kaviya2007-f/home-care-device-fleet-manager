"""
Cross-Platform Launcher for Home-Care Device Fleet Monitoring System
Operational device support only — this system does not provide medical advice or clinical recommendations.
"""

import subprocess
import sys
import time
import os


def main():
    print("=" * 72)
    print("🛡️  HOME-CARE DEVICE FLEET MONITORING PROTOTYPE LAUNCHER")
    print("=" * 72)

    # 1. Seed Database
    print("\n[1/4] Generating and seeding 500+ realistic devices...")
    subprocess.run([sys.executable, "data_generator.py"], check=True)

    # 2. Run Baseline Experiment Analysis
    print("\n[2/4] Running empirical baseline comparison & error analysis...")
    subprocess.run([sys.executable, "experiment_analysis.py"], check=True)

    # 3. Run Automated Tests
    print("\n[3/4] Running automated test suite...")
    subprocess.run([sys.executable, "-m", "pytest", "tests/", "-v"], check=True)

    # 4. Start Services
    print("\n[4/4] Starting FastAPI backend and Streamlit dashboard...")
    print("=" * 72)
    print("FastAPI Backend:     http://localhost:8000")
    print("Swagger UI Docs:     http://localhost:8000/docs")
    print("Streamlit Dashboard: http://localhost:8501")
    print("=" * 72)

    fastapi_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
    )

    time.sleep(2)

    try:
        subprocess.run(
            [sys.executable, "-m", "streamlit", "run", "dashboard.py", "--server.port", "8501", "--server.headless", "false"]
        )
    except KeyboardInterrupt:
        print("\nStopping services...")
    finally:
        fastapi_proc.terminate()
        fastapi_proc.wait()


if __name__ == "__main__":
    main()
