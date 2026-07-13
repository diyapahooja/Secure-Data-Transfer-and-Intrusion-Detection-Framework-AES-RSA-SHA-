@echo off
echo Installing required libraries...
python -m pip install -r requirements.txt
echo.
echo Starting SDTIDF project...
python main.py
pause
