@echo off
REM One-command demo on Windows: run_demo.bat path\to\drone_clip.mp4
set VIDEO=%1
if "%VIDEO%"=="" set VIDEO=0
start "Control Unit" python -m control_unit.server --video "%VIDEO%"
timeout /t 3 >nul
start "Drone sim" python tools\drone_sim.py
start "Handheld sim" python tools\handheld_sim.py --id HAND_02 --officer "HC Arun"
echo Open http://localhost:5000/dashboard and press Start run
