#!/usr/bin/env bash
# One-command demo: Control Unit + simulated drone telemetry + one simulated RPF officer.
# Usage: bash run_demo.sh path/to/drone_clip.mp4
VIDEO=${1:-0}
python -m control_unit.server --video "$VIDEO" &
CU=$!
sleep 3
python tools/drone_sim.py &
python tools/handheld_sim.py --id HAND_02 --officer "HC Arun" &
echo; echo "Open http://localhost:5000/dashboard  (press Start run)"; echo "Phone: http://<this-ip>:5000/handheld"
trap "kill 0" EXIT
wait $CU
