#!/usr/bin/env bash

set -u
set -o pipefail

PYTHON=/home/yu3194924316/llmrec-py311-env/bin/python
ROOT=/home/yu3194924316/llm-recovery-dt/llm_ir_dt_new

cd "$ROOT"

replay_server() {
    local run_dir=$1
    local server_label=$2

    echo
    echo "=== Replaying four-server recovery for ${server_label} ==="

    "$PYTHON" stop.py
    "$PYTHON" start.py
    "$PYTHON" run_attack_four_servers_diverse.py

    "$PYTHON" -u replay_selected_plans.py \
        --selected-plans-dir "$run_dir/selected_plans" \
        --output-json "$run_dir/replay_selected_plans.json" \
        2>&1 | tee "$run_dir/replay_selected_plans.log"
}

replay_server \
    "artifacts/recovery_loop_llm_state/runs/20260613_105607four_servers_10.0.2.11_server_ssh" \
    "10.0.2.11 server_ssh"

replay_server \
    "artifacts/recovery_loop_llm_state/runs/20260614_030822four_servers_10.0.2.12_server_samba" \
    "10.0.2.12 server_samba"

replay_server \
    "artifacts/recovery_loop_llm_state/runs/20260613_081302four_servers_10.0.2.13_server_shellshock" \
    "10.0.2.13 server_shellshock"

replay_server \
    "artifacts/recovery_loop_llm_state/runs/20260614_052443four_servers10.0.2.14_server_web1" \
    "10.0.2.14 server_web1"
