#!/usr/bin/env bash
set -euo pipefail

AGENT_NAME="SVLTAgent"
PIDS=( $(pgrep -x "$AGENT_NAME" || true) )
if [[ "${#PIDS[@]}" -eq 0 ]]; then
  echo "SVLTAgent is not running. Check System Settings > General > Login Items and SVLT service status."
  exit 1
fi

printf 'SVLTAgent processes: %s\n' "${PIDS[*]}"
ps -o pid,ppid,%cpu,%mem,rss,etime,command -p "${PIDS[*]// /,}"

echo
echo "For a short live sample (Ctrl-C to stop):"
echo "  top -pid ${PIDS[0]} -stats pid,command,cpu,mem,rsize,time -l 5"
if command -v powermetrics >/dev/null 2>&1; then
  echo
echo "Optional power sample (may require administrator approval):"
  echo "  sudo powermetrics --show-process-energy -n 1 | grep -A2 -B2 SVLTAgent"
fi
