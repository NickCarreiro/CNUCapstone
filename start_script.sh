#!/bin/bash
set -euo pipefail

PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"
APP="${APP:-app.main:app}"
MODE="${1:-start}"

find_running_servers() {
  ps -eo pid=,state=,comm=,args= | awk -v app="$APP" -v port="$PORT" '
    {
      pid = $1
      state = $2
      comm = $3

      # Rebuild args from field 4 onward.
      args = ""
      for (i = 4; i <= NF; i++) {
        args = args (i == 4 ? "" : " ") $i
      }

      # Skip zombies and only consider actual python/uvicorn server processes.
      if (state ~ /Z/) {
        next
      }
      is_server_proc = (comm ~ /^python([0-9.]+)?$/ || comm == "uvicorn")
      has_uvicorn = (index(args, "uvicorn") > 0)
      has_app = (index(args, app) > 0)
      has_port = (index(args, "--port " port) > 0 || index(args, "--port=" port) > 0)

      if (is_server_proc && has_uvicorn && has_app && has_port) {
        print pid " " args
      }
    }
  '
}

wait_until_stopped() {
  local timeout_seconds="${1:-5}"
  local elapsed=0
  while (( elapsed < timeout_seconds )); do
    if [[ -z "$(find_running_servers)" ]]; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  [[ -z "$(find_running_servers)" ]]
}

stop_matching_servers() {
  local grace_seconds="${1:-5}"
  local running
  running="$(find_running_servers)"
  if [[ -z "$running" ]]; then
    echo "No matching server running on port $PORT."
    return 0
  fi

  echo "Stopping existing server(s) on port $PORT..."
  mapfile -t pids < <(echo "$running" | awk '{print $1}' | sort -u)
  for pid in "${pids[@]}"; do
    kill -TERM "$pid" 2>/dev/null || true
  done

  if wait_until_stopped "$grace_seconds"; then
    echo "Server stopped."
    return 0
  fi

  echo "Graceful stop timed out; forcing shutdown..."
  for pid in "${pids[@]}"; do
    kill -KILL "$pid" 2>/dev/null || true
  done

  if wait_until_stopped 2; then
    echo "Server stopped."
    return 0
  fi

  echo "Some server process(es) are still running:"
  find_running_servers
  return 1
}

if [[ "$MODE" == "stop" || "$MODE" == "--stop" ]]; then
  stop_matching_servers
  exit $?
elif [[ "$MODE" == "restart" || "$MODE" == "--restart" ]]; then
  stop_matching_servers || exit 1
elif [[ "$MODE" != "start" ]]; then
  echo "Usage: ./start_script.sh [start|stop|--stop|restart|--restart]"
  exit 1
fi

RUNNING="$(find_running_servers)"
if [[ -n "$RUNNING" ]]; then
  echo "Server already running on port $PORT:"
  echo "$RUNNING"
  echo "Use ./start_script.sh --restart to restart cleanly."
  exit 0
fi

echo "Starting server on $HOST:$PORT..."
exec python3 -m uvicorn "$APP" --reload --host "$HOST" --port "$PORT"
