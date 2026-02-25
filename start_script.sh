#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"
APP="${APP:-app.main:app}"
ENV_FROM_DOTENV=""
if [[ -f .env ]]; then
  ENV_FROM_DOTENV="$(grep '^PFV_ENVIRONMENT=' .env 2>/dev/null | tail -n1 | cut -d= -f2- || true)"
  ENV_FROM_DOTENV="${ENV_FROM_DOTENV%\"}"
  ENV_FROM_DOTENV="${ENV_FROM_DOTENV#\"}"
fi
ENVIRONMENT="${PFV_ENVIRONMENT:-${ENVIRONMENT:-${ENV_FROM_DOTENV:-production}}}"
RELOAD="${RELOAD:-}"
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

find_port_listener_pids() {
  ss -ltnp "sport = :$PORT" 2>/dev/null | awk '
    NR > 1 {
      line = $0
      while (match(line, /pid=[0-9]+/)) {
        pid = substr(line, RSTART + 4, RLENGTH - 4)
        print pid
        line = substr(line, RSTART + RLENGTH)
      }
    }
  ' | sort -u
}

find_port_listeners() {
  local pid
  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    ps -p "$pid" -o pid=,args= 2>/dev/null || true
  done < <(find_port_listener_pids)
}

wait_until_stopped() {
  local timeout_seconds="${1:-5}"
  local elapsed=0
  while (( elapsed < timeout_seconds )); do
    if [[ -z "$(find_running_servers)" && -z "$(find_port_listener_pids)" ]]; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  [[ -z "$(find_running_servers)" && -z "$(find_port_listener_pids)" ]]
}

stop_matching_servers() {
  local grace_seconds="${1:-5}"
  local running
  local listeners
  local pids=()
  running="$(find_running_servers)"
  listeners="$(find_port_listeners)"
  if [[ -z "$running" && -z "$listeners" ]]; then
    echo "No matching server running on port $PORT."
    return 0
  fi

  echo "Stopping existing server(s) on port $PORT..."
  mapfile -t pids < <(
    {
      echo "$running" | awk '{print $1}'
      echo "$listeners" | awk '{print $1}'
    } | awk 'NF' | sort -u
  )
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

  echo "Some process(es) are still holding port $PORT:"
  find_port_listeners
  local still_running
  still_running="$(find_running_servers)"
  if [[ -n "$still_running" ]]; then
    echo "$still_running"
  fi
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
LISTENERS="$(find_port_listeners)"
if [[ -n "$RUNNING" || -n "$LISTENERS" ]]; then
  echo "Server already running on port $PORT:"
  if [[ -n "$RUNNING" ]]; then
    echo "$RUNNING"
  else
    echo "$LISTENERS"
  fi
  echo "Use ./start_script.sh --restart to restart cleanly."
  exit 0
fi

echo "Starting server on $HOST:$PORT..."
if [[ -z "$RELOAD" ]]; then
  case "${ENVIRONMENT,,}" in
    prod|production|staging)
      RELOAD="0"
      ;;
    *)
      RELOAD="1"
      ;;
  esac
fi

UVICORN_ARGS=(--host "$HOST" --port "$PORT")
if [[ "$RELOAD" == "1" || "$RELOAD" == "true" || "$RELOAD" == "yes" ]]; then
  UVICORN_ARGS+=(--reload)
fi

exec python3 -m uvicorn "$APP" "${UVICORN_ARGS[@]}"
