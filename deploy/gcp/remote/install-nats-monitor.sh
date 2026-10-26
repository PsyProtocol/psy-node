#!/usr/bin/env bash
set -euo pipefail

: "${NATS_MONITOR_UPLOAD_URL:?NATS_MONITOR_UPLOAD_URL is required}"
: "${NATS_MONITOR_UPLOAD_TOKEN:=}"
: "${NATS_MONITOR_LOCAL_DIR:=/var/log/parth/nats-monitor}"
: "${NATS_MONITOR_INTERVAL_SECONDS:=60}"
: "${NATS_MONITOR_RETENTION_MINUTES:=10080}"
: "${NATS_MONITOR_NATS_HTTP_PORT:=8222}"
: "${NATS_MONITOR_NATS_PORT:=4222}"

export DEBIAN_FRONTEND=noninteractive
missing=""
for cmd in curl jq ss docker; do
  command -v "$cmd" >/dev/null 2>&1 || {
    case "$cmd" in
      ss) missing="$missing iproute2" ;;
      docker) missing="$missing docker.io" ;;
      *) missing="$missing $cmd" ;;
    esac
  }
done
if [ -n "$missing" ]; then
  apt-get update
  apt-get install -y $missing
fi
systemctl enable --now docker >/dev/null 2>&1 || true

install -d -m 0755 "$NATS_MONITOR_LOCAL_DIR"
install -d -m 0755 /etc/parth

cat >/usr/local/bin/parth-nats-monitor-snapshot.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [ -f /etc/parth/nats-monitor.env ]; then
  # shellcheck disable=SC1091
  source /etc/parth/nats-monitor.env
fi

: "${NATS_MONITOR_UPLOAD_URL:?NATS_MONITOR_UPLOAD_URL is required}"
: "${NATS_MONITOR_UPLOAD_TOKEN:=}"
: "${NATS_MONITOR_LOCAL_DIR:=/var/log/parth/nats-monitor}"
: "${NATS_MONITOR_RETENTION_MINUTES:=10080}"
: "${NATS_MONITOR_NATS_HTTP_PORT:=8222}"
: "${NATS_MONITOR_NATS_PORT:=4222}"

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
host="$(hostname -f 2>/dev/null || hostname)"
short_host="$(hostname -s 2>/dev/null || hostname)"
mkdir -p "$NATS_MONITOR_LOCAL_DIR"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

write_text() {
  local output="$1"
  shift
  "$@" >"$output" 2>&1 || true
}

write_json_or_null() {
  local output="$1"
  local url="$2"
  curl -fsS --max-time 3 "$url" 2>/dev/null | jq -c . >"$output" 2>/dev/null || printf 'null\n' >"$output"
}

write_text "$tmp_dir/free.txt" free -h
write_text "$tmp_dir/free_bytes.txt" free -b
write_text "$tmp_dir/df.txt" df -h / /var/lib/parth /var/lib/parth/nats
write_text "$tmp_dir/df_bytes.txt" df -B1 / /var/lib/parth /var/lib/parth/nats
write_text "$tmp_dir/uptime.txt" uptime
cat /proc/loadavg >"$tmp_dir/loadavg.txt" 2>/dev/null || true
write_text "$tmp_dir/meminfo.txt" grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree|Dirty|Writeback):' /proc/meminfo
cat /proc/pressure/cpu >"$tmp_dir/pressure_cpu.txt" 2>/dev/null || true
cat /proc/pressure/memory >"$tmp_dir/pressure_memory.txt" 2>/dev/null || true
cat /proc/pressure/io >"$tmp_dir/pressure_io.txt" 2>/dev/null || true
write_text "$tmp_dir/ss.txt" ss -ltnp
write_text "$tmp_dir/docker_ps.txt" docker ps --filter name=nats-server --no-trunc
write_text "$tmp_dir/docker_stats.txt" docker stats nats-server --no-stream --format '{{json .}}'
docker inspect nats-server 2>/dev/null \
  | jq -c '.[0] | {State, RestartCount, Created, HostConfig: {RestartPolicy, Memory, NanoCpus}, NetworkSettings: {Ports}, Mounts}' \
  >"$tmp_dir/docker_inspect.json" 2>/dev/null || printf 'null\n' >"$tmp_dir/docker_inspect.json"
write_text "$tmp_dir/nats_container_logs.txt" docker logs --tail 120 nats-server
journalctl -k -n 500 --no-pager 2>/dev/null \
  | grep -Ei 'oom|out of memory|killed process|blocked for more than|hung task' \
  | tail -80 >"$tmp_dir/kernel_oom.txt" || true
journalctl -p warning -n 200 --no-pager 2>/dev/null \
  | tail -120 >"$tmp_dir/system_errors.txt" || true

nats_tcp_ok="false"
if timeout 2 bash -lc "</dev/tcp/127.0.0.1/${NATS_MONITOR_NATS_PORT}" >/dev/null 2>&1; then
  nats_tcp_ok="true"
fi

write_json_or_null "$tmp_dir/varz.json" "http://127.0.0.1:${NATS_MONITOR_NATS_HTTP_PORT}/varz"
write_json_or_null "$tmp_dir/jsz.json" "http://127.0.0.1:${NATS_MONITOR_NATS_HTTP_PORT}/jsz?config=true&streams=true&consumers=true"
write_json_or_null "$tmp_dir/connz.json" "http://127.0.0.1:${NATS_MONITOR_NATS_HTTP_PORT}/connz?limit=20&sort=last"

snapshot="$NATS_MONITOR_LOCAL_DIR/${stamp}.json"
jq -n \
  --arg timestamp "$timestamp" \
  --arg host "$host" \
  --arg short_host "$short_host" \
  --rawfile uptime "$tmp_dir/uptime.txt" \
  --rawfile loadavg "$tmp_dir/loadavg.txt" \
  --rawfile free "$tmp_dir/free.txt" \
  --rawfile free_bytes "$tmp_dir/free_bytes.txt" \
  --rawfile df "$tmp_dir/df.txt" \
  --rawfile df_bytes "$tmp_dir/df_bytes.txt" \
  --rawfile meminfo "$tmp_dir/meminfo.txt" \
  --rawfile pressure_cpu "$tmp_dir/pressure_cpu.txt" \
  --rawfile pressure_memory "$tmp_dir/pressure_memory.txt" \
  --rawfile pressure_io "$tmp_dir/pressure_io.txt" \
  --rawfile ss "$tmp_dir/ss.txt" \
  --rawfile docker_ps "$tmp_dir/docker_ps.txt" \
  --rawfile docker_stats "$tmp_dir/docker_stats.txt" \
  --rawfile nats_container_logs "$tmp_dir/nats_container_logs.txt" \
  --rawfile kernel_oom "$tmp_dir/kernel_oom.txt" \
  --rawfile system_errors "$tmp_dir/system_errors.txt" \
  --slurpfile docker_inspect "$tmp_dir/docker_inspect.json" \
  --slurpfile nats_varz "$tmp_dir/varz.json" \
  --slurpfile nats_jsz "$tmp_dir/jsz.json" \
  --slurpfile nats_connz "$tmp_dir/connz.json" \
  --argjson nats_tcp_ok "$nats_tcp_ok" \
  '{
    timestamp: $timestamp,
    host: $host,
    short_host: $short_host,
    checks: {
      nats_tcp_ok: $nats_tcp_ok
    },
    system: {
      uptime: $uptime,
      loadavg: $loadavg,
      free: $free,
      free_bytes: $free_bytes,
      df: $df,
      df_bytes: $df_bytes,
      meminfo: $meminfo,
      pressure: {
        cpu: $pressure_cpu,
        memory: $pressure_memory,
        io: $pressure_io
      },
      listening_sockets: $ss,
      kernel_oom: $kernel_oom,
      recent_warnings: $system_errors
    },
    docker: {
      ps: $docker_ps,
      stats: $docker_stats,
      inspect: $docker_inspect[0],
      nats_logs_tail: $nats_container_logs
    },
    nats: {
      varz: $nats_varz[0],
      jsz: $nats_jsz[0],
      connz: $nats_connz[0]
    }
  }' >"$snapshot"
ln -sfn "$snapshot" "$NATS_MONITOR_LOCAL_DIR/latest.json"

upload_base="${NATS_MONITOR_UPLOAD_URL%/}/${short_host}"
curl_args=(-fsS --max-time 10 --retry 2 --retry-delay 2 -X PUT)
if [ -n "$NATS_MONITOR_UPLOAD_TOKEN" ]; then
  curl_args+=(-H "X-Upload-Token: $NATS_MONITOR_UPLOAD_TOKEN")
fi
curl "${curl_args[@]}" --data-binary "@$snapshot" "${upload_base}/${stamp}.json" >/dev/null
curl "${curl_args[@]}" --data-binary "@$snapshot" "${upload_base}/latest.json" >/dev/null

find "$NATS_MONITOR_LOCAL_DIR" -type f -name '*.json' -mmin +"$NATS_MONITOR_RETENTION_MINUTES" -delete || true
SH
chmod 0755 /usr/local/bin/parth-nats-monitor-snapshot.sh

cat >/etc/parth/nats-monitor.env <<EOF
NATS_MONITOR_UPLOAD_URL=$NATS_MONITOR_UPLOAD_URL
NATS_MONITOR_UPLOAD_TOKEN=$NATS_MONITOR_UPLOAD_TOKEN
NATS_MONITOR_LOCAL_DIR=$NATS_MONITOR_LOCAL_DIR
NATS_MONITOR_RETENTION_MINUTES=$NATS_MONITOR_RETENTION_MINUTES
NATS_MONITOR_NATS_HTTP_PORT=$NATS_MONITOR_NATS_HTTP_PORT
NATS_MONITOR_NATS_PORT=$NATS_MONITOR_NATS_PORT
EOF
chmod 0600 /etc/parth/nats-monitor.env

cat >/etc/systemd/system/parth-nats-monitor.service <<'EOF'
[Unit]
Description=Parth NATS performance monitor snapshot
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/parth-nats-monitor-snapshot.sh
User=root
Group=root
EOF

cat >/etc/systemd/system/parth-nats-monitor.timer <<EOF
[Unit]
Description=Run Parth NATS performance monitor periodically

[Timer]
OnBootSec=30s
OnUnitActiveSec=${NATS_MONITOR_INTERVAL_SECONDS}s
AccuracySec=5s
Persistent=true
Unit=parth-nats-monitor.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now parth-nats-monitor.timer
systemctl restart parth-nats-monitor.service || true

echo "installed NATS monitor: upload=$NATS_MONITOR_UPLOAD_URL interval=${NATS_MONITOR_INTERVAL_SECONDS}s local_dir=$NATS_MONITOR_LOCAL_DIR"
systemctl --no-pager --full status parth-nats-monitor.timer || true
