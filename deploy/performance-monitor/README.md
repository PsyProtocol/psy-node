# Parth performance monitor

`parth-perf-monitor` is a small, host-local telemetry collector intended for
proof workers and other memory-heavy Parth services. It stores short-interval
metrics and selected service journal events in SQLite so a resource peak can
be correlated with the proof workload that was active at that time.

The initial deployment targets `parth-offsite-prove-proxy.service` on
`arc99x2`. The collector is generic: another instance only needs a different
environment file with its systemd unit and cgroup path.

## Data model

Every five seconds the collector records:

- systemd cgroup memory current/peak and swap current/peak;
- cgroup anonymous, file, shmem, kernel, slab, and page-table memory;
- cgroup OOM, throttling, CPU, and block-I/O counters;
- aggregate RSS, virtual memory, swap, CPU, I/O, and thread count for all
  processes in the target cgroup;
- host total/available/cache/swap memory and load averages;
- filesystem total/free/available bytes, inode capacity, and host block-device
  read/write/I/O-time counters;
- kernel swap-in, swap-out, and major-fault counters;
- memory, CPU, and I/O PSI `avg10`;
- zram logical, compressed, physical, limit, and peak sizes.

The journal follower stores only diagnostically useful events: errors,
warnings, deposit batch work, withdrawal work, bridge aggregation, Groth16
work, contract proof work, and request IDs. Its durable journal cursor avoids
duplicating events after monitor restarts.

SQLite uses WAL mode. Raw samples and captured events are retained for 30 days
by default. At a five-second interval this is expected to remain well below
one gigabyte.

## Deploy on arc99x2

From the unified deployment repository:

```bash
bash deploy/performance-monitor/deploy-arc99x2.sh
```

The script builds an independent Rust crate, stages the binary and
configuration over SSH, prompts for sudo on `arc99x2`, and starts:

```text
parth-performance-monitor@prove-proxy.service
```

This does not restart or modify the prove-proxy service.

## Inspect

On `arc99x2`:

```bash
sudo /usr/local/bin/parth-perf-monitor report 2h
sudo /usr/local/bin/parth-perf-monitor events 30m
sudo /usr/local/bin/parth-perf-monitor alerts 24h
sudo /usr/local/bin/parth-perf-monitor report 7d
```

Or from the deployment checkout copied to that host:

```bash
REPORT_WINDOW=24h bash deploy/performance-monitor/status-arc99x2.sh
```

`report` prints the peak memory and swap values, swap-I/O deltas, PSI, OOM
counters, storage headroom, active alerts, and the eight largest memory
samples. For each peak sample it lists the proof event categories observed
within 30 seconds.

For ad-hoc investigation:

```bash
sudo sqlite3 /var/lib/parth-performance-monitor/prove-proxy/metrics.sqlite3
```

Useful SQL:

```sql
.headers on
.mode column
SELECT
  datetime(ts_ms / 1000, 'unixepoch', 'localtime') AS observed_at,
  round(cgroup_memory_current / 1073741824.0, 2) AS memory_gib,
  round(cgroup_swap_current / 1073741824.0, 2) AS swap_gib,
  round(host_memory_available / 1073741824.0, 2) AS available_gib,
  memory_psi_some_avg10 AS psi
FROM samples
ORDER BY cgroup_memory_current DESC
LIMIT 20;
```

```sql
SELECT
  datetime(ts_ms / 1000, 'unixepoch', 'localtime') AS observed_at,
  category,
  request_id,
  message
FROM journal_events
WHERE ts_ms >= (unixepoch('now', '-2 hours') * 1000)
ORDER BY ts_ms;
```

## Alerts

The collector persists alert state and history in SQLite and writes every
trigger, repeat, and resolution to its own systemd journal as
`PERFORMANCE_ALERT`. Conditions must normally be present in three consecutive
samples (15 seconds) before opening an alert. OOM kills alert immediately.

Default conditions:

- target service has no processes;
- cgroup memory is at least 56 GiB;
- host available memory is at most 4 GiB;
- swap-out rate is at least 64 MiB/min;
- memory PSI `some avg10` is at least 0.1;
- filesystem has at most 10 GiB available, or is below 10% while also below
  50 GiB available;
- free inodes are at most 10%;
- logical zram swap use is at least 80%;
- cgroup OOM kill counter increases.

Open alerts are deduplicated by key. An active condition is repeated at most
once every 15 minutes and emits a matching resolution when it clears.
Thresholds are configured in `prove-proxy.env`.

PagerDuty Events v2 is optional. Put the integration routing key on
`arc99x2`; do not commit it:

```bash
sudoedit /etc/parth/performance-monitor-alerts.env
```

```text
PARTH_PERF_PAGERDUTY_ROUTING_KEY=<integration-routing-key>
```

Slack is supported through an Incoming Webhook. Create a Slack app, enable
Incoming Webhooks, and authorize it for the target alerts channel:

<https://api.slack.com/messaging/webhooks>

Add the generated secret URL to the same machine-local file:

```text
PARTH_PERF_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

Then restart only the monitor:

```bash
sudo systemctl restart parth-performance-monitor@prove-proxy.service
```

Verify delivery without creating an alert in SQLite:

```bash
sudo /usr/local/bin/parth-perf-monitor test-slack
```

Slack receives a Block Kit message for both trigger and resolution, including
severity, host, service, first-observed time, alert key, and details. The
webhook URL is passed to curl through a protected process environment variable
instead of a command-line argument.

Without PagerDuty or Slack secrets, alerts remain fully available in SQLite
and journald:

```bash
sudo journalctl -u parth-performance-monitor@prove-proxy.service \
  -g PERFORMANCE_ALERT --since '24 hours ago'
```

## Operational limits

The monitor runs with a 5% CPU quota, idle I/O priority, and a 256 MiB memory
limit. It reads local `/proc`, `/sys/fs/cgroup`, zram sysfs, and journald only.
It opens no network listener and does not export private request payloads.

Do not interpret non-zero swap usage alone as an incident. Investigate when
swap-out counters continue increasing, memory PSI becomes non-zero, available
memory remains low, or cgroup OOM counters change.
