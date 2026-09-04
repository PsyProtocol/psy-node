# Mining Performance Optimization

> Updated: 2026-09-03.

## Abstract

Mining throughput depends primarily on CPU capacity, memory, storage latency, network stability, and worker concurrency. Measure the active worker process before increasing process count or batch size.

## Table of Contents

- [1. Hardware](#1-hardware)
- [2. Multiple Workers](#2-multiple-workers)
- [3. Monitoring](#3-monitoring)
- [4. Optimization Checklist](#4-optimization-checklist)
- [5. Failure Handling](#5-failure-handling)

## 1. Hardware

### 1.1 CPU

For proof generation, prefer:

- At least 8 CPU cores.
- High sustained clock speed.
- AVX-512 support when available.

Inspect CPU features and available cores:

```bash
lscpu | grep -E "(avx|sse)"
nproc
```

### 1.2 Memory

| Workload | Memory |
|---|---:|
| Minimum worker capacity | 8 GB |
| Recommended worker capacity | 16 GB or more |
| High-concurrency worker capacity | 32 GB or more |

### 1.3 Storage

- Use solid-state storage for proof data and job backups.
- Keep at least 100 GB free for sustained operation.
- Monitor write latency when several workers share one device.

### 1.4 GPU boundary

The worker performs proof generation on the supported CPU path. Do not plan worker capacity around GPU acceleration.

## 2. Multiple Workers

Run separate worker processes with separate wallet identities:

```bash
psy_worker_cli worker \
  --config config.json \
  --keystore-path miner1.json &

psy_worker_cli worker \
  --config config.json \
  --keystore-path miner2.json &

psy_worker_cli worker \
  --config config.json \
  --keystore-path miner3.json &
```

Increase worker count only while CPU, memory, and storage latency remain within operating limits. The worker also exposes `--batch-size` for concurrent job processing (`psy_cli/psy_worker_cli/src/subcommand.rs:55-56`).

## 3. Monitoring

Monitor the actual worker binary and its logs:

```bash
# CPU and memory usage
htop -p $(pgrep psy_worker_cli)

# Redirected worker output
tail -f miner.log
```

Track:

- CPU saturation and throttling.
- Resident memory and swap activity.
- Proof completion time.
- Job failure rate.
- Network disconnects.
- Storage latency and free space.

## 4. Optimization Checklist

1. Use dedicated hardware for sustained proof generation.
2. Keep worker endpoints on stable, low-latency network paths.
3. Increase process count or `--batch-size` one step at a time.
4. Stop increasing concurrency when proof latency or failure rate rises.
5. Retain completed-job backups required for reward claims.
6. Keep the operating system and CPU microcode updated.

## 5. Failure Handling

- **CPU saturation:** reduce worker count or `--batch-size`.
- **Memory pressure:** reduce concurrency before the system begins swapping.
- **Slow proof completion:** inspect thermal throttling and shared storage latency.
- **Worker disconnects:** verify every configured coordinator and realm endpoint.
- **Missing monitoring process:** confirm `psy_worker_cli` is running before invoking `htop`.
