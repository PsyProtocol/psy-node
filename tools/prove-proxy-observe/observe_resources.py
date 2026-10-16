#!/usr/bin/env python3
"""Read-only, bounded external sampler. No env, command lines, payloads, or service changes."""
import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import subprocess
import time


def read(path):
    try:
        with open(path) as f:
            return f.read(65536)
    except OSError:
        return None


def pairs(text):
    result = {}
    for line in (text or "").splitlines():
        p = line.replace(":", "").split()
        if len(p) >= 2 and p[1].isdigit():
            result[p[0]] = int(p[1])
    return result


def sample(pid, gpu=False, diagnostic_dir=None):
    stat = read(f"/proc/{pid}/stat")
    if stat is None:
        return {"process_missing": True}
    # comm may contain spaces or parentheses; split after its last closing parenthesis.
    p = stat[stat.rfind(")") + 2:].split()
    status = pairs(read(f"/proc/{pid}/status"))
    result = {
        "pid": pid, "start_ticks": int(p[19]),
        "cpu_ticks": int(p[11]) + int(p[12]), "minor_faults": int(p[7]), "major_faults": int(p[9]),
        "process_kib": {k: status.get(k) for k in ("VmRSS", "RssAnon", "RssFile", "VmSwap", "VmLck")},
        "threads": status.get("Threads"), "process_io": pairs(read(f"/proc/{pid}/io")),
        "host_meminfo_kib": pairs(read("/proc/meminfo")),
        "host_vmstat": {k: v for k, v in pairs(read("/proc/vmstat")).items() if k in ("pswpin", "pswpout", "pgmajfault")},
        "host_psi": {kind: read(f"/proc/pressure/{kind}") for kind in ("cpu", "memory", "io")},
        "host_diskstats": read("/proc/diskstats"),
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"), "page_bytes": os.sysconf("SC_PAGE_SIZE"),
    }
    for line in (read(f"/proc/{pid}/cgroup") or "").splitlines():
        if line.startswith("0::"):
            relative = Path(line[3:].lstrip("/"))
            if ".." not in relative.parts:
                base = Path("/sys/fs/cgroup") / relative
                result["cgroup_v2"] = {name: read(base / name) for name in (
                    "memory.current", "memory.max", "memory.high", "memory.events", "memory.swap.current",
                    "cpu.stat", "cpu.max", "cpu.pressure", "memory.pressure", "io.pressure", "io.stat")}
    if diagnostic_dir:
        try:
            result["observer_log_age_s"] = time.time() - (Path(diagnostic_dir) / "events.0.jsonl").stat().st_mtime
        except OSError:
            result["observer_log_age_s"] = None
    if gpu:
        try:
            run = subprocess.run(["nvidia-smi", "--query-gpu=uuid,utilization.gpu,memory.used,memory.total",
                                  "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=2)
            result["gpu_device_csv"] = run.stdout[:4096] if run.returncode == 0 else None
            result["gpu_query_ok"] = run.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            result["gpu_query_ok"] = False
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=12)
    parser.add_argument("--interval", type=float, default=5)
    parser.add_argument("--gpu", action="store_true")
    parser.add_argument("--diagnostic-dir")
    args = parser.parse_args()
    if args.pid <= 0 or not 1 <= args.samples <= 17280 or not 1 <= args.interval <= 60:
        parser.error("positive PID; 1..17280 samples; 1..60 second interval")
    os.umask(0o077)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("resources")
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(args.output, maxBytes=4*1024*1024, backupCount=3)
    logger.addHandler(handler)
    identity, previous = None, None
    for index in range(args.samples):
        start = time.monotonic()
        data = sample(args.pid, args.gpu, args.diagnostic_dir)
        data.update(epoch_s=time.time(), mono_s=start)
        if identity is None:
            identity = data.get("start_ticks")
        elif identity != data.get("start_ticks"):
            data["identity_changed"] = True
        if previous and not data.get("process_missing") and not data.get("identity_changed"):
            dt = start - previous["mono_s"]
            data["rates"] = {k + "_per_s": (data[k] - previous[k]) / dt
                             for k in ("cpu_ticks", "minor_faults", "major_faults")}
            data["rates"]["cpu_cores"] = data["rates"]["cpu_ticks_per_s"] / data["clock_ticks_per_second"]
            data["rates"].update({k + "_pages_per_s": (v - previous["host_vmstat"].get(k, v)) / dt
                                     for k, v in data["host_vmstat"].items() if k.startswith("pswp")})
        logger.info(json.dumps(data, separators=(",", ":")))
        if data.get("process_missing") or data.get("identity_changed"):
            break
        previous = data
        if index + 1 < args.samples:
            time.sleep(max(0, args.interval - (time.monotonic() - start)))


if __name__ == "__main__":
    main()
