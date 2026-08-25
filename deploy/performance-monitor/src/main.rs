use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ffi::CString;
use std::env;
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

const SCHEMA_VERSION: &str = "2";

#[derive(Clone, Debug)]
struct Config {
    db_path: PathBuf,
    unit: String,
    cgroup_path: PathBuf,
    interval: Duration,
    retention: Duration,
    journal_enabled: bool,
    journal_since: String,
    storage_path: PathBuf,
    alert_consecutive_samples: u32,
    alert_cooldown: Duration,
    alert_memory_bytes: i64,
    alert_available_bytes: i64,
    alert_swap_out_bytes_per_minute: i64,
    alert_memory_psi_avg10: f64,
    alert_disk_available_bytes: i64,
    alert_disk_available_percent: f64,
    alert_inode_free_percent: f64,
    alert_zram_percent: f64,
    pagerduty_routing_key: Option<String>,
    slack_webhook_url: Option<String>,
}

impl Config {
    fn from_env() -> Result<Self> {
        let interval_secs = env_u64("PARTH_PERF_INTERVAL_SECS", 5)?.max(1);
        let retention_days = env_u64("PARTH_PERF_RETENTION_DAYS", 30)?.max(1);
        Ok(Self {
            db_path: env::var_os("PARTH_PERF_DB")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from(
                        "/var/lib/parth-performance-monitor/prove-proxy/metrics.sqlite3",
                    )
                }),
            unit: env::var("PARTH_PERF_UNIT")
                .unwrap_or_else(|_| "parth-offsite-prove-proxy.service".to_owned()),
            cgroup_path: env::var_os("PARTH_PERF_CGROUP")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from(
                        "/sys/fs/cgroup/system.slice/parth-offsite-prove-proxy.service",
                    )
                }),
            interval: Duration::from_secs(interval_secs),
            retention: Duration::from_secs(retention_days * 86_400),
            journal_enabled: env_bool("PARTH_PERF_JOURNAL_ENABLED", true),
            journal_since: env::var("PARTH_PERF_JOURNAL_INITIAL_SINCE")
                .unwrap_or_else(|_| "-1 hour".to_owned()),
            storage_path: env::var_os("PARTH_PERF_STORAGE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/")),
            alert_consecutive_samples: env_u64("PARTH_PERF_ALERT_CONSECUTIVE_SAMPLES", 3)?
                .max(1) as u32,
            alert_cooldown: Duration::from_secs(
                env_u64("PARTH_PERF_ALERT_COOLDOWN_SECS", 900)?.max(60),
            ),
            alert_memory_bytes: env_gib("PARTH_PERF_ALERT_MEMORY_GIB", 56.0)?,
            alert_available_bytes: env_gib("PARTH_PERF_ALERT_AVAILABLE_GIB", 4.0)?,
            alert_swap_out_bytes_per_minute: env_mib(
                "PARTH_PERF_ALERT_SWAP_OUT_MIB_PER_MIN",
                64.0,
            )?,
            alert_memory_psi_avg10: env_f64("PARTH_PERF_ALERT_MEMORY_PSI_AVG10", 0.1)?,
            alert_disk_available_bytes: env_gib(
                "PARTH_PERF_ALERT_DISK_AVAILABLE_GIB",
                10.0,
            )?,
            alert_disk_available_percent: env_f64(
                "PARTH_PERF_ALERT_DISK_AVAILABLE_PERCENT",
                10.0,
            )?,
            alert_inode_free_percent: env_f64(
                "PARTH_PERF_ALERT_INODE_FREE_PERCENT",
                10.0,
            )?,
            alert_zram_percent: env_f64("PARTH_PERF_ALERT_ZRAM_PERCENT", 80.0)?,
            pagerduty_routing_key: env::var("PARTH_PERF_PAGERDUTY_ROUTING_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            slack_webhook_url: env::var("PARTH_PERF_SLACK_WEBHOOK_URL")
                .ok()
                .filter(|value| !value.trim().is_empty()),
        })
    }
}

#[derive(Default, Debug)]
struct Psi {
    some_avg10: f64,
    full_avg10: f64,
}

#[derive(Default, Debug)]
struct ProcAggregate {
    main_pid: i64,
    pid_count: i64,
    rss_bytes: i64,
    swap_bytes: i64,
    virtual_bytes: i64,
    threads: i64,
    cpu_ticks: i64,
    read_bytes: i64,
    write_bytes: i64,
}

#[derive(Default, Debug)]
struct Storage {
    total_bytes: i64,
    free_bytes: i64,
    available_bytes: i64,
    total_inodes: i64,
    free_inodes: i64,
}

#[derive(Clone, Debug)]
struct AlertRule {
    key: &'static str,
    severity: &'static str,
    condition: bool,
    immediate: bool,
    message: String,
}

#[derive(Default, Debug)]
struct ReportSummary {
    sample_count: i64,
    first_ts_ms: i64,
    last_ts_ms: i64,
    peak_memory_bytes: i64,
    peak_swap_bytes: i64,
    minimum_available_memory_bytes: i64,
    peak_memory_psi_some: f64,
    peak_memory_psi_full: f64,
    swap_in_pages: i64,
    swap_out_pages: i64,
    oom_count: i64,
    oom_kill_count: i64,
    minimum_storage_available_bytes: i64,
    minimum_storage_available_percent: f64,
    disk_read_bytes: i64,
    disk_write_bytes: i64,
    disk_io_millis: i64,
}

#[derive(Clone, Default, Debug)]
struct Sample {
    ts_ms: i64,
    boot_id: String,
    main_pid: i64,
    pid_count: i64,
    cgroup_memory_current: i64,
    cgroup_memory_peak: i64,
    cgroup_swap_current: i64,
    cgroup_swap_peak: i64,
    cgroup_anon: i64,
    cgroup_file: i64,
    cgroup_shmem: i64,
    cgroup_kernel: i64,
    cgroup_slab: i64,
    cgroup_pagetables: i64,
    event_high: i64,
    event_max: i64,
    event_oom: i64,
    event_oom_kill: i64,
    process_rss: i64,
    process_swap: i64,
    process_virtual: i64,
    process_threads: i64,
    process_cpu_ticks: i64,
    process_read_bytes: i64,
    process_write_bytes: i64,
    host_memory_total: i64,
    host_memory_available: i64,
    host_cached: i64,
    host_swap_total: i64,
    host_swap_free: i64,
    vm_pswpin: i64,
    vm_pswpout: i64,
    vm_pgmajfault: i64,
    load1: f64,
    load5: f64,
    load15: f64,
    memory_psi_some_avg10: f64,
    memory_psi_full_avg10: f64,
    cpu_psi_some_avg10: f64,
    io_psi_some_avg10: f64,
    io_psi_full_avg10: f64,
    cpu_usage_usec: i64,
    cpu_user_usec: i64,
    cpu_system_usec: i64,
    cpu_nr_throttled: i64,
    cpu_throttled_usec: i64,
    cgroup_io_read_bytes: i64,
    cgroup_io_write_bytes: i64,
    zram_original_bytes: i64,
    zram_compressed_bytes: i64,
    zram_memory_used_bytes: i64,
    zram_memory_limit_bytes: i64,
    zram_memory_peak_bytes: i64,
    storage_total_bytes: i64,
    storage_free_bytes: i64,
    storage_available_bytes: i64,
    storage_total_inodes: i64,
    storage_free_inodes: i64,
    disk_read_bytes: i64,
    disk_write_bytes: i64,
    disk_io_millis: i64,
}

fn main() -> Result<()> {
    let command = env::args().nth(1).unwrap_or_else(|| "help".to_owned());
    let config = Config::from_env()?;
    match command.as_str() {
        "collect" => collect(config),
        "report" => {
            let duration = env::args().nth(2).unwrap_or_else(|| "1h".to_owned());
            report(&config, parse_duration(&duration)?)
        }
        "events" => {
            let duration = env::args().nth(2).unwrap_or_else(|| "1h".to_owned());
            print_events(&config, parse_duration(&duration)?)
        }
        "alerts" => {
            let duration = env::args().nth(2).unwrap_or_else(|| "24h".to_owned());
            print_alerts(&config, parse_duration(&duration)?)
        }
        "test-slack" => test_slack(&config),
        "prune" => {
            let mut conn = open_database(&config.db_path)?;
            prune(&mut conn, config.retention)
        }
        _ => {
            eprintln!(
                "Usage:\n  parth-perf-monitor collect\n  parth-perf-monitor report [15m|2h|7d]\n  parth-perf-monitor events [15m|2h|7d]\n  parth-perf-monitor alerts [1h|24h|7d]\n  parth-perf-monitor test-slack\n  parth-perf-monitor prune"
            );
            Ok(())
        }
    }
}

fn collect(config: Config) -> Result<()> {
    if let Some(parent) = config.db_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut conn = open_database(&config.db_path)?;
    set_metadata(&conn, "collector_unit", &config.unit)?;
    set_metadata(
        &conn,
        "collector_interval_seconds",
        &config.interval.as_secs().to_string(),
    )?;
    set_metadata(
        &conn,
        "collector_retention_seconds",
        &config.retention.as_secs().to_string(),
    )?;
    set_metadata(
        &conn,
        "collector_storage_path",
        &config.storage_path.display().to_string(),
    )?;
    set_metadata(
        &conn,
        "collector_hostname",
        &read_trimmed(Path::new("/etc/hostname")).unwrap_or_default(),
    )?;

    if config.journal_enabled {
        let journal_config = config.clone();
        thread::spawn(move || journal_supervisor(journal_config));
    }

    eprintln!(
        "collecting unit={} cgroup={} storage={} interval={}s db={}",
        config.unit,
        config.cgroup_path.display(),
        config.storage_path.display(),
        config.interval.as_secs(),
        config.db_path.display()
    );

    let mut samples_since_maintenance = 0_u64;
    let mut previous_sample: Option<Sample> = None;
    let mut alert_streaks: HashMap<String, u32> = HashMap::new();
    loop {
        let started = SystemTime::now();
        match read_sample(&config) {
            Ok(sample) => {
                if let Err(error) = insert_sample(&conn, &config.unit, &sample) {
                    eprintln!("sample insert failed: {error}");
                } else {
                    let _ = set_metadata(&conn, "last_sample_ts_ms", &sample.ts_ms.to_string());
                    if let Err(error) = evaluate_alerts(
                        &conn,
                        &config,
                        &sample,
                        previous_sample.as_ref(),
                        &mut alert_streaks,
                    ) {
                        eprintln!("alert evaluation failed: {error}");
                    }
                    previous_sample = Some(sample);
                }
            }
            Err(error) => eprintln!("sample collection failed: {error}"),
        }

        samples_since_maintenance += 1;
        let maintenance_every = (3600 / config.interval.as_secs()).max(1);
        if samples_since_maintenance >= maintenance_every {
            if let Err(error) = prune(&mut conn, config.retention) {
                eprintln!("database maintenance failed: {error}");
            }
            samples_since_maintenance = 0;
        }

        let elapsed = started.elapsed().unwrap_or_default();
        thread::sleep(config.interval.saturating_sub(elapsed));
    }
}

fn open_database(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute_batch(
        "
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA temp_store=MEMORY;
        PRAGMA wal_autocheckpoint=1000;

        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS samples (
            id INTEGER PRIMARY KEY,
            ts_ms INTEGER NOT NULL,
            boot_id TEXT NOT NULL,
            unit TEXT NOT NULL,
            main_pid INTEGER NOT NULL,
            pid_count INTEGER NOT NULL,
            cgroup_memory_current INTEGER NOT NULL,
            cgroup_memory_peak INTEGER NOT NULL,
            cgroup_swap_current INTEGER NOT NULL,
            cgroup_swap_peak INTEGER NOT NULL,
            cgroup_anon INTEGER NOT NULL,
            cgroup_file INTEGER NOT NULL,
            cgroup_shmem INTEGER NOT NULL,
            cgroup_kernel INTEGER NOT NULL,
            cgroup_slab INTEGER NOT NULL,
            cgroup_pagetables INTEGER NOT NULL,
            event_high INTEGER NOT NULL,
            event_max INTEGER NOT NULL,
            event_oom INTEGER NOT NULL,
            event_oom_kill INTEGER NOT NULL,
            process_rss INTEGER NOT NULL,
            process_swap INTEGER NOT NULL,
            process_virtual INTEGER NOT NULL,
            process_threads INTEGER NOT NULL,
            process_cpu_ticks INTEGER NOT NULL,
            process_read_bytes INTEGER NOT NULL,
            process_write_bytes INTEGER NOT NULL,
            host_memory_total INTEGER NOT NULL,
            host_memory_available INTEGER NOT NULL,
            host_cached INTEGER NOT NULL,
            host_swap_total INTEGER NOT NULL,
            host_swap_free INTEGER NOT NULL,
            vm_pswpin INTEGER NOT NULL,
            vm_pswpout INTEGER NOT NULL,
            vm_pgmajfault INTEGER NOT NULL,
            load1 REAL NOT NULL,
            load5 REAL NOT NULL,
            load15 REAL NOT NULL,
            memory_psi_some_avg10 REAL NOT NULL,
            memory_psi_full_avg10 REAL NOT NULL,
            cpu_psi_some_avg10 REAL NOT NULL,
            io_psi_some_avg10 REAL NOT NULL,
            io_psi_full_avg10 REAL NOT NULL,
            cpu_usage_usec INTEGER NOT NULL,
            cpu_user_usec INTEGER NOT NULL,
            cpu_system_usec INTEGER NOT NULL,
            cpu_nr_throttled INTEGER NOT NULL,
            cpu_throttled_usec INTEGER NOT NULL,
            cgroup_io_read_bytes INTEGER NOT NULL,
            cgroup_io_write_bytes INTEGER NOT NULL,
            zram_original_bytes INTEGER NOT NULL,
            zram_compressed_bytes INTEGER NOT NULL,
            zram_memory_used_bytes INTEGER NOT NULL,
            zram_memory_limit_bytes INTEGER NOT NULL,
            zram_memory_peak_bytes INTEGER NOT NULL,
            storage_total_bytes INTEGER NOT NULL,
            storage_free_bytes INTEGER NOT NULL,
            storage_available_bytes INTEGER NOT NULL,
            storage_total_inodes INTEGER NOT NULL,
            storage_free_inodes INTEGER NOT NULL,
            disk_read_bytes INTEGER NOT NULL,
            disk_write_bytes INTEGER NOT NULL,
            disk_io_millis INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS samples_ts_idx ON samples(ts_ms);

        CREATE TABLE IF NOT EXISTS journal_events (
            id INTEGER PRIMARY KEY,
            ts_ms INTEGER NOT NULL,
            cursor TEXT NOT NULL UNIQUE,
            unit TEXT NOT NULL,
            priority INTEGER,
            category TEXT NOT NULL,
            request_id TEXT,
            message TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS journal_events_ts_idx ON journal_events(ts_ms);
        CREATE INDEX IF NOT EXISTS journal_events_category_ts_idx
            ON journal_events(category, ts_ms);

        CREATE TABLE IF NOT EXISTS alert_state (
            key TEXT PRIMARY KEY,
            active INTEGER NOT NULL,
            first_ts_ms INTEGER NOT NULL,
            last_seen_ts_ms INTEGER NOT NULL,
            last_notify_ts_ms INTEGER NOT NULL,
            occurrences INTEGER NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alert_history (
            id INTEGER PRIMARY KEY,
            ts_ms INTEGER NOT NULL,
            key TEXT NOT NULL,
            action TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS alert_history_ts_idx ON alert_history(ts_ms);
        ",
    )?;
    ensure_column(&conn, "samples", "storage_total_bytes", "INTEGER NOT NULL DEFAULT 0")?;
    ensure_column(&conn, "samples", "storage_free_bytes", "INTEGER NOT NULL DEFAULT 0")?;
    ensure_column(
        &conn,
        "samples",
        "storage_available_bytes",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        &conn,
        "samples",
        "storage_total_inodes",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        &conn,
        "samples",
        "storage_free_inodes",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(&conn, "samples", "disk_read_bytes", "INTEGER NOT NULL DEFAULT 0")?;
    ensure_column(
        &conn,
        "samples",
        "disk_write_bytes",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(&conn, "samples", "disk_io_millis", "INTEGER NOT NULL DEFAULT 0")?;
    set_metadata(&conn, "schema_version", SCHEMA_VERSION)?;
    Ok(conn)
}

fn open_database_read_only(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(conn)
}

fn ensure_column(conn: &Connection, table: &str, column: &str, definition: &str) -> Result<()> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let exists = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(std::result::Result::ok)
        .any(|name| name == column);
    if !exists {
        conn.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {definition};"
        ))?;
    }
    Ok(())
}

fn set_metadata(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO metadata(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn read_sample(config: &Config) -> Result<Sample> {
    let memory_stat =
        read_key_values(&config.cgroup_path.join("memory.stat"), 1).unwrap_or_default();
    let memory_events =
        read_key_values(&config.cgroup_path.join("memory.events"), 1).unwrap_or_default();
    let cpu_stat = read_key_values(&config.cgroup_path.join("cpu.stat"), 1).unwrap_or_default();
    let host_mem = read_key_values(Path::new("/proc/meminfo"), 1024)?;
    let vm_stat = read_key_values(Path::new("/proc/vmstat"), 1)?;
    let proc = read_process_aggregate(&config.cgroup_path).unwrap_or_default();
    let memory_psi = read_psi(Path::new("/proc/pressure/memory"));
    let cpu_psi = read_psi(Path::new("/proc/pressure/cpu"));
    let io_psi = read_psi(Path::new("/proc/pressure/io"));
    let (load1, load5, load15) = read_loadavg()?;
    let (cgroup_io_read_bytes, cgroup_io_write_bytes) =
        read_cgroup_io(&config.cgroup_path.join("io.stat"));
    let zram = read_zram_mm_stat(Path::new("/sys/block/zram0/mm_stat"));
    let storage = read_storage(&config.storage_path)?;
    let disk = read_diskstats(Path::new("/proc/diskstats"));

    Ok(Sample {
        ts_ms: now_ms(),
        boot_id: read_trimmed(Path::new("/proc/sys/kernel/random/boot_id")).unwrap_or_default(),
        main_pid: proc.main_pid,
        pid_count: proc.pid_count,
        cgroup_memory_current: read_i64(&config.cgroup_path.join("memory.current")),
        cgroup_memory_peak: read_i64(&config.cgroup_path.join("memory.peak")),
        cgroup_swap_current: read_i64(&config.cgroup_path.join("memory.swap.current")),
        cgroup_swap_peak: read_i64(&config.cgroup_path.join("memory.swap.peak")),
        cgroup_anon: value(&memory_stat, "anon"),
        cgroup_file: value(&memory_stat, "file"),
        cgroup_shmem: value(&memory_stat, "shmem"),
        cgroup_kernel: value(&memory_stat, "kernel"),
        cgroup_slab: value(&memory_stat, "slab"),
        cgroup_pagetables: value(&memory_stat, "pagetables"),
        event_high: value(&memory_events, "high"),
        event_max: value(&memory_events, "max"),
        event_oom: value(&memory_events, "oom"),
        event_oom_kill: value(&memory_events, "oom_kill"),
        process_rss: proc.rss_bytes,
        process_swap: proc.swap_bytes,
        process_virtual: proc.virtual_bytes,
        process_threads: proc.threads,
        process_cpu_ticks: proc.cpu_ticks,
        process_read_bytes: proc.read_bytes,
        process_write_bytes: proc.write_bytes,
        host_memory_total: value(&host_mem, "MemTotal"),
        host_memory_available: value(&host_mem, "MemAvailable"),
        host_cached: value(&host_mem, "Cached") + value(&host_mem, "SReclaimable"),
        host_swap_total: value(&host_mem, "SwapTotal"),
        host_swap_free: value(&host_mem, "SwapFree"),
        vm_pswpin: value(&vm_stat, "pswpin"),
        vm_pswpout: value(&vm_stat, "pswpout"),
        vm_pgmajfault: value(&vm_stat, "pgmajfault"),
        load1,
        load5,
        load15,
        memory_psi_some_avg10: memory_psi.some_avg10,
        memory_psi_full_avg10: memory_psi.full_avg10,
        cpu_psi_some_avg10: cpu_psi.some_avg10,
        io_psi_some_avg10: io_psi.some_avg10,
        io_psi_full_avg10: io_psi.full_avg10,
        cpu_usage_usec: value(&cpu_stat, "usage_usec"),
        cpu_user_usec: value(&cpu_stat, "user_usec"),
        cpu_system_usec: value(&cpu_stat, "system_usec"),
        cpu_nr_throttled: value(&cpu_stat, "nr_throttled"),
        cpu_throttled_usec: value(&cpu_stat, "throttled_usec"),
        cgroup_io_read_bytes,
        cgroup_io_write_bytes,
        zram_original_bytes: zram[0],
        zram_compressed_bytes: zram[1],
        zram_memory_used_bytes: zram[2],
        zram_memory_limit_bytes: zram[3],
        zram_memory_peak_bytes: zram[4],
        storage_total_bytes: storage.total_bytes,
        storage_free_bytes: storage.free_bytes,
        storage_available_bytes: storage.available_bytes,
        storage_total_inodes: storage.total_inodes,
        storage_free_inodes: storage.free_inodes,
        disk_read_bytes: disk.0,
        disk_write_bytes: disk.1,
        disk_io_millis: disk.2,
    })
}

fn insert_sample(conn: &Connection, unit: &str, sample: &Sample) -> Result<()> {
    conn.execute(
        "INSERT INTO samples (
            ts_ms, boot_id, unit, main_pid, pid_count,
            cgroup_memory_current, cgroup_memory_peak,
            cgroup_swap_current, cgroup_swap_peak,
            cgroup_anon, cgroup_file, cgroup_shmem, cgroup_kernel,
            cgroup_slab, cgroup_pagetables,
            event_high, event_max, event_oom, event_oom_kill,
            process_rss, process_swap, process_virtual, process_threads,
            process_cpu_ticks, process_read_bytes, process_write_bytes,
            host_memory_total, host_memory_available, host_cached,
            host_swap_total, host_swap_free,
            vm_pswpin, vm_pswpout, vm_pgmajfault,
            load1, load5, load15,
            memory_psi_some_avg10, memory_psi_full_avg10,
            cpu_psi_some_avg10, io_psi_some_avg10, io_psi_full_avg10,
            cpu_usage_usec, cpu_user_usec, cpu_system_usec,
            cpu_nr_throttled, cpu_throttled_usec,
            cgroup_io_read_bytes, cgroup_io_write_bytes,
            zram_original_bytes, zram_compressed_bytes,
            zram_memory_used_bytes, zram_memory_limit_bytes,
            zram_memory_peak_bytes,
            storage_total_bytes, storage_free_bytes, storage_available_bytes,
            storage_total_inodes, storage_free_inodes,
            disk_read_bytes, disk_write_bytes, disk_io_millis
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
            ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30,
            ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38, ?39, ?40,
            ?41, ?42, ?43, ?44, ?45, ?46, ?47, ?48, ?49, ?50,
            ?51, ?52, ?53, ?54, ?55, ?56, ?57, ?58, ?59, ?60,
            ?61, ?62
        )",
        params![
            sample.ts_ms,
            sample.boot_id,
            unit,
            sample.main_pid,
            sample.pid_count,
            sample.cgroup_memory_current,
            sample.cgroup_memory_peak,
            sample.cgroup_swap_current,
            sample.cgroup_swap_peak,
            sample.cgroup_anon,
            sample.cgroup_file,
            sample.cgroup_shmem,
            sample.cgroup_kernel,
            sample.cgroup_slab,
            sample.cgroup_pagetables,
            sample.event_high,
            sample.event_max,
            sample.event_oom,
            sample.event_oom_kill,
            sample.process_rss,
            sample.process_swap,
            sample.process_virtual,
            sample.process_threads,
            sample.process_cpu_ticks,
            sample.process_read_bytes,
            sample.process_write_bytes,
            sample.host_memory_total,
            sample.host_memory_available,
            sample.host_cached,
            sample.host_swap_total,
            sample.host_swap_free,
            sample.vm_pswpin,
            sample.vm_pswpout,
            sample.vm_pgmajfault,
            sample.load1,
            sample.load5,
            sample.load15,
            sample.memory_psi_some_avg10,
            sample.memory_psi_full_avg10,
            sample.cpu_psi_some_avg10,
            sample.io_psi_some_avg10,
            sample.io_psi_full_avg10,
            sample.cpu_usage_usec,
            sample.cpu_user_usec,
            sample.cpu_system_usec,
            sample.cpu_nr_throttled,
            sample.cpu_throttled_usec,
            sample.cgroup_io_read_bytes,
            sample.cgroup_io_write_bytes,
            sample.zram_original_bytes,
            sample.zram_compressed_bytes,
            sample.zram_memory_used_bytes,
            sample.zram_memory_limit_bytes,
            sample.zram_memory_peak_bytes,
            sample.storage_total_bytes,
            sample.storage_free_bytes,
            sample.storage_available_bytes,
            sample.storage_total_inodes,
            sample.storage_free_inodes,
            sample.disk_read_bytes,
            sample.disk_write_bytes,
            sample.disk_io_millis,
        ],
    )?;
    Ok(())
}

fn read_key_values(path: &Path, multiplier: i64) -> Result<HashMap<String, i64>> {
    let mut values = HashMap::new();
    for line in fs::read_to_string(path)?.lines() {
        let mut fields = line.split_whitespace();
        if let (Some(key), Some(raw)) = (fields.next(), fields.next()) {
            if let Ok(number) = raw.trim_end_matches(':').parse::<i64>() {
                values.insert(key.trim_end_matches(':').to_owned(), number * multiplier);
            }
        }
    }
    Ok(values)
}

fn read_process_aggregate(cgroup_path: &Path) -> Result<ProcAggregate> {
    let mut aggregate = ProcAggregate::default();
    let pids = fs::read_to_string(cgroup_path.join("cgroup.procs"))?;
    let mut largest_rss = -1_i64;
    for raw_pid in pids.lines() {
        let Ok(pid) = raw_pid.trim().parse::<i64>() else {
            continue;
        };
        let proc_root = PathBuf::from(format!("/proc/{pid}"));
        let Ok(status) = read_key_values(&proc_root.join("status"), 1024) else {
            continue;
        };
        let rss = value(&status, "VmRSS");
        aggregate.pid_count += 1;
        aggregate.rss_bytes += rss;
        aggregate.swap_bytes += value(&status, "VmSwap");
        aggregate.virtual_bytes += value(&status, "VmSize");
        aggregate.threads += value(&status, "Threads");

        if rss > largest_rss {
            largest_rss = rss;
            aggregate.main_pid = pid;
        }

        if let Ok(stat) = fs::read_to_string(proc_root.join("stat")) {
            if let Some(close) = stat.rfind(") ") {
                let fields: Vec<&str> = stat[(close + 2)..].split_whitespace().collect();
                aggregate.cpu_ticks += fields
                    .get(11)
                    .and_then(|value| value.parse::<i64>().ok())
                    .unwrap_or(0);
                aggregate.cpu_ticks += fields
                    .get(12)
                    .and_then(|value| value.parse::<i64>().ok())
                    .unwrap_or(0);
            }
        }

        if let Ok(io) = read_key_values(&proc_root.join("io"), 1) {
            aggregate.read_bytes += value(&io, "read_bytes");
            aggregate.write_bytes += value(&io, "write_bytes");
        }
    }
    Ok(aggregate)
}

fn read_psi(path: &Path) -> Psi {
    let Ok(contents) = fs::read_to_string(path) else {
        return Psi::default();
    };
    let mut psi = Psi::default();
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let kind = fields.next().unwrap_or_default();
        for field in fields {
            if let Some(raw) = field.strip_prefix("avg10=") {
                let value = raw.parse::<f64>().unwrap_or(0.0);
                match kind {
                    "some" => psi.some_avg10 = value,
                    "full" => psi.full_avg10 = value,
                    _ => {}
                }
            }
        }
    }
    psi
}

fn read_cgroup_io(path: &Path) -> (i64, i64) {
    let Ok(contents) = fs::read_to_string(path) else {
        return (0, 0);
    };
    let mut read_bytes = 0;
    let mut write_bytes = 0;
    for field in contents.split_whitespace() {
        if let Some(raw) = field.strip_prefix("rbytes=") {
            read_bytes += raw.parse::<i64>().unwrap_or(0);
        } else if let Some(raw) = field.strip_prefix("wbytes=") {
            write_bytes += raw.parse::<i64>().unwrap_or(0);
        }
    }
    (read_bytes, write_bytes)
}

fn read_zram_mm_stat(path: &Path) -> [i64; 5] {
    let Ok(contents) = fs::read_to_string(path) else {
        return [0; 5];
    };
    let values: Vec<i64> = contents
        .split_whitespace()
        .filter_map(|value| value.parse::<i64>().ok())
        .collect();
    [
        *values.first().unwrap_or(&0),
        *values.get(1).unwrap_or(&0),
        *values.get(2).unwrap_or(&0),
        *values.get(3).unwrap_or(&0),
        *values.get(4).unwrap_or(&0),
    ]
}

fn read_storage(path: &Path) -> Result<Storage> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let result = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stats = unsafe { stats.assume_init() };
    let block_size = stats.f_frsize as i64;
    Ok(Storage {
        total_bytes: (stats.f_blocks as i64).saturating_mul(block_size),
        free_bytes: (stats.f_bfree as i64).saturating_mul(block_size),
        available_bytes: (stats.f_bavail as i64).saturating_mul(block_size),
        total_inodes: stats.f_files as i64,
        free_inodes: stats.f_favail as i64,
    })
}

fn read_diskstats(path: &Path) -> (i64, i64, i64) {
    let Ok(contents) = fs::read_to_string(path) else {
        return (0, 0, 0);
    };
    let mut read_bytes = 0_i64;
    let mut write_bytes = 0_i64;
    let mut io_millis = 0_i64;
    for line in contents.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 14 {
            continue;
        }
        let device = fields[2];
        if device.starts_with("loop")
            || device.starts_with("ram")
            || device.starts_with("zram")
            || !Path::new("/sys/block").join(device).exists()
        {
            continue;
        }
        read_bytes += fields[5].parse::<i64>().unwrap_or(0).saturating_mul(512);
        write_bytes += fields[9].parse::<i64>().unwrap_or(0).saturating_mul(512);
        io_millis += fields[12].parse::<i64>().unwrap_or(0);
    }
    (read_bytes, write_bytes, io_millis)
}

fn read_loadavg() -> Result<(f64, f64, f64)> {
    let contents = fs::read_to_string("/proc/loadavg")?;
    let mut fields = contents.split_whitespace();
    Ok((
        fields.next().unwrap_or("0").parse().unwrap_or(0.0),
        fields.next().unwrap_or("0").parse().unwrap_or(0.0),
        fields.next().unwrap_or("0").parse().unwrap_or(0.0),
    ))
}

fn journal_supervisor(config: Config) {
    loop {
        if let Err(error) = follow_journal(&config) {
            eprintln!("journal follower stopped: {error}; retrying in 5s");
        }
        thread::sleep(Duration::from_secs(5));
    }
}

fn follow_journal(config: &Config) -> Result<()> {
    let conn = open_database(&config.db_path)?;
    let cursor: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key = 'journal_cursor'",
            [],
            |row| row.get(0),
        )
        .optional()?;

    let mut command = Command::new("/usr/bin/journalctl");
    command
        .arg("--unit")
        .arg(&config.unit)
        .arg("--follow")
        .arg("--output=json")
        .arg("--no-pager");
    if let Some(cursor) = cursor {
        command.arg(format!("--after-cursor={cursor}"));
    } else {
        command.arg("--since").arg(&config.journal_since);
    }
    let mut child = command.stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?;
    let stdout = child.stdout.take().ok_or("journalctl stdout unavailable")?;
    let reader = BufReader::new(stdout);
    let mut lines_since_cursor_write = 0_u64;

    for line in reader.lines() {
        let line = line?;
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some(cursor) = json_string(&value, "__CURSOR") else {
            continue;
        };
        let message = json_string(&value, "MESSAGE").unwrap_or_default();
        let category = classify_message(&message);
        let ts_ms = json_string(&value, "__REALTIME_TIMESTAMP")
            .and_then(|value| value.parse::<i64>().ok())
            .map(|value| value / 1000)
            .unwrap_or_else(now_ms);
        let priority = json_string(&value, "PRIORITY").and_then(|value| value.parse::<i64>().ok());
        lines_since_cursor_write += 1;

        if let Some(category) = category {
            let tx = conn.unchecked_transaction()?;
            tx.execute(
                "INSERT OR IGNORE INTO journal_events(
                    ts_ms, cursor, unit, priority, category, request_id, message
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    ts_ms,
                    cursor,
                    config.unit,
                    priority,
                    category,
                    extract_request_id(&message),
                    truncate_utf8(&message, 4096),
                ],
            )?;
            set_metadata(&tx, "journal_cursor", &cursor)?;
            tx.commit()?;
            lines_since_cursor_write = 0;
        } else if lines_since_cursor_write >= 100 {
            set_metadata(&conn, "journal_cursor", &cursor)?;
            lines_since_cursor_write = 0;
        }
    }

    let status = child.wait()?;
    Err(format!("journalctl exited with {status}").into())
}

fn json_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(|value| match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    })
}

fn classify_message(message: &str) -> Option<&'static str> {
    let lower = message.to_ascii_lowercase();
    if lower.contains("out of memory")
        || lower.contains("oom")
        || lower.contains("panic")
        || lower.contains(" error")
        || lower.starts_with("error")
        || lower.contains("failed")
    {
        Some("error")
    } else if lower.contains(" warn") || lower.starts_with("warn") {
        Some("warning")
    } else if lower.contains("deposit_batch")
        || lower.contains("deposit batch")
        || lower.contains("prove_deposit")
    {
        Some("deposit_batch")
    } else if lower.contains("withdrawal")
        || lower.contains("withdraw batch")
        || lower.contains("prove_withdraw")
    {
        Some("withdrawal")
    } else if lower.contains("bridge aggregation")
        || lower.contains("bridge wrap")
        || lower.contains("prove_bridge")
    {
        Some("bridge_aggregation")
    } else if lower.contains("groth16") {
        Some("groth16")
    } else if lower.contains("prove_contract")
        || lower.contains("contract proof")
        || lower.contains("contract_id=")
    {
        Some("contract_proof")
    } else if lower.contains("request_id=") || lower.contains("received request") {
        Some("rpc_request")
    } else {
        None
    }
}

fn extract_request_id(message: &str) -> Option<String> {
    let start = message.find("request_id")?;
    let remainder = &message[(start + "request_id".len())..];
    let value = remainder
        .trim_start_matches(|character: char| {
            character.is_whitespace() || matches!(character, '=' | ':' | '"' | '\'')
        })
        .split(|character: char| {
            character.is_whitespace() || matches!(character, ',' | '}' | ']' | '"' | '\'')
        })
        .next()
        .unwrap_or_default();
    (!value.is_empty()).then(|| value.to_owned())
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn evaluate_alerts(
    conn: &Connection,
    config: &Config,
    sample: &Sample,
    previous: Option<&Sample>,
    streaks: &mut HashMap<String, u32>,
) -> Result<()> {
    let swap_out_delta = previous
        .map(|previous| (sample.vm_pswpout - previous.vm_pswpout).max(0))
        .unwrap_or(0);
    let swap_out_bytes_per_minute = swap_out_delta
        .saturating_mul(4096)
        .saturating_mul(60)
        / config.interval.as_secs().max(1) as i64;
    let disk_available_percent = percent(
        sample.storage_available_bytes,
        sample.storage_total_bytes,
    );
    let inode_free_percent = percent(sample.storage_free_inodes, sample.storage_total_inodes);
    let zram_percent = percent(
        sample.host_swap_total - sample.host_swap_free,
        sample.host_swap_total,
    );
    let oom_kill_delta = previous
        .map(|previous| (sample.event_oom_kill - previous.event_oom_kill).max(0))
        .unwrap_or(0);

    let rules = vec![
        AlertRule {
            key: "target_service_down",
            severity: "critical",
            condition: sample.pid_count == 0,
            immediate: false,
            message: format!(
                "{} has no processes in {}",
                config.unit,
                config.cgroup_path.display()
            ),
        },
        AlertRule {
            key: "cgroup_oom_kill",
            severity: "critical",
            condition: oom_kill_delta > 0,
            immediate: true,
            message: format!(
                "{} cgroup OOM kill counter increased by {} (total={})",
                config.unit, oom_kill_delta, sample.event_oom_kill
            ),
        },
        AlertRule {
            key: "memory_near_capacity",
            severity: "warning",
            condition: sample.cgroup_memory_current >= config.alert_memory_bytes,
            immediate: false,
            message: format!(
                "{} cgroup memory {} is above threshold {}",
                config.unit,
                human_bytes(sample.cgroup_memory_current),
                human_bytes(config.alert_memory_bytes)
            ),
        },
        AlertRule {
            key: "host_available_memory_low",
            severity: "critical",
            condition: sample.host_memory_available <= config.alert_available_bytes,
            immediate: false,
            message: format!(
                "host available memory {} is below threshold {}",
                human_bytes(sample.host_memory_available),
                human_bytes(config.alert_available_bytes)
            ),
        },
        AlertRule {
            key: "active_swap_out",
            severity: "warning",
            condition: swap_out_bytes_per_minute >= config.alert_swap_out_bytes_per_minute,
            immediate: false,
            message: format!(
                "swap-out rate {}/min is above threshold {}/min",
                human_bytes(swap_out_bytes_per_minute),
                human_bytes(config.alert_swap_out_bytes_per_minute)
            ),
        },
        AlertRule {
            key: "memory_pressure",
            severity: "warning",
            condition: sample.memory_psi_some_avg10 >= config.alert_memory_psi_avg10,
            immediate: false,
            message: format!(
                "memory PSI some avg10 {:.2} is above threshold {:.2}",
                sample.memory_psi_some_avg10, config.alert_memory_psi_avg10
            ),
        },
        AlertRule {
            key: "storage_available_low",
            severity: "critical",
            condition: sample.storage_available_bytes <= config.alert_disk_available_bytes
                || (disk_available_percent <= config.alert_disk_available_percent
                    && sample.storage_available_bytes
                        <= config.alert_disk_available_bytes.saturating_mul(5)),
            immediate: false,
            message: format!(
                "storage {} available={} ({:.1}%), thresholds={} or {:.1}%",
                config.storage_path.display(),
                human_bytes(sample.storage_available_bytes),
                disk_available_percent,
                human_bytes(config.alert_disk_available_bytes),
                config.alert_disk_available_percent
            ),
        },
        AlertRule {
            key: "storage_inodes_low",
            severity: "warning",
            condition: sample.storage_total_inodes > 0
                && inode_free_percent <= config.alert_inode_free_percent,
            immediate: false,
            message: format!(
                "storage {} free inodes={:.1}% threshold={:.1}%",
                config.storage_path.display(),
                inode_free_percent,
                config.alert_inode_free_percent
            ),
        },
        AlertRule {
            key: "zram_usage_high",
            severity: "warning",
            condition: sample.host_swap_total > 0 && zram_percent >= config.alert_zram_percent,
            immediate: false,
            message: format!(
                "zram logical swap use={:.1}% ({}) threshold={:.1}%",
                zram_percent,
                human_bytes(sample.host_swap_total - sample.host_swap_free),
                config.alert_zram_percent
            ),
        },
    ];

    for rule in rules {
        let count = streaks.entry(rule.key.to_owned()).or_default();
        if rule.condition {
            *count = count.saturating_add(1);
        } else {
            *count = 0;
        }
        let currently_active = alert_is_active(conn, rule.key)?;
        let should_be_active = rule.condition
            && (rule.immediate
                || currently_active
                || *count >= config.alert_consecutive_samples);
        update_alert(conn, config, &rule, should_be_active)?;
    }
    Ok(())
}

fn alert_is_active(conn: &Connection, key: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT active FROM alert_state WHERE key = ?1",
            params![key],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0)
        != 0)
}

fn update_alert(
    conn: &Connection,
    config: &Config,
    rule: &AlertRule,
    should_be_active: bool,
) -> Result<()> {
    let now = now_ms();
    let state: Option<(bool, i64, i64, i64)> = conn
        .query_row(
            "SELECT active, first_ts_ms, last_notify_ts_ms, occurrences
             FROM alert_state WHERE key = ?1",
            params![rule.key],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? != 0,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                ))
            },
        )
        .optional()?;
    let prior_occurrences = state.map(|state| state.3).unwrap_or(0);

    match (state, should_be_active) {
        (Some((true, first_ts, last_notify, occurrences)), true) => {
            let notify_again =
                now - last_notify >= config.alert_cooldown.as_millis() as i64;
            conn.execute(
                "UPDATE alert_state SET
                    last_seen_ts_ms = ?2,
                    last_notify_ts_ms = CASE WHEN ?3 THEN ?2 ELSE last_notify_ts_ms END,
                    occurrences = ?4,
                    severity = ?5,
                    message = ?6
                 WHERE key = ?1",
                params![
                    rule.key,
                    now,
                    notify_again,
                    occurrences + 1,
                    rule.severity,
                    rule.message,
                ],
            )?;
            if notify_again {
                record_alert_history(conn, now, rule, "repeat")?;
                emit_alert(config, rule, "trigger", first_ts);
            }
        }
        (Some((false, _, _, _)), true) | (None, true) => {
            conn.execute(
                "INSERT INTO alert_state(
                    key, active, first_ts_ms, last_seen_ts_ms, last_notify_ts_ms,
                    occurrences, severity, message
                 ) VALUES (?1, 1, ?2, ?2, ?2, ?3, ?4, ?5)
                 ON CONFLICT(key) DO UPDATE SET
                    active = 1,
                    first_ts_ms = excluded.first_ts_ms,
                    last_seen_ts_ms = excluded.last_seen_ts_ms,
                    last_notify_ts_ms = excluded.last_notify_ts_ms,
                    occurrences = excluded.occurrences,
                    severity = excluded.severity,
                    message = excluded.message",
                params![
                    rule.key,
                    now,
                    prior_occurrences + 1,
                    rule.severity,
                    rule.message,
                ],
            )?;
            record_alert_history(conn, now, rule, "trigger")?;
            emit_alert(config, rule, "trigger", now);
        }
        (Some((true, first_ts, _, occurrences)), false) => {
            conn.execute(
                "UPDATE alert_state SET
                    active = 0, last_seen_ts_ms = ?2, occurrences = ?3
                 WHERE key = ?1",
                params![rule.key, now, occurrences],
            )?;
            let resolution = AlertRule {
                key: rule.key,
                severity: rule.severity,
                condition: false,
                immediate: rule.immediate,
                message: format!("condition cleared: {}", rule.key),
            };
            record_alert_history(conn, now, &resolution, "resolve")?;
            emit_alert(config, &resolution, "resolve", first_ts);
        }
        _ => {}
    }
    Ok(())
}

fn record_alert_history(
    conn: &Connection,
    ts_ms: i64,
    rule: &AlertRule,
    action: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO alert_history(ts_ms, key, action, severity, message)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![ts_ms, rule.key, action, rule.severity, rule.message],
    )?;
    Ok(())
}

fn emit_alert(config: &Config, rule: &AlertRule, action: &str, first_ts_ms: i64) {
    eprintln!(
        "PERFORMANCE_ALERT action={} severity={} key={} message={}",
        action, rule.severity, rule.key, rule.message
    );
    if let Some(webhook_url) = &config.slack_webhook_url {
        if let Err(error) = send_slack(config, webhook_url, rule, action, first_ts_ms) {
            eprintln!("Slack notification failed: {error}");
        }
    }
    if let Some(routing_key) = &config.pagerduty_routing_key {
        if let Err(error) = send_pagerduty(config, routing_key, rule, action, first_ts_ms) {
            eprintln!("PagerDuty notification failed: {error}");
        }
    }
}

fn send_slack(
    config: &Config,
    webhook_url: &str,
    rule: &AlertRule,
    action: &str,
    first_ts_ms: i64,
) -> Result<()> {
    let hostname =
        read_trimmed(Path::new("/etc/hostname")).unwrap_or_else(|| "unknown-host".to_owned());
    let resolved = action == "resolve";
    let state = if resolved { "RESOLVED" } else { "TRIGGERED" };
    let color = if resolved {
        "#2EB67D"
    } else if rule.severity == "critical" {
        "#E01E5A"
    } else {
        "#ECB22E"
    };
    let fallback = format!(
        "[{}] {} {} on {}: {}",
        state,
        rule.severity.to_ascii_uppercase(),
        rule.key,
        hostname,
        rule.message
    );
    let body = json!({
        "text": fallback,
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": truncate_utf8(
                            &format!("{}: {}", state, rule.key),
                            150
                        )
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": format!("*Severity*\n{}", rule.severity)
                        },
                        {
                            "type": "mrkdwn",
                            "text": format!("*Host*\n{}", hostname)
                        },
                        {
                            "type": "mrkdwn",
                            "text": format!("*Service*\n{}", config.unit)
                        },
                        {
                            "type": "mrkdwn",
                            "text": format!(
                                "*First observed*\n<!date^{}^{{date_num}} {{time_secs}}|{}>",
                                first_ts_ms / 1000,
                                first_ts_ms / 1000
                            )
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": format!("*Details*\n{}", rule.message)
                    }
                }
            ]
        }]
    });
    post_secret_webhook(webhook_url, &body)
}

fn send_pagerduty(
    config: &Config,
    routing_key: &str,
    rule: &AlertRule,
    action: &str,
    first_ts_ms: i64,
) -> Result<()> {
    let hostname = read_trimmed(Path::new("/etc/hostname"))
        .unwrap_or_else(|| "unknown-host".to_owned());
    let dedup_key = format!("parth-perf:{}:{}", hostname, rule.key);
    let body = if action == "resolve" {
        json!({
            "routing_key": routing_key,
            "event_action": "resolve",
            "dedup_key": dedup_key
        })
    } else {
        json!({
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": format!("{}: {}", config.unit, rule.message),
                "source": hostname,
                "severity": rule.severity,
                "component": config.unit,
                "group": "parth-performance",
                "class": rule.key,
                "custom_details": {
                    "first_observed_ts_ms": first_ts_ms,
                    "database": config.db_path.display().to_string()
                }
            }
        })
    };
    post_json("https://events.pagerduty.com/v2/enqueue", &body)
}

fn post_json(url: &str, body: &Value) -> Result<()> {
    let mut child = Command::new("/usr/bin/curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "10",
            "--request",
            "POST",
            "--header",
            "content-type: application/json",
            "--data-binary",
            "@-",
            url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("curl stdin unavailable")?
        .write_all(body.to_string().as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        return Err(format!("HTTP notification curl exited with {status}").into());
    }
    Ok(())
}

fn post_secret_webhook(url: &str, body: &Value) -> Result<()> {
    let mut child = Command::new("/usr/bin/curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "10",
            "--request",
            "POST",
            "--header",
            "content-type: application/json",
            "--data-binary",
            "@-",
            "--variable",
            "%PARTH_SECRET_WEBHOOK_URL",
            "--expand-url",
            "{{PARTH_SECRET_WEBHOOK_URL}}",
        ])
        .env("PARTH_SECRET_WEBHOOK_URL", url)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("curl stdin unavailable")?
        .write_all(body.to_string().as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        return Err(format!("webhook curl exited with {status}").into());
    }
    Ok(())
}

fn test_slack(config: &Config) -> Result<()> {
    let webhook_url = config
        .slack_webhook_url
        .as_deref()
        .ok_or("PARTH_PERF_SLACK_WEBHOOK_URL is not configured")?;
    let rule = AlertRule {
        key: "notification_test",
        severity: "warning",
        condition: true,
        immediate: true,
        message: "Parth performance monitor Slack delivery test".to_owned(),
    };
    send_slack(config, webhook_url, &rule, "trigger", now_ms())?;
    println!("Slack test notification delivered successfully.");
    Ok(())
}

fn percent(numerator: i64, denominator: i64) -> f64 {
    if denominator <= 0 {
        0.0
    } else {
        numerator.max(0) as f64 * 100.0 / denominator as f64
    }
}

fn prune(conn: &mut Connection, retention: Duration) -> Result<()> {
    let cutoff = now_ms() - retention.as_millis() as i64;
    let tx = conn.transaction()?;
    let samples = tx.execute("DELETE FROM samples WHERE ts_ms < ?1", params![cutoff])?;
    let events = tx.execute(
        "DELETE FROM journal_events WHERE ts_ms < ?1",
        params![cutoff],
    )?;
    let alerts = tx.execute(
        "DELETE FROM alert_history WHERE ts_ms < ?1",
        params![cutoff],
    )?;
    tx.commit()?;
    conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);")?;
    eprintln!(
        "retention maintenance removed samples={samples} events={events} alerts={alerts}"
    );
    Ok(())
}

fn report(config: &Config, duration: Duration) -> Result<()> {
    let conn = open_database_read_only(&config.db_path)?;
    let cutoff = now_ms() - duration.as_millis() as i64;
    let summary: Option<ReportSummary> = conn
        .query_row(
            "SELECT
                COUNT(*), MIN(ts_ms), MAX(ts_ms),
                MAX(cgroup_memory_current), MAX(cgroup_swap_current),
                MIN(host_memory_available),
                MAX(memory_psi_some_avg10), MAX(memory_psi_full_avg10),
                MAX(vm_pswpin) - MIN(vm_pswpin),
                MAX(vm_pswpout) - MIN(vm_pswpout),
                MAX(event_oom), MAX(event_oom_kill),
                MIN(storage_available_bytes),
                MIN(CASE WHEN storage_total_bytes > 0
                    THEN storage_available_bytes * 100.0 / storage_total_bytes
                    ELSE 0 END),
                MAX(disk_read_bytes) - MIN(disk_read_bytes),
                MAX(disk_write_bytes) - MIN(disk_write_bytes),
                MAX(disk_io_millis) - MIN(disk_io_millis)
             FROM samples WHERE ts_ms >= ?1",
            params![cutoff],
            |row| {
                Ok(ReportSummary {
                    sample_count: row.get(0)?,
                    first_ts_ms: row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                    last_ts_ms: row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                    peak_memory_bytes: row.get::<_, Option<i64>>(3)?.unwrap_or(0),
                    peak_swap_bytes: row.get::<_, Option<i64>>(4)?.unwrap_or(0),
                    minimum_available_memory_bytes: row
                        .get::<_, Option<i64>>(5)?
                        .unwrap_or(0),
                    peak_memory_psi_some: row.get::<_, Option<f64>>(6)?.unwrap_or(0.0),
                    peak_memory_psi_full: row.get::<_, Option<f64>>(7)?.unwrap_or(0.0),
                    swap_in_pages: row.get::<_, Option<i64>>(8)?.unwrap_or(0),
                    swap_out_pages: row.get::<_, Option<i64>>(9)?.unwrap_or(0),
                    oom_count: row.get::<_, Option<i64>>(10)?.unwrap_or(0),
                    oom_kill_count: row.get::<_, Option<i64>>(11)?.unwrap_or(0),
                    minimum_storage_available_bytes: row
                        .get::<_, Option<i64>>(12)?
                        .unwrap_or(0),
                    minimum_storage_available_percent: row
                        .get::<_, Option<f64>>(13)?
                        .unwrap_or(0.0),
                    disk_read_bytes: row.get::<_, Option<i64>>(14)?.unwrap_or(0),
                    disk_write_bytes: row.get::<_, Option<i64>>(15)?.unwrap_or(0),
                    disk_io_millis: row.get::<_, Option<i64>>(16)?.unwrap_or(0),
                })
            },
        )
        .optional()?;

    let Some(summary) = summary.filter(|summary| summary.sample_count > 0) else {
        println!("No samples found in the requested interval.");
        return Ok(());
    };

    println!("Performance summary for {}:", config.unit);
    println!(
        "  samples={} range={} .. {}",
        summary.sample_count,
        format_ts(&conn, summary.first_ts_ms)?,
        format_ts(&conn, summary.last_ts_ms)?
    );
    println!(
        "  peak cgroup memory={}  peak swap={}  minimum host available={}",
        human_bytes(summary.peak_memory_bytes),
        human_bytes(summary.peak_swap_bytes),
        human_bytes(summary.minimum_available_memory_bytes)
    );
    println!(
        "  memory PSI avg10: some={:.2} full={:.2}",
        summary.peak_memory_psi_some, summary.peak_memory_psi_full
    );
    println!(
        "  swap pages: in_delta={} ({}) out_delta={} ({})",
        summary.swap_in_pages,
        human_bytes(summary.swap_in_pages * 4096),
        summary.swap_out_pages,
        human_bytes(summary.swap_out_pages * 4096)
    );
    println!(
        "  cgroup OOM counters: oom={} oom_kill={}",
        summary.oom_count, summary.oom_kill_count
    );
    println!(
        "  storage minimum available={} ({:.1}%) host disk read={} write={} io_time={}ms",
        human_bytes(summary.minimum_storage_available_bytes),
        summary.minimum_storage_available_percent,
        human_bytes(summary.disk_read_bytes),
        human_bytes(summary.disk_write_bytes),
        summary.disk_io_millis
    );

    println!("\nActive alerts:");
    let mut active_statement = conn.prepare(
        "SELECT key, severity, first_ts_ms, last_seen_ts_ms, occurrences, message
         FROM alert_state WHERE active = 1 ORDER BY severity, first_ts_ms",
    )?;
    let mut active_count = 0;
    for row in active_statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, String>(5)?,
        ))
    })? {
        let (key, severity, first, last, occurrences, message) = row?;
        active_count += 1;
        println!(
            "  {} {} first={} last={} occurrences={} {}",
            severity,
            key,
            format_ts(&conn, first)?,
            format_ts(&conn, last)?,
            occurrences,
            message
        );
    }
    if active_count == 0 {
        println!("  none");
    }

    println!("\nTop memory samples and nearby proof events:");
    let mut statement = conn.prepare(
        "SELECT ts_ms, cgroup_memory_current, cgroup_swap_current,
                process_rss, host_memory_available,
                memory_psi_some_avg10, vm_pswpin, vm_pswpout
         FROM samples WHERE ts_ms >= ?1
         ORDER BY cgroup_memory_current DESC LIMIT 8",
    )?;
    let rows = statement.query_map(params![cutoff], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, f64>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, i64>(7)?,
        ))
    })?;
    for row in rows {
        let row = row?;
        let nearby: String = conn
            .query_row(
                "SELECT COALESCE(group_concat(category, ','), '')
                 FROM (
                    SELECT DISTINCT category FROM journal_events
                    WHERE ts_ms BETWEEN ?1 AND ?2
                    ORDER BY category
                 )",
                params![row.0 - 30_000, row.0 + 30_000],
                |result| result.get(0),
            )
            .unwrap_or_default();
        println!(
            "  {} mem={} swap={} rss={} avail={} psi={:.2} swap_io={}/{} events=[{}]",
            format_ts(&conn, row.0)?,
            human_bytes(row.1),
            human_bytes(row.2),
            human_bytes(row.3),
            human_bytes(row.4),
            row.5,
            row.6,
            row.7,
            nearby
        );
    }

    println!("\nCaptured event counts:");
    let mut statement = conn.prepare(
        "SELECT category, COUNT(*) FROM journal_events
         WHERE ts_ms >= ?1 GROUP BY category ORDER BY COUNT(*) DESC",
    )?;
    for row in statement.query_map(params![cutoff], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })? {
        let (category, count) = row?;
        println!("  {category}: {count}");
    }
    Ok(())
}

fn print_events(config: &Config, duration: Duration) -> Result<()> {
    let conn = open_database_read_only(&config.db_path)?;
    let cutoff = now_ms() - duration.as_millis() as i64;
    let mut statement = conn.prepare(
        "SELECT ts_ms, priority, category, request_id, message
         FROM journal_events WHERE ts_ms >= ?1 ORDER BY ts_ms",
    )?;
    for row in statement.query_map(params![cutoff], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Option<i64>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, String>(4)?,
        ))
    })? {
        let (ts, priority, category, request_id, message) = row?;
        println!(
            "{} priority={} category={} request_id={} {}",
            format_ts(&conn, ts)?,
            priority.map_or_else(|| "-".to_owned(), |value| value.to_string()),
            category,
            request_id.unwrap_or_else(|| "-".to_owned()),
            message
        );
    }
    Ok(())
}

fn print_alerts(config: &Config, duration: Duration) -> Result<()> {
    let conn = open_database_read_only(&config.db_path)?;
    let cutoff = now_ms() - duration.as_millis() as i64;
    let mut statement = conn.prepare(
        "SELECT ts_ms, action, severity, key, message
         FROM alert_history WHERE ts_ms >= ?1 ORDER BY ts_ms",
    )?;
    for row in statement.query_map(params![cutoff], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })? {
        let (ts, action, severity, key, message) = row?;
        println!(
            "{} action={} severity={} key={} {}",
            format_ts(&conn, ts)?,
            action,
            severity,
            key,
            message
        );
    }
    Ok(())
}

fn format_ts(conn: &Connection, ts_ms: i64) -> Result<String> {
    Ok(conn.query_row(
        "SELECT strftime('%Y-%m-%d %H:%M:%f', ?1 / 1000.0, 'unixepoch', 'localtime')",
        params![ts_ms],
        |row| row.get(0),
    )?)
}

fn human_bytes(bytes: i64) -> String {
    let mut value = bytes.max(0) as f64;
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut unit = 0;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", units[unit])
}

fn parse_duration(raw: &str) -> Result<Duration> {
    let split = raw
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(raw.len());
    let amount = raw[..split].parse::<u64>()?;
    let unit = &raw[split..];
    let multiplier = match unit {
        "s" | "" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(format!("unsupported duration: {raw}").into()),
    };
    Ok(Duration::from_secs(amount * multiplier))
}

fn env_u64(key: &str, default: u64) -> Result<u64> {
    match env::var(key) {
        Ok(value) => Ok(value.parse::<u64>()?),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

fn env_f64(key: &str, default: f64) -> Result<f64> {
    match env::var(key) {
        Ok(value) => Ok(value.parse::<f64>()?),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

fn env_gib(key: &str, default: f64) -> Result<i64> {
    Ok((env_f64(key, default)? * 1024.0 * 1024.0 * 1024.0) as i64)
}

fn env_mib(key: &str, default: f64) -> Result<i64> {
    Ok((env_f64(key, default)? * 1024.0 * 1024.0) as i64)
}

fn env_bool(key: &str, default: bool) -> bool {
    env::var(key)
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

fn read_i64(path: &Path) -> i64 {
    read_trimmed(path)
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0)
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|value| value.trim().to_owned())
}

fn value(values: &HashMap<String, i64>, key: &str) -> i64 {
    values.get(key).copied().unwrap_or(0)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_relevant_events() {
        assert_eq!(
            classify_message("starting bridge aggregation for checkpoints"),
            Some("bridge_aggregation")
        );
        assert_eq!(
            classify_message("deposit_batch pre-wrap complete"),
            Some("deposit_batch")
        );
        assert_eq!(
            classify_message("prove_withdrawal_batch_claim_groth16 complete"),
            Some("withdrawal")
        );
        assert_eq!(classify_message("ordinary startup detail"), None);
    }

    #[test]
    fn extracts_request_identifiers() {
        assert_eq!(
            extract_request_id("method=prove request_id=abc-123 elapsed=5"),
            Some("abc-123".to_owned())
        );
        assert_eq!(
            extract_request_id(r#"{"request_id":"req-9","method":"prove"}"#),
            Some("req-9".to_owned())
        );
    }

    #[test]
    fn parses_operator_durations() {
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert!(parse_duration("1w").is_err());
    }
}
