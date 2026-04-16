//! Process memory sampling and histogram helpers.

use anyhow::{Context, Result};
use hdrhistogram::Histogram;

/// Clock ticks per second for `/proc/*/stat` utime/stime fields (Linux).
pub fn clk_tck() -> i64 {
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 {
        v
    } else {
        100
    }
}

/// Read process user/system CPU time in jiffies from `/proc/{pid}/stat`.
pub fn read_process_cpu_jiffies(pid: u32) -> Result<(u64, u64)> {
    let path = format!("/proc/{pid}/stat");
    let s = std::fs::read_to_string(&path).with_context(|| format!("read {path}"))?;
    let idx = s
        .rfind(')')
        .with_context(|| format!("bad proc stat: {path}"))?;
    let rest = s[idx + 2..].trim_start();
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() < 13 {
        anyhow::bail!("proc stat too short: {path}");
    }
    let utime: u64 = fields[11].parse().context("utime")?;
    let stime: u64 = fields[12].parse().context("stime")?;
    Ok((utime, stime))
}

pub fn logical_cpu_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Total CPU time in seconds (user+sys) between two jiffies samples.
pub fn cpu_seconds_from_jiffies(before: (u64, u64), after: (u64, u64)) -> f64 {
    let dt = after.0.saturating_sub(before.0) + after.1.saturating_sub(before.1);
    dt as f64 / clk_tck() as f64
}

/// Average CPU usage as a fraction of the whole machine (0..=1), assuming homogeneous cores.
pub fn avg_cpu_fraction_of_machine(cpu_seconds: f64, wall_seconds: f64) -> f64 {
    if wall_seconds <= 0.0 {
        return 0.0;
    }
    let n = logical_cpu_count().max(1) as f64;
    (cpu_seconds / wall_seconds) / n
}

/// RSS from `/proc/{pid}/status` (Linux).
#[derive(Debug, Clone, Copy)]
pub struct MemoryStats {
    pub rss_kb: u64,
}

/// Read VmRSS for a process (Linux only).
pub fn read_process_memory(pid: u32) -> Result<MemoryStats> {
    let path = format!("/proc/{pid}/status");
    let text = std::fs::read_to_string(&path).with_context(|| format!("read {path}"))?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 2 && parts[1] == "kB" {
                let kb: u64 = parts[0].parse().context("parse VmRSS kb")?;
                return Ok(MemoryStats { rss_kb: kb });
            }
        }
    }
    anyhow::bail!("VmRSS not found in {path}")
}

pub fn rss_to_mb(rss_kb: u64) -> f64 {
    rss_kb as f64 / 1024.0
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LatencySummary {
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub p999_us: u64,
    pub max_us: u64,
}

pub fn summarize_histogram(h: &Histogram<u64>) -> LatencySummary {
    LatencySummary {
        p50_us: h.value_at_quantile(0.50),
        p95_us: h.value_at_quantile(0.95),
        p99_us: h.value_at_quantile(0.99),
        p999_us: h.value_at_quantile(0.999),
        max_us: h.max(),
    }
}

/// Simple jitter proxy: P95 minus P50 (microseconds).
pub fn jitter_approx_us(h: &Histogram<u64>) -> u64 {
    h.value_at_quantile(0.95)
        .saturating_sub(h.value_at_quantile(0.50))
}
