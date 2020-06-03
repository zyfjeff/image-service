// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Rafs fop stats accounting and exporting.

use std::collections::HashMap;
use std::io::Error;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

pub type Inode = u64;

#[derive(PartialEq, Copy)]
pub enum StatsFop {
    Stat,
    Readlink,
    Open,
    Release,
    Read,
    Statfs,
    Getxatr,
    Opendir,
    Fstat,
    Lookup,
    Readdir,
    Max,
}

impl Clone for StatsFop {
    fn clone(&self) -> Self {
        *self
    }
}

type FilesStatsCounters = RwLock<Vec<Arc<Option<InodeIOStats>>>>;

/// Block size separated counters.
/// 1K; 4K; 16K; 64K, 128K.
const BLOCK_READ_COUNT_MAX: usize = 5;

/// <=200us, <=500us, <=1ms, <=20ms, <=50ms, <=100ms, <=500ms, >500ms
const READ_LATENCY_RANGE_MAX: usize = 8;

lazy_static! {
    pub static ref IOS_SET: RwLock<HashMap<String, Arc<GlobalIOStats>>> = Default::default();
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct GlobalIOStats {
    // Whether to enable each file accounting switch.
    // As fop accounting might consume much memory space, it is disabled by default.
    // But global fop accounting is always working within each Rafs.
    files_account_enabled: AtomicBool,
    // Given the fact that we don't have to measure latency all the time,
    // use this to turn it off.
    measure_latency: AtomicBool,
    id: String,
    // Total bytes read against the filesystem.
    data_read: AtomicUsize,
    // Cumulative bytes for different block size.
    block_count_read: [AtomicUsize; BLOCK_READ_COUNT_MAX],
    // Counters for successful various file operations.
    fop_hits: [AtomicUsize; StatsFop::Max as usize],
    // Counters for failed file operations.
    fop_errors: [AtomicUsize; StatsFop::Max as usize],
    // Cumulative latency's life cycle is equivalent to Rafs, unlike incremental
    // latency which will be cleared each time dumped. Unit as micro-seconds.
    //   * @avg means fop average latency from mount, io_stats calculates the up-to-date average latency.
    //   * @total means io_stats simply adds every fop latency to the counter which is never cleared.
    //     It is useful for other tools to calculate their metrics report.
    fop_cumulative_latency_avg: [AtomicIsize; StatsFop::Max as usize],
    fop_cumulative_latency_total: [AtomicUsize; StatsFop::Max as usize],
    // Record how many times read latency drops to the ranges.
    // This helps us to understand the io service time stability.
    read_latency_dist: [AtomicIsize; READ_LATENCY_RANGE_MAX],
    // Total number of files that are currently open.
    nr_opens: AtomicUsize,
    nr_max_opens: AtomicUsize,
    // Record last rafs fop timestamp, this helps us with detecting backend hang or
    // inside dead-lock, etc.
    // TODO: To be implemented, should not be hard.
    last_fop_tp: AtomicUsize,

    // Rwlock closes the race that more than one threads are creating counters concurrently.
    #[serde(skip_serializing, skip_deserializing)]
    file_counters: RwLock<HashMap<Inode, Arc<InodeIOStats>>>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct InodeIOStats {
    // Total open number of this file.
    nr_open: AtomicUsize,
    nr_max_open: AtomicUsize,
    total_fops: AtomicUsize,
    data_read: AtomicUsize,
    // Cumulative bytes for different block size.
    block_count_read: [AtomicUsize; BLOCK_READ_COUNT_MAX],
    fop_hits: [AtomicUsize; StatsFop::Max as usize],
    fop_errors: [AtomicUsize; StatsFop::Max as usize],
}

pub trait InodeStatsCounter {
    fn stats_fop_inc(&self, fop: StatsFop);
    fn stats_fop_err_inc(&self, fop: StatsFop);
    fn stats_cumulative(&self, fop: StatsFop, value: usize);
}

impl InodeStatsCounter for InodeIOStats {
    fn stats_fop_inc(&self, fop: StatsFop) {
        self.fop_hits[fop as usize].fetch_add(1, Ordering::Relaxed);
        self.total_fops.fetch_add(1, Ordering::Relaxed);
        // TODO: It seems no Open fop arrives before any read.
        if fop == StatsFop::Open {
            self.nr_open.fetch_add(1, Ordering::Relaxed);
            // Below can't guarantee that load and store are atomic but it should be OK
            // for debug tracing info.
            if self.nr_open.load(Ordering::Relaxed) > self.nr_max_open.load(Ordering::Relaxed) {
                self.nr_max_open
                    .store(self.nr_open.load(Ordering::Relaxed), Ordering::Relaxed)
            }
        }
    }

    fn stats_fop_err_inc(&self, fop: StatsFop) {
        self.fop_errors[fop as usize].fetch_add(1, Ordering::Relaxed);
    }

    fn stats_cumulative(&self, fop: StatsFop, value: usize) {
        if fop == StatsFop::Read {
            self.data_read.fetch_add(value, Ordering::Relaxed);
            // We put block count into 5 catagories e.g. 1K; 4K; 16K; 64K, 128K.
            match value {
                // <=1K
                _ if value >> 10 == 0 => self.block_count_read[0].fetch_add(1, Ordering::Relaxed),
                // <=4K
                _ if value >> 12 == 0 => self.block_count_read[1].fetch_add(1, Ordering::Relaxed),
                // <=16K
                _ if value >> 14 == 0 => self.block_count_read[2].fetch_add(1, Ordering::Relaxed),
                // <=64K
                _ if value >> 16 == 0 => self.block_count_read[3].fetch_add(1, Ordering::Relaxed),
                // >64K
                _ => self.block_count_read[4].fetch_add(1, Ordering::Relaxed),
            };
        }
    }
}

pub fn ios_new(id: &str) -> Arc<GlobalIOStats> {
    let c = Arc::new(GlobalIOStats {
        id: id.to_string(),
        ..Default::default()
    });
    IOS_SET.write().unwrap().insert(id.to_string(), c.clone());
    c
}

/// <=200us, <=500us, <=1ms, <=20ms, <=50ms, <=100ms, <=500ms, >500ms
fn latency_range_index(elapsed: isize) -> usize {
    match elapsed {
        _ if elapsed <= 200 => 0,
        _ if elapsed <= 500 => 1,
        _ if elapsed <= 1000 => 2,
        _ if elapsed <= 20_000 => 3,
        _ if elapsed <= 50_000 => 4,
        _ if elapsed <= 100_000 => 5,
        _ if elapsed <= 500_000 => 6,
        _ => 7,
    }
}

impl GlobalIOStats {
    pub fn ios_init(&self) {
        self.files_account_enabled.store(false, Ordering::Relaxed);
        self.measure_latency.store(true, Ordering::Relaxed);
    }

    pub fn ios_files_enabled(&self) -> bool {
        self.files_account_enabled.load(Ordering::Relaxed)
    }

    pub fn ios_file_stats_update<T>(
        &self,
        ino: Inode,
        fop: StatsFop,
        bsize: usize,
        r: &Result<T, Error>,
    ) {
        self.ios_global_update(fop, bsize, &r);

        if self.ios_files_enabled() {
            let mut counters = self.file_counters.write().unwrap();
            if counters.get(&ino).is_none() {
                counters.insert(ino, Arc::new(InodeIOStats::default()));
                counters.get_mut(&ino).unwrap().stats_fop_inc(fop.clone());
                counters.get_mut(&ino).unwrap().stats_cumulative(fop, bsize);
            }
        }
    }

    pub fn ios_global_update<T>(&self, fop: StatsFop, value: usize, r: &Result<T, Error>) {
        self.last_fop_tp.store(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as usize,
            Ordering::Relaxed,
        );

        // We put block count into 5 catagories e.g. 1K; 4K; 16K; 64K, 128K.
        if fop == StatsFop::Read {
            match value {
                // <=1K
                _ if value >> 10 == 0 => self.block_count_read[0].fetch_add(1, Ordering::Relaxed),
                // <=4K
                _ if value >> 12 == 0 => self.block_count_read[1].fetch_add(1, Ordering::Relaxed),
                // <=16K
                _ if value >> 14 == 0 => self.block_count_read[2].fetch_add(1, Ordering::Relaxed),
                // <=64K
                _ if value >> 16 == 0 => self.block_count_read[3].fetch_add(1, Ordering::Relaxed),
                // >64K
                _ => self.block_count_read[4].fetch_add(1, Ordering::Relaxed),
            };
        }

        match r {
            Ok(_) => {
                self.fop_hits[fop as usize].fetch_add(1, Ordering::Relaxed);
                match fop {
                    StatsFop::Read => self.data_read.fetch_add(value, Ordering::Relaxed),
                    StatsFop::Open => self.nr_opens.fetch_add(1, Ordering::Relaxed),
                    StatsFop::Release => self.nr_opens.fetch_sub(1, Ordering::Relaxed),
                    _ => 0,
                }
            }
            Err(_) => self.fop_errors[fop as usize].fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Paired with `ios_latency_end` to record elapsed time for a certain type of fop.
    pub fn ios_latency_start(&self) -> Option<SystemTime> {
        if !self.measure_latency.load(Ordering::Relaxed) {
            return None;
        }

        Some(SystemTime::now())
    }

    pub fn ios_latency_end(&self, start: &Option<SystemTime>, fop: StatsFop) {
        if let Some(start) = start {
            if let Ok(d) = SystemTime::elapsed(start) {
                let elapsed = d.as_micros() as isize;
                self.read_latency_dist[latency_range_index(elapsed)]
                    .fetch_add(1, Ordering::Relaxed);
                self.fop_cumulative_latency_total[fop as usize]
                    .fetch_add(elapsed as usize, Ordering::Relaxed);
                let avg = self.fop_cumulative_latency_avg[fop as usize].load(Ordering::Relaxed);
                let fop_cnt = self.fop_hits[fop as usize].load(Ordering::Relaxed) as isize;

                // Zero fop count is hardly to meet, but still check here in
                // case callers misuses ios-latency
                if fop_cnt == 0 {
                    return;
                }
                let new_avg = || avg + (elapsed - avg) / fop_cnt;
                self.fop_cumulative_latency_avg[fop as usize].store(new_avg(), Ordering::Relaxed);
            }
        }
    }

    pub fn export_files_stats(&self) -> String {
        let mut rs = String::new();
        for c in (*self.file_counters.read().unwrap()).values() {
            // Files that are never opened have no metrics to be exported.
            if c.total_fops.load(Ordering::Relaxed) == 0 {
                continue;
            }
            let m = serde_json::to_string(c).unwrap_or_else(|_| "Invalid item".to_string());
            rs.push_str(&m);
        }
        if rs.is_empty() {
            rs.push_str("No files to be exported!");
        }
        rs
    }

    pub fn export_global_stats(&self) -> String {
        match serde_json::to_string(self) {
            Ok(s) => s,
            Err(e) => format!("Failed in serializing global metrics {}", e),
        }
    }
}

pub fn export_files_stats(name: &Option<String>) -> Result<String, String> {
    let ios_set = IOS_SET.read().unwrap();

    match name {
        Some(k) => ios_set
            .get(k)
            .ok_or_else(|| "No such id".to_string())
            .map(|v| v.export_files_stats()),
        None => {
            if ios_set.len() == 1 {
                if let Some(ios) = ios_set.values().next() {
                    return Ok(ios.export_files_stats());
                }
            }
            Err("No metrics counter was specified.".to_string())
        }
    }
}

pub fn export_global_stats(name: &Option<String>) -> Result<String, String> {
    // With only one rafs instance, we allow caller to ask for an unknown ios name.
    let ios_set = IOS_SET.read().unwrap();

    match name {
        Some(k) => ios_set
            .get(k)
            .ok_or_else(|| "No such id".to_string())
            .map(|v| v.export_global_stats()),
        None => {
            if ios_set.len() == 1 {
                if let Some(ios) = ios_set.values().next() {
                    return Ok(ios.export_global_stats());
                }
            }
            Err("No metrics counter was specified.".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_block_read_count() {
        let g = GlobalIOStats::default();
        g.ios_init();
        g.ios_global_update(StatsFop::Read, 4000, &Ok(()));
        assert_eq!(g.block_count_read[1].load(Ordering::Relaxed), 1);

        g.ios_global_update(StatsFop::Read, 4096, &Ok(()));
        assert_eq!(g.block_count_read[1].load(Ordering::Relaxed), 1);

        g.ios_global_update(StatsFop::Read, 65535, &Ok(()));
        assert_eq!(g.block_count_read[3].load(Ordering::Relaxed), 1);

        g.ios_global_update(StatsFop::Read, 131072, &Ok(()));
        assert_eq!(g.block_count_read[4].load(Ordering::Relaxed), 1);

        g.ios_global_update(StatsFop::Read, 65520, &Ok(()));
        assert_eq!(g.block_count_read[3].load(Ordering::Relaxed), 2);

        g.ios_global_update(StatsFop::Read, 2015520, &Ok(()));
        assert_eq!(g.block_count_read[3].load(Ordering::Relaxed), 2);
    }
    #[test]
    fn test_latency_record() {
        let g = GlobalIOStats::default();
        g.ios_init();
        let start = g.ios_latency_start();
        sleep(Duration::from_micros(800));
        g.ios_global_update(StatsFop::Read, 100, &Ok(()));
        g.ios_latency_end(&start, StatsFop::Read);

        println!("{:?}", g.read_latency_dist);
        println!("{:?}", g.fop_hits);
        assert_eq!(g.read_latency_dist[2].load(Ordering::Relaxed), 1);

        let start = g.ios_latency_start();
        sleep(Duration::from_micros(2000));
        g.ios_global_update(StatsFop::Read, 100, &Ok(()));
        g.ios_latency_end(&start, StatsFop::Read);

        assert_eq!(g.read_latency_dist[3].load(Ordering::Relaxed), 1);

        let start = g.ios_latency_start();
        sleep(Duration::from_micros(10));
        g.ios_global_update(StatsFop::Read, 100, &Ok(()));
        g.ios_latency_end(&start, StatsFop::Read);

        assert_eq!(g.read_latency_dist[0].load(Ordering::Relaxed), 1);

        let start = g.ios_latency_start();
        sleep(Duration::from_micros(1600));
        g.ios_global_update(StatsFop::Read, 100, &Ok(()));
        g.ios_latency_end(&start, StatsFop::Read);

        assert_eq!(g.read_latency_dist[3].load(Ordering::Relaxed), 2);
    }
}
