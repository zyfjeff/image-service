// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Rafs fop stats accounting and exporting.

use std::io::Error;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

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

/// Block size separated counters.
/// 1K; 4K; 16K; 64K, 128K.
const BLOCK_READ_COUNT_MAX: usize = 5;

/// <=200us, <=500us, <=1ms, <=20ms, <=50ms, <=100ms, <=500ms, >500ms
const READ_LATENCY_RANGE_MAX: usize = 8;

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct GlobalIOStats {
    // Whether to enable each file accounting switch.
    // As fop accounting might consume much memory space, it is disabled by default.
    // But global fop accounting is always working within each Rafs.
    files_account_enabled: AtomicBool,
    // Given the fact that we don't have to measure latency all the time,
    // use this to turn it off.
    measure_latency: AtomicBool,
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
    fop_cumulative_latency_total: [AtomicIsize; StatsFop::Max as usize],
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
}

#[derive(Default, Debug, Serialize)]
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

lazy_static! {
    pub static ref IOS: GlobalIOStats = Default::default();
    // Rwlock closes the race that more than one threads are creating counters concurrently.
    pub static ref COUNTERS: RwLock<Vec<Arc<Option<InodeIOStats>>>> = Default::default();
}

pub fn ios_files_enabled() -> bool {
    IOS.files_account_enabled.load(Ordering::Relaxed)
}

pub fn ios() -> &'static GlobalIOStats {
    &IOS
}

pub fn ios_init() {
    IOS.files_account_enabled.store(false, Ordering::Relaxed);
    IOS.measure_latency.store(true, Ordering::Relaxed);
}

/// Paired with `ios_latency_end` to record elapsed time for a certain type of fop.
pub fn ios_latency_start() -> Option<SystemTime> {
    if !IOS.measure_latency.load(Ordering::Relaxed) {
        return None;
    }

    Some(SystemTime::now())
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

pub fn ios_latency_end(start: &Option<SystemTime>, fop: StatsFop) {
    if IOS.measure_latency.load(Ordering::Relaxed) {
        if let Some(start) = start {
            if let Ok(d) = SystemTime::elapsed(start) {
                let elapsed = d.as_micros() as isize;
                IOS.fop_cumulative_latency_total[fop as usize]
                    .fetch_add(elapsed, Ordering::Relaxed);
                let avg = IOS.fop_cumulative_latency_avg[fop as usize].load(Ordering::Relaxed);
                let fop_cnt = IOS.fop_hits[fop as usize].load(Ordering::Relaxed) as isize;

                // Zero fop count is hardly to meet, but still check here in
                // case callers misuses ios-latency
                if fop_cnt == 0 {
                    return;
                }
                let new_avg = || avg + (elapsed - avg) / fop_cnt;
                IOS.fop_cumulative_latency_avg[fop as usize].store(new_avg(), Ordering::Relaxed);

                IOS.read_latency_dist[latency_range_index(elapsed)].fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

pub fn export_files_stats() -> String {
    let mut rs = String::new();
    for c in &(*COUNTERS.read().unwrap()) {
        if c.is_some() {
            // Files that are never opened have no metrics to be exported.
            if c.as_ref()
                .as_ref()
                .unwrap()
                .total_fops
                .load(Ordering::Relaxed)
                == 0
            {
                continue;
            }
            let m = serde_json::to_string(c).unwrap_or_else(|_| "Invalid item".to_string());
            rs.push_str(&m);
        }
    }
    if rs.is_empty() {
        rs.push_str("No files to be exported!");
    }
    rs
}

pub fn ios_global_update<T>(fop: StatsFop, value: usize, r: &Result<T, Error>) {
    IOS.last_fop_tp.store(
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
            _ if value >> 10 == 0 => IOS.block_count_read[0].fetch_add(1, Ordering::Relaxed),
            // <=4K
            _ if value >> 12 == 0 => IOS.block_count_read[1].fetch_add(1, Ordering::Relaxed),
            // <=16K
            _ if value >> 14 == 0 => IOS.block_count_read[2].fetch_add(1, Ordering::Relaxed),
            // <=64K
            _ if value >> 16 == 0 => IOS.block_count_read[3].fetch_add(1, Ordering::Relaxed),
            // >64K
            _ => IOS.block_count_read[4].fetch_add(1, Ordering::Relaxed),
        };
    }

    match r {
        Ok(_) => {
            IOS.fop_hits[fop as usize].fetch_add(1, Ordering::Relaxed);
            match fop {
                StatsFop::Read => IOS.data_read.fetch_add(value, Ordering::Relaxed),
                StatsFop::Open => IOS.nr_opens.fetch_add(1, Ordering::Relaxed),
                StatsFop::Release => IOS.nr_opens.fetch_sub(1, Ordering::Relaxed),
                _ => 0,
            }
        }
        Err(_) => IOS.fop_errors[fop as usize].fetch_add(1, Ordering::Relaxed),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_block_read_count() {
        let inode_stats = InodeIOStats::default();
        inode_stats.stats_cumulative(StatsFop::Read, 4000);
        assert_eq!(IOS.block_count_read[1].load(Ordering::Relaxed), 1);

        inode_stats.stats_cumulative(StatsFop::Read, 4096);
        assert_eq!(IOS.block_count_read[1].load(Ordering::Relaxed), 1);

        inode_stats.stats_cumulative(StatsFop::Read, 65535);
        assert_eq!(IOS.block_count_read[3].load(Ordering::Relaxed), 1);

        inode_stats.stats_cumulative(StatsFop::Read, 131072);
        assert_eq!(IOS.block_count_read[4].load(Ordering::Relaxed), 1);

        inode_stats.stats_cumulative(StatsFop::Read, 65520);
        assert_eq!(IOS.block_count_read[3].load(Ordering::Relaxed), 2);

        inode_stats.stats_cumulative(StatsFop::Read, 2015520);
        assert_eq!(IOS.block_count_read[3].load(Ordering::Relaxed), 2);
    }
    #[test]
    fn test_latency_record() {
        ios_init();
        let start = ios_latency_start();
        sleep(Duration::from_micros(800));
        ios_global_update(StatsFop::Read, 100, &Ok(()));
        ios_latency_end(&start, StatsFop::Read);

        assert_eq!(IOS.read_latency_dist[2].load(Ordering::Relaxed), 1);

        let start = ios_latency_start();
        sleep(Duration::from_micros(2000));
        ios_global_update(StatsFop::Read, 100, &Ok(()));
        ios_latency_end(&start, StatsFop::Read);

        assert_eq!(IOS.read_latency_dist[3].load(Ordering::Relaxed), 1);

        let start = ios_latency_start();
        sleep(Duration::from_micros(10));
        ios_global_update(StatsFop::Read, 100, &Ok(()));
        ios_latency_end(&start, StatsFop::Read);

        assert_eq!(IOS.read_latency_dist[0].load(Ordering::Relaxed), 1);

        let start = ios_latency_start();
        sleep(Duration::from_micros(1600));
        ios_global_update(StatsFop::Read, 100, &Ok(()));
        ios_latency_end(&start, StatsFop::Read);

        assert_eq!(IOS.read_latency_dist[3].load(Ordering::Relaxed), 2);
    }
}
