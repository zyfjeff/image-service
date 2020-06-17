// Copyright 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::{self, remove_file, File, OpenOptions};
use std::io::{self, Error, Result};
use std::mem::{size_of, ManuallyDrop};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::{thread, time};

use nix::sys::uio;
use vm_memory::VolatileSlice;

use crate::storage::backend::ReqErr;
use crate::storage::backend::{BlobBackend, BlobBackendUploader};
use crate::storage::utils::readv;
use crate::{ebadf, einval};
use nydus_utils::{round_down_4k, round_up_4k};

const BLOB_ACCESSED_SUFFIX: &str = ".access";

// Each access record takes 16 bytes: u64 + u32 + u32
// So we allow 2048 entries at most to avoid hurting backend upon flush
const ACCESS_RECORD_ENTRY_SIZE: usize = size_of::<u64>() + size_of::<u32>() + size_of::<u32>();
const MAX_ACCESS_RECORD_FILE_SIZE: usize = 32768;
const MAX_ACCESS_RECORD: usize = MAX_ACCESS_RECORD_FILE_SIZE / ACCESS_RECORD_ENTRY_SIZE;

type FileTableEntry = (File, Option<Arc<LocalFsAccessLog>>);

#[derive(Default)]
pub struct LocalFs {
    // the specified blob file
    blob_file: String,
    // directory to blob files
    dir: String,
    // readahead blob file
    readahead: bool,
    // blobid-File map
    file_table: RwLock<HashMap<String, FileTableEntry>>,
}

pub fn new<S: std::hash::BuildHasher>(config: &HashMap<String, String, S>) -> Result<LocalFs> {
    let readahead = config
        .get("readahead")
        .map(|r| r == "true")
        .unwrap_or(false);

    match (config.get("blob_file"), config.get("dir")) {
        (Some(blob_file), _) => Ok(LocalFs {
            blob_file: String::from(blob_file),
            readahead,
            file_table: RwLock::new(HashMap::new()),
            ..Default::default()
        }),

        (_, Some(dir)) => Ok(LocalFs {
            dir: String::from(dir),
            readahead,
            file_table: RwLock::new(HashMap::new()),
            ..Default::default()
        }),

        _ => Err(ReqErr::inv_input("blob file or dir is required")),
    }
}

type AccessLogEntry = (u64, u32, u32);

// Access entries can be either mmapped or Vec-allocated.
// Use mmap for read case and Vec-allocated for write case.
struct LocalFsAccessLog {
    log_path: String,                                  // log file path
    log_fd: RawFd,                                     // log file fd
    log_base: *const u8,                               // mmaped access log base
    log_size: usize,                                   // log file size
    blob_fd: RawFd,                                    // blob fd for readahead
    blob_size: usize,                                  // blob file size
    records: ManuallyDrop<Mutex<Vec<AccessLogEntry>>>, // access records
}

unsafe impl Send for LocalFsAccessLog {}

unsafe impl Sync for LocalFsAccessLog {}

impl LocalFsAccessLog {
    fn new() -> LocalFsAccessLog {
        LocalFsAccessLog {
            log_path: "".to_string(),
            log_fd: -1,
            log_base: std::ptr::null(),
            log_size: 0,
            blob_fd: -1,
            blob_size: 0,
            records: ManuallyDrop::new(Mutex::new(Vec::new())),
        }
    }

    fn init(
        &mut self,
        log_file: File,
        log_path: String,
        blob_fd: RawFd,
        blob_size: usize,
        load_entries: bool,
    ) -> Result<()> {
        if self.log_fd > 0
            || !self.log_path.is_empty()
            || self.blob_fd > 0
            || self.records.lock().unwrap().len() > 0
        {
            return Err(einval());
        }

        self.log_fd = unsafe { libc::dup(log_file.as_raw_fd()) };
        if self.log_fd < 0 {
            return Err(Error::last_os_error());
        }
        self.blob_fd = unsafe { libc::dup(blob_fd) };
        if self.blob_fd < 0 {
            return Err(Error::last_os_error());
        }
        self.log_path = log_path;
        self.blob_size = blob_size;

        if !load_entries {
            return Ok(());
        }

        // load exiting entries
        let size = log_file.metadata()?.len() as usize;
        if size == 0 || size % ACCESS_RECORD_ENTRY_SIZE != 0 {
            warn!("ignoring unaligned log file");
            return Ok(());
        }
        let count = size / ACCESS_RECORD_ENTRY_SIZE;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size as usize,
                libc::PROT_READ,
                libc::MAP_NORESERVE | libc::MAP_PRIVATE,
                self.log_fd,
                0,
            )
        } as *const AccessLogEntry;
        if base as *mut core::ffi::c_void == libc::MAP_FAILED {
            return Err(Error::last_os_error());
        }
        if base.is_null() {
            return Err(ebadf());
        }
        // safe because we have validated size
        self.records = unsafe {
            ManuallyDrop::new(Mutex::new(Vec::from_raw_parts(
                base as *mut AccessLogEntry,
                count as usize,
                count as usize,
            )))
        };
        self.log_base = base as *const u8;
        self.log_size = size;
        Ok(())
    }

    fn do_readahead(&self) -> Result<()> {
        info!("starting localfs blob readahead");
        for &(offset, len, zero) in self.records.lock().unwrap().iter() {
            let end: u64 = offset.checked_add(len as u64).ok_or_else(einval)?;
            if offset > self.blob_size as u64 || end > self.blob_size as u64 || zero != 0 {
                warn!(
                    "invalid readahead entry ({}, {}), blob size {}",
                    offset, len, self.blob_size
                );
                return Err(einval());
            }
            unsafe { libc::readahead(self.blob_fd, offset as i64, len as usize) };
        }
        Ok(())
    }

    fn record(&self, offset: u64, len: u32) {
        // Never modify mmaped records
        if !self.log_base.is_null() {
            return;
        }

        let mut r = self.records.lock().unwrap();
        if r.len() < MAX_ACCESS_RECORD {
            r.push((
                round_down_4k(offset),
                // Safe to unwrap because len is u32
                round_up_4k(len as u64).unwrap() as u32,
                0,
            ));
        }
    }

    fn flush(&self) {
        info!("flushing access log to {}", &self.log_path);
        let mut r = self.records.lock().unwrap();
        if r.len() == 0 {
            info!(
                "No read access is recorded. Drop access file {}",
                &self.log_path
            );
            // set record length to max to no new record is saved
            // safe becasue we have locked records
            unsafe { r.set_len(MAX_ACCESS_RECORD) };
            drop(r);
            if let Err(e) = remove_file(Path::new(&self.log_path)) {
                warn!("failed to remove access file {}: {}", &self.log_path, e);
            }
            return;
        }
        r.sort();
        r.dedup();
        let record = r.clone();
        r.clear();
        // set record length to max to no new record is saved
        // safe becasue we have locked records
        unsafe { r.set_len(MAX_ACCESS_RECORD) };
        drop(r);

        let record = unsafe {
            std::slice::from_raw_parts(
                record.as_ptr() as *const u8,
                record.len() * std::mem::size_of::<AccessLogEntry>(),
            )
        };

        let _ = nix::unistd::write(self.log_fd, record).map_err(|e| {
            warn!("fail to write access log: {}", e);
            e
        });
    }
}

impl Drop for LocalFsAccessLog {
    fn drop(&mut self) {
        if !self.log_base.is_null() {
            unsafe {
                libc::munmap(
                    self.log_base as *mut u8 as *mut libc::c_void,
                    self.log_size as usize,
                )
            };
            self.log_base = std::ptr::null();
            self.log_size = 0;
        } else {
            // Drop records if it is not mmapped
            unsafe {
                ManuallyDrop::drop(&mut self.records);
            }
        }
        if self.blob_fd > 0 {
            let _ = nix::unistd::close(self.blob_fd);
            self.blob_fd = -1;
        }
        if self.log_fd > 0 {
            let _ = nix::unistd::close(self.log_fd);
            self.log_fd = -1;
        }
    }
}

impl LocalFs {
    fn get_blob_fd(&self, blob_id: &str, offset: u64, len: usize) -> Result<RawFd> {
        let blob_file_path = if self.use_blob_file() {
            Path::new(&self.blob_file).to_path_buf()
        } else {
            Path::new(&self.dir).join(blob_id)
        };

        // Don't expect poisoned lock here.
        if let Some((file, access_log)) = self.file_table.read().unwrap().get(blob_id) {
            if let Some(access_log) = access_log {
                if len != 0 {
                    access_log.record(offset, len as u32);
                }
            }
            return Ok(file.as_raw_fd());
        }

        let file = OpenOptions::new()
            .read(true)
            .open(&blob_file_path)
            .map_err(|e| {
                error!("failed to open blob {}: {}", blob_id, e);
                e
            })?;
        let size = file.metadata()?.len() as usize;
        let fd = file.as_raw_fd();

        // Don't expect poisoned lock here.
        let mut table_guard = self.file_table.write().unwrap();
        // Double check whether someone else inserted the file concurrently.
        if let Some((other, access_log)) = table_guard.get(blob_id) {
            if let Some(access_log) = access_log {
                if len != 0 {
                    access_log.record(offset, len as u32);
                }
            }
            return Ok(other.as_raw_fd());
        }

        // Case 1: no readahead
        if !self.readahead {
            table_guard.insert(blob_id.to_string(), (file, None));
            return Ok(fd);
        }

        // Case 2: someone else has done logging, kick off readahead
        let access_file_path = blob_file_path.to_str().unwrap().to_owned() + BLOB_ACCESSED_SUFFIX;
        if let Ok(access_file) = OpenOptions::new()
            .read(true)
            .open(Path::new(&access_file_path))
        {
            table_guard.insert(blob_id.to_string(), (file, None));
            drop(table_guard);
            // Found access log, kick off readahead
            if size > 0 {
                let mut access_log = LocalFsAccessLog::new();
                access_log.init(access_file, access_file_path, fd, size, true)?;
                let _ = thread::Builder::new()
                    .name("nydus-localfs-readahead".to_string())
                    .spawn(move || {
                        let _ = access_log.do_readahead();
                    });
            }
            return Ok(fd);
        }

        // Case 3: no existing access file, try to get log right
        // If failing to create exclusively, it means others have succeeded, just ignore the error
        if let Ok(access_file) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(Path::new(&access_file_path))
        {
            let mut access_log = LocalFsAccessLog::new();
            access_log.init(access_file, access_file_path, fd, size, false)?;
            // Log the first access
            if len != 0 {
                access_log.record(offset, len as u32);
            }
            let access_log = Arc::new(access_log);
            table_guard.insert(blob_id.to_string(), (file, Some(access_log.clone())));
            drop(table_guard);
            // Split a thread to flush access record
            let _ = thread::Builder::new()
                .name("nydus-localfs-access-recorder".to_string())
                .spawn(move || {
                    thread::sleep(time::Duration::from_secs(10));
                    access_log.flush();
                });
            return Ok(fd);
        }

        // Case 4: failed race, just let others log
        table_guard.insert(blob_id.to_string(), (file, None));
        Ok(fd)
    }

    fn use_blob_file(&self) -> bool {
        !self.blob_file.is_empty()
    }
}

impl BlobBackend for LocalFs {
    fn init_blob(&self, blobs: Vec<&str>) {
        for blob in blobs.iter() {
            let _ = self.get_blob_fd(blob, 0, 0);
        }
    }

    fn read(&self, blob_id: &str, buf: &mut [u8], offset: u64) -> Result<usize> {
        let fd = self.get_blob_fd(blob_id, offset, buf.len())?;

        debug!(
            "local blob file reading: offset={}, size={}",
            offset,
            buf.len()
        );
        let len = uio::pread(fd, buf, offset as i64).map_err(|_| Error::last_os_error())?;
        debug!("local blob file read {} bytes", len);

        Ok(len)
    }

    fn readv(
        &self,
        blob_id: &str,
        bufs: &[VolatileSlice],
        offset: u64,
        max_size: usize,
    ) -> Result<usize> {
        let fd = self.get_blob_fd(blob_id, offset, max_size)?;
        readv(fd, bufs, offset, max_size)
    }

    fn write(&self, _blob_id: &str, _buf: &[u8], _offset: u64) -> Result<usize> {
        unimplemented!("write operation not supported with localfs");
    }

    fn close(&mut self) {}
}

impl BlobBackendUploader for LocalFs {
    type Reader = std::fs::File;

    fn upload(
        &self,
        blob_id: &str,
        mut reader: std::fs::File,
        _size: usize,
        _callback: fn((usize, usize)),
    ) -> Result<usize> {
        let blob = if self.use_blob_file() {
            Path::new(&self.blob_file).to_path_buf()
        } else {
            Path::new(&self.dir).join(blob_id)
        };

        if let Some(parent) = blob.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut w = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&blob)
            .map_err(|e| {
                error!("localfs update: open failed {:?}", e);
                e
            })?;

        io::copy(&mut reader, &mut w).map(|sz| sz as usize)
    }
}
