// Copyright 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::{self, remove_file, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Error, Result, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::{thread, time};

use nix::sys::uio;
use vm_memory::VolatileSlice;

use crate::storage::backend::ReqErr;
use crate::storage::backend::{BlobBackend, BlobBackendUploader};
use crate::storage::utils::readv;
use nydus_utils::{round_down_4k, round_up_4k};

const BLOB_ACCESSED_SPLITTER: &str = "\t";
const BLOB_ACCESSED_SUFFIX: &str = ".access";

// Each access record takes 18 bytes: u64 + usize + "\t" + "\n"
// So we allow 1820 at most to avoid hurting backend upon flush
const MAX_ACCESS_RECORD: usize = 32768 / 18;

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

struct LocalFsAccessLog {
    path: String,                      // access log file path
    fd: RawFd,                         // blob fd for readahead
    file: Mutex<File>,                 // access log file
    records: Mutex<Vec<(u64, usize)>>, // access records
}

impl LocalFsAccessLog {
    fn new(file: File, path: String, fd: RawFd) -> LocalFsAccessLog {
        LocalFsAccessLog {
            path,
            fd,
            file: Mutex::new(file),
            records: Mutex::new(Vec::new()),
        }
    }

    fn do_readahead(&self) -> Result<()> {
        info!("starting localfs blob readahead");
        let file = self.file.lock().unwrap();
        for line in BufReader::new(&(*file)).lines() {
            if let Ok(line) = line {
                let v: Vec<&str> = line.split(BLOB_ACCESSED_SPLITTER).collect();
                if v.len() != 2 {
                    warn!("localfs blob access log invalid entry: {}", line);
                    return Err(Error::from_raw_os_error(libc::EINVAL));
                }
                let offset: i64 = v[0].parse().map_err(|_| {
                    warn!("localfs blob access log invalid entry: {}", line);
                    Error::from_raw_os_error(libc::EINVAL)
                })?;
                let len: usize = v[1].parse().map_err(|_| {
                    warn!("localfs blob access log invalid entry: {}", line);
                    Error::from_raw_os_error(libc::EINVAL)
                })?;
                unsafe { libc::readahead(self.fd, offset, len) };
            }
        }
        Ok(())
    }

    fn record(&self, offset: u64, len: u32) {
        let mut r = self.records.lock().unwrap();
        if r.len() < MAX_ACCESS_RECORD {
            r.push((
                round_down_4k(offset),
                // Safe to unwrap because len is u32
                round_up_4k(len as u64).unwrap() as usize,
            ));
        }
    }

    fn flush(&self) {
        info!("flushing access log to {}", &self.path);
        let mut record: Vec<String> = Vec::new();
        let mut r = self.records.lock().unwrap();
        if r.len() == 0 {
            info!(
                "No read access is recorded. Drop access file {}",
                &self.path
            );
            drop(r);
            if let Err(e) = remove_file(Path::new(&self.path)) {
                warn!("failed to remove access file {}: {}", &self.path, e);
            }
            return;
        }
        r.sort();
        r.dedup();
        for (offset, len) in r.iter() {
            record.push(
                vec![
                    offset.to_string(),
                    BLOB_ACCESSED_SPLITTER.to_string(),
                    len.to_string(),
                ]
                .join(""),
            )
        }
        r.clear();
        // set record length to max to no new record is saved
        // safe becasue we have locked records
        unsafe { r.set_len(MAX_ACCESS_RECORD) };
        drop(r);

        let _ = self
            .file
            .lock()
            .unwrap()
            .write_all((record.join("\n") + "\n").as_bytes())
            .map_err(|e| {
                warn!("fail to write access log: {}", e);
                e
            });
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
            // Found access log, kick off readahead
            if file.metadata().unwrap().len() > 0 {
                let access_log = LocalFsAccessLog::new(access_file, access_file_path, fd);
                let _ = thread::Builder::new()
                    .name("nydus-localfs-readahead".to_string())
                    .spawn(move || {
                        let _ = access_log.do_readahead();
                    });
            }
            table_guard.insert(blob_id.to_string(), (file, None));
            return Ok(fd);
        }

        // Case 3: no existing access file, try to get log right
        // If failing to create exclusively, it means others have succeeded, just ignore the error
        if let Ok(access_file) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(Path::new(&access_file_path))
        {
            let access_log = Arc::new(LocalFsAccessLog::new(access_file, access_file_path, fd));
            // Log the first access
            if len != 0 {
                access_log.record(offset, len as u32);
            }
            table_guard.insert(blob_id.to_string(), (file, Some(access_log.clone())));
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
