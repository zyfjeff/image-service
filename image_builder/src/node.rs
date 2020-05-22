// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be
// found in the LICENSE file.

// use std::ffi::{c_void, CString};
use rafs::RafsIoWrite;
use std::fmt;
use std::fs::{self, File};
use std::io::prelude::*;
use std::io::{Result, SeekFrom};
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use rafs::metadata::layout::*;
use rafs::metadata::*;

#[derive(Clone, Debug, PartialEq)]
pub enum Overlay {
    LowerAddition,
    UpperAddition,
    UpperOpaque,
    UpperRemoval,
    UpperModification,
}

impl fmt::Display for Overlay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Overlay::LowerAddition => write!(f, "lower added"),
            Overlay::UpperAddition => write!(f, "upper added"),
            Overlay::UpperOpaque => write!(f, "upper opaqued"),
            Overlay::UpperRemoval => write!(f, "upper removed"),
            Overlay::UpperModification => write!(f, "upper modified"),
        }
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} ino {}, parent {}, childs {}, child index {}",
            // self.get_type(),
            self.get_rootfs(),
            self.inode.ino(),
            self.inode.parent(),
            self.inode.child_count(),
            self.inode.child_index(),
        )
    }
}

#[derive(Clone)]
pub struct Node {
    /// type
    pub overlay: Overlay,
    /// offset of blob file
    pub blob_offset: u64,
    /// source path
    pub root: PathBuf,
    /// file path
    pub path: PathBuf,
    /// file inode info
    pub inode: OndiskInode,
    /// chunks info of file
    pub chunks: Vec<OndiskChunkInfo>,
    // chunks info of symlink file
    pub link_chunk: Option<OndiskSymlinkInfo>,
    // xattr info of file
    // pub xattr_chunks: RafsInodeXattrInfos,
}

impl Node {
    pub fn build(&mut self, hardlink_node: Option<Node>) -> Result<bool> {
        self.build_inode(hardlink_node)?;
        let file_type = self.get_type();
        if file_type != "" {
            info!("upper building {} {:?}", file_type, self.get_rootfs());
            return Ok(true);
        }
        info!("skip build {:?}", self.get_rootfs());
        Ok(false)
    }

    fn build_inode_xattr(&mut self) -> Result<()> {
        let mut xattrs = xattr::list(&self.path)?.peekable();

        if xattrs.peek().is_none() {
            return Ok(());
        }

        let mut xattr_chunk = OndiskXAttr::new();
        for (count, key) in xattrs.enumerate() {
            let value = xattr::get(&self.path, &key)?;
            let mut pair = OndiskXAttrPair::new();
            pair.set(key.to_str().unwrap(), value.unwrap_or_else(Vec::new));
            xattr_chunk.push(pair);
        }

        // let filepath = CString::new(self.path.as_str())?;
        // // Safe because we are calling into C functions.
        // let name_size =
        //     unsafe { libc::llistxattr(filepath.as_ptr() as *const i8, std::ptr::null_mut(), 0) };
        // if name_size <= 0 {
        //     return Ok(());
        // }

        // let mut buf: Vec<u8> = Vec::new();
        // buf.resize(name_size as usize, 0);
        // // Safe because we are calling into C functions.
        // unsafe {
        //     let ret = libc::llistxattr(
        //         filepath.as_ptr() as *const i8,
        //         buf.as_mut_ptr() as *mut i8,
        //         name_size as usize,
        //     );
        //     if ret <= 0 {
        //         return Ok(());
        //     }
        // };

        // let names = match str::from_utf8(&buf) {
        //     Ok(s) => {
        //         let s: Vec<&str> = s.split_terminator('\0').collect();
        //         Ok(s)
        //     }
        //     Err(_) => Err(Error::from_raw_os_error(libc::EINVAL)),
        // }?;

        // let mut count = 0;
        // for n in names.iter() {
        //     // make sure name is nul terminated
        //     let mut name = (*n).to_string();
        //     name.push('\0');
        //     let value_size = unsafe {
        //         libc::lgetxattr(
        //             filepath.as_ptr() as *const i8,
        //             name.as_ptr() as *const i8,
        //             std::ptr::null_mut(),
        //             0,
        //         )
        //     };
        //     if value_size < 0 {
        //         continue;
        //     }
        //     if value_size == 0 {
        //         count += 1;
        //         self.xattr_chunks.data.insert(name, vec![]);
        //         continue;
        //     }
        //     // Need to read xattr value
        //     let mut value_buf: Vec<u8> = Vec::new();
        //     value_buf.resize(value_size as usize, 0);
        //     // Safe because we are calling into C functions.
        //     unsafe {
        //         let ret = libc::lgetxattr(
        //             filepath.as_ptr() as *const i8,
        //             name.as_ptr() as *const i8,
        //             value_buf.as_mut_ptr() as *mut c_void,
        //             value_size as usize,
        //         );
        //         if ret < 0 {
        //             continue;
        //         }
        //         if ret == 0 {
        //             count += 1;
        //             self.xattr_chunks.data.insert(name, vec![]);
        //             continue;
        //         }
        //     };
        //     count += 1;
        //     self.xattr_chunks.data.insert(name, value_buf);
        // }

        // if count > 0 {
        //     self.inode.i_flags |= INO_FLAG_XATTR;
        //     self.xattr_chunks.count = count;
        //     trace!(
        //         "\tinode {} has xattr {:?}",
        //         self.inode.name,
        //         self.xattr_chunks
        //     );
        // }
        // Ok(())

        Ok(())
    }

    #[allow(clippy::borrowed_box)]
    pub fn dump_blob(
        &mut self,
        f_blob: &mut Box<dyn RafsIoWrite>,
        blob_hash: &mut Sha256,
    ) -> Result<OndiskDigest> {
        let mut inode_digest = OndiskDigest::new();

        if self.is_symlink() {
            let target_path = fs::read_link(&self.path)?;
            let mut link_chunk =
                OndiskSymlinkInfo::from_raw(target_path.to_str().unwrap().as_bytes())?;
            link_chunk.store(f_blob)?;
            return Ok(inode_digest);
        }

        if self.is_dir() {
            return Ok(inode_digest);
        }

        let file_size = self.inode.size();
        let mut inode_hash = Sha256::new();
        let mut file = File::open(&self.path)?;

        for i in 0..self.inode.chunk_cnt() {
            let mut chunk = OndiskChunkInfo::new();

            // get chunk info
            chunk.set_file_offset((i * RAFS_DEFAULT_BLOCK_SIZE as u64) as u64);
            let len = if i == self.inode.chunk_cnt() - 1 {
                (file_size % RAFS_DEFAULT_BLOCK_SIZE as u64) as usize
            } else {
                RAFS_DEFAULT_BLOCK_SIZE
            };

            // get chunk data
            file.seek(SeekFrom::Start(chunk.file_offset()))?;
            let mut chunk_data = vec![0; len];
            file.read_exact(&mut chunk_data)?;

            // calc chunk digest
            let digest = OndiskDigest::from_buf(chunk_data.as_slice());
            chunk.set_block_id(&digest);

            // compress chunk data
            let compressed = utils::compress(&chunk_data)?;
            let compressed_size = compressed.len();
            chunk.set_blob_offset(self.blob_offset);
            chunk.set_compress_size(compressed_size as u32);

            // move cursor to offset of next chunk
            self.blob_offset += compressed_size as u64;

            trace!(
                "\tbuilding chunk: file offset {}, blob offset {}, size {}",
                chunk.file_offset(),
                chunk.blob_offset(),
                chunk.compress_size(),
            );

            // calc blob hash
            blob_hash.input(&compressed);

            // dump compressed chunk data to blob
            f_blob.write_all(&compressed)?;

            // calc inode digest
            inode_hash.input(&chunk.block_id().data());

            // stash chunk
            self.chunks.push(chunk);
        }

        // finish calc inode digest
        let mut inode_hash_buf = [0; RAFS_SHA256_LENGTH];
        inode_hash.result(&mut inode_hash_buf);
        inode_digest.data_mut().clone_from_slice(&inode_hash_buf);

        info!(
            "\tbuilding inode: name {}, ino {}, digest {}, parent {}, chunk_cnt {}",
            self.inode.name(),
            self.inode.ino(),
            self.inode.digest(),
            self.inode.parent(),
            self.inode.chunk_cnt(),
        );

        self.inode.set_digest(&inode_digest);

        Ok(inode_digest)
    }

    #[allow(clippy::borrowed_box)]
    pub fn dump_bootstrap(
        &mut self,
        f_bootstrap: &mut Box<dyn RafsIoWrite>,
        blob_index: u32,
    ) -> Result<()> {
        // dump inode info
        self.inode.store(f_bootstrap)?;

        // dump inode xattr
        // self.xattr_chunks.store(f_bootstrap)?;

        // dump chunk info
        for chunk in &mut self.chunks {
            chunk.set_blob_index(blob_index);
            chunk.store(f_bootstrap)?;
        }

        // dump symlink chunk info
        if let Some(link_chunk) = &mut self.link_chunk {
            link_chunk.store(f_bootstrap)?;
        }

        Ok(())
    }

    pub fn new(blob_offset: u64, root: PathBuf, path: PathBuf, overlay: Overlay) -> Node {
        Node {
            blob_offset,
            root,
            path,
            overlay,
            inode: OndiskInode::new(),
            chunks: Vec::new(),
            link_chunk: None,
            // xattr_chunks: RafsInodeXattrInfos::new(),
        }
    }

    fn build_inode_stat(&mut self) -> Result<()> {
        let meta = self.meta();

        self.inode.set_mode(meta.st_mode());
        self.inode.set_uid(meta.st_uid());
        self.inode.set_gid(meta.st_gid());
        self.inode.set_projid(0);
        self.inode.set_rdev(meta.st_rdev());
        self.inode.set_size(meta.st_size());
        self.inode.set_nlink(meta.st_nlink());
        self.inode.set_blocks(meta.st_blocks());
        self.inode.set_atime(meta.st_atime() as u64);
        self.inode.set_mtime(meta.st_mtime() as u64);
        self.inode.set_ctime(meta.st_ctime() as u64);

        Ok(())
    }

    pub fn build_inode(&mut self, hardlink_node: Option<Node>) -> Result<()> {
        if self.get_rootfs() == PathBuf::from("/") {
            self.inode.set_name("/")?;
            self.build_inode_stat()?;
            return Ok(());
        }

        let file_name = self.path.file_name().unwrap().to_str().unwrap();

        self.inode.set_name(file_name)?;
        self.build_inode_stat()?;
        self.build_inode_xattr()?;

        if self.is_reg() {
            if self.is_hardlink() {
                if let Some(hardlink_node) = hardlink_node {
                    self.inode
                        .set_flags(self.inode.flags() | INO_FLAG_HARDLINK as u64);
                    self.inode.set_digest(hardlink_node.inode.digest());
                    self.inode.set_chunk_cnt(0);
                    return Ok(());
                }
            }
            let file_size = self.inode.size();
            let chunk_count = (file_size as f64 / RAFS_DEFAULT_BLOCK_SIZE as f64).ceil() as u64;
            self.inode.set_chunk_cnt(chunk_count);
        } else if self.is_symlink() {
            self.inode
                .set_flags(self.inode.flags() | INO_FLAG_SYMLINK as u64);
            let target_path = fs::read_link(&self.path)?;
            let link_chunk = OndiskSymlinkInfo::from_raw(target_path.to_str().unwrap().as_bytes())?;
            self.inode.set_chunk_cnt(link_chunk.count() as u64);
            self.link_chunk = Some(link_chunk);
        }

        Ok(())
    }

    pub fn meta(&self) -> impl MetadataExt {
        self.path.symlink_metadata().unwrap()
    }

    pub fn is_dir(&self) -> bool {
        self.meta().st_mode() & libc::S_IFMT == libc::S_IFDIR
    }

    pub fn is_symlink(&self) -> bool {
        self.meta().st_mode() & libc::S_IFMT == libc::S_IFLNK
    }

    pub fn is_reg(&self) -> bool {
        self.meta().st_mode() & libc::S_IFMT == libc::S_IFREG
    }

    pub fn is_hardlink(&self) -> bool {
        self.meta().st_nlink() > 1
    }

    pub fn get_type(&self) -> &str {
        let mut file_type = "";

        if self.is_symlink() {
            file_type = "symlink";
        } else if self.is_dir() {
            file_type = "dir"
        } else if self.is_reg() {
            if self.is_hardlink() {
                file_type = "hardlink";
            } else {
                file_type = "file";
            }
        }

        file_type
    }

    pub fn get_rootfs(&self) -> PathBuf {
        Path::new("/").join(self.path.strip_prefix(&self.root).unwrap())
    }
}
