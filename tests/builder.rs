use std::collections::HashMap;
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use rafs::metadata::RafsSuper;
use rafs::RafsIoRead;

const NYDUS_IMAGE: &str = "./target-fusedev/debug/nydus-image";

pub fn exec(cmd: &str) -> Result<()> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let status = child.wait()?;

    let status = status
        .code()
        .ok_or(Error::new(ErrorKind::Other, "exited with unknown status"))?;

    if status != 0 {
        return Err(Error::new(ErrorKind::Other, "exited with non-zero"));
    }

    Ok(())
}

pub fn hash(data: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.input(data);
    hash.result_str()
}

#[allow(dead_code)]
pub struct FileInfo {
    hash: String,
}

pub struct Builder<'a> {
    work_dir: &'a PathBuf,
    files: HashMap<PathBuf, FileInfo>,
}

pub fn new<'a>(work_dir: &'a PathBuf) -> Builder<'a> {
    Builder {
        work_dir,
        files: HashMap::new(),
    }
}

impl<'a> Builder<'a> {
    pub fn record(&mut self, path: &PathBuf, file_info: FileInfo) {
        self.files.insert(path.clone(), file_info);
    }

    pub fn create_dir(&mut self, path: &PathBuf) -> Result<()> {
        fs::create_dir_all(path)?;
        self.record(path, FileInfo { hash: hash(b"") });
        Ok(())
    }

    pub fn create_file(&mut self, path: &PathBuf, data: &[u8]) -> Result<()> {
        File::create(path)?.write_all(data)?;
        self.record(path, FileInfo { hash: hash(data) });
        Ok(())
    }

    pub fn create_symlink(&mut self, src: &PathBuf, dst: &PathBuf) -> Result<()> {
        unix_fs::symlink(src, dst)?;
        self.record(dst, FileInfo { hash: hash(b"") });
        Ok(())
    }

    pub fn create_hardlink(&mut self, src: &PathBuf, dst: &PathBuf) -> Result<()> {
        fs::hard_link(src, dst)?;
        self.record(dst, FileInfo { hash: hash(b"") });
        Ok(())
    }

    pub fn create_rnd_file(&mut self, path: &PathBuf, size: &str) -> Result<()> {
        exec(
            format!(
                "dd if=/dev/urandom of={:?} bs={} count=1 2>/dev/null",
                path, size
            )
            .as_str(),
        )?;

        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        self.record(
            path,
            FileInfo {
                hash: hash(data.as_slice()),
            },
        );

        Ok(())
    }

    pub fn set_xattr(&mut self, path: &PathBuf, key: &str, value: &[u8]) -> Result<()> {
        xattr::set(path, key, value)?;
        Ok(())
    }

    pub fn make_parent(&mut self) -> Result<()> {
        let dir = self.work_dir.join("parent");
        self.create_dir(&dir)?;

        self.create_file(&dir.join("test-1"), b"lower:test-1")?;
        self.create_file(&dir.join("test-2"), b"lower:test-2")?;
        self.create_rnd_file(&dir.join("test-3-large"), "2MB")?;
        self.create_dir(&dir.join("sub"))?;
        self.create_file(&dir.join("sub/test-1"), b"lower:sub/test-1")?;
        self.create_file(&dir.join("sub/test-2"), b"lower:sub/test-2")?;

        let long_name = &"中文-name.".repeat(100)[..255];
        self.create_file(&dir.join(long_name), b"lower:sub/long-name")?;

        self.create_symlink(
            &Path::new("../test-3-large").to_path_buf(),
            &dir.join("sub/test-3-large-symlink"),
        )?;

        self.create_hardlink(
            &dir.join("test-3-large"),
            &dir.join("sub/test-3-large-hardlink"),
        )?;

        self.create_dir(&dir.join("sub/hide"))?;
        self.create_file(&dir.join("sub/hide/test-1"), b"lower:sub/hide/test-1")?;
        self.create_file(&dir.join("sub/hide/test-2"), b"lower:sub/hide/test-2")?;
        self.create_dir(&dir.join("sub/hide/sub"))?;

        self.create_symlink(
            &Path::new("../../hide/sub").to_path_buf(),
            &dir.join("sub/hide/sub/hide-symlink"),
        )?;

        self.create_file(
            &dir.join("sub/hide/sub/test-1"),
            b"lower:sub/hide/sub/test-1",
        )?;

        self.set_xattr(
            &dir.join("sub/hide/sub/test-1"),
            "user.key-a",
            "value-b".as_bytes(),
        )?;

        self.set_xattr(
            &dir.join("sub/hide/sub/test-1"),
            "user.key-cd",
            "value-ef".as_bytes(),
        )?;

        Ok(())
    }

    pub fn make_source(&mut self) -> Result<()> {
        let dir = self.work_dir.join("source");

        self.create_dir(&dir)?;
        self.create_file(&dir.join("test-2"), b"upper:test-2")?;
        self.create_dir(&dir.join("sub"))?;
        self.create_file(&dir.join("sub/test-4"), b"upper:sub/test-4")?;
        self.create_dir(&dir.join("sub/hide"))?;
        self.create_dir(&dir.join("sub/hide/sub"))?;
        self.create_file(&dir.join("sub/hide/.wh..wh..opq"), b"")?;
        self.create_file(&dir.join("sub/hide/test-1"), b"upper:sub/hide/test-1")?;
        self.create_file(&dir.join("sub/.wh.test-1"), b"")?;

        Ok(())
    }

    pub fn build_parent(&mut self) -> Result<()> {
        let parent_dir = self.work_dir.join("parent");

        self.create_dir(&self.work_dir.join("blobs"))?;

        // exec(format!("tree {:?} -a", parent_dir).as_str())?;
        exec(
            format!(
                "{:?} create --bootstrap {:?} {:?} --backend_type localfs --backend_config '{{\"dir\": {:?}}}' --log_level error",
                NYDUS_IMAGE,
                self.work_dir.join("parent-bootstrap"),
                parent_dir,
                self.work_dir.join("blobs"),
            )
            .as_str(),
        )?;

        Ok(())
    }

    pub fn build_source(&mut self) -> Result<()> {
        let source_dir = self.work_dir.join("source").to_path_buf();

        // exec(format!("tree {:?} -a", source_dir).as_str())?;
        exec(
            format!(
                "{:?} create --blob {:?} --bootstrap {:?} --parent_bootstrap {:?} {:?} --log_level error",
                NYDUS_IMAGE,
                self.work_dir.join("source-blob"),
                self.work_dir.join("bootstrap"),
                self.work_dir.join("parent-bootstrap"),
                source_dir,
            )
            .as_str(),
        )?;

        Ok(())
    }

    pub fn check(&mut self) -> Result<()> {
        let mount_path = self.work_dir.join("mnt");

        exec(format!("tree -a {:?}", mount_path).as_str())?;
        exec(format!("find {:?} -type f -exec md5sum {{}} +", mount_path).as_str())?;

        Ok(())
    }

    #[allow(dead_code)]
    pub fn check_bootstrap(&mut self) -> Result<()> {
        let mut f_bootstrap: Box<dyn RafsIoRead> = Box::new(
            OpenOptions::new()
                .write(false)
                .create(false)
                .read(true)
                .open(self.work_dir.join("parent-bootstrap"))?,
        ) as Box<dyn RafsIoRead>;

        let mut super_block = RafsSuper::new("direct")?;
        super_block.load(&mut f_bootstrap)?;

        for i in 1..17 {
            let inode = super_block.get_inode(i)?;

            println!(
                "----- inode name: {:?} size: {} ino: {} idx: {} has_xattr {}",
                inode.name()?,
                inode.size(),
                inode.ino(),
                i,
                inode.has_xattr(),
            );

            if inode.is_symlink() {
                let link = inode.get_symlink()?;
                println!("\tlink {}", link);
            } else if inode.is_dir() {
                for i in 0..inode.get_child_count()? {
                    let child = inode.get_child_by_index(i as u64)?;
                    println!("\tchild {}", child.name()?);
                }
            } else if inode.is_reg() {
                if inode.has_xattr() {
                    let xattrs = inode.get_xattrs();
                    println!("\txattrs {:?}", xattrs);
                }
            }
        }

        Ok(())
    }
}
