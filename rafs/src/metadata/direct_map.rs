use crate::fs::Inode;
use crate::metadata::layout::{OndiskInode, OndiskSuperBlock};
use crate::*;

/*
pub struct CachedInodes {
    sb_data: &'static OndiskSuperBlock,
    sb_ptr: *const u8,
    max_size: u64,
    ino_2_offset: *const u32,
}

impl CachedInodes {
    fn get_inode_internal(&self, ino: Inode) -> Result<&OndiskInode> {
        // TODO:
        if ino >= 0x1000  || (ino << 3) > std::u32::MAX as u64 {
            return Err(enoent());
        }

        let ptr = unsafe { *(self.sb_ptr.add((ino as usize) << 3) as u32 };
    }
}
 */
