use compress::lz4 as LZ4;
use std::io::{Error, ErrorKind, Result};
use lz4_compress;

pub fn compress_with_lz4_old(src: &[u8], dst: &mut Vec<u8>) -> Result<usize> {
    Ok(LZ4::encode_block(src, dst))
}

pub fn decompress_with_lz4_old(src: &[u8], dst: &mut Vec<u8>) -> Result<usize> {
    Ok(LZ4::decode_block(src, dst))
}

pub fn compress_with_lz4(src: &Vec<u8>) -> Result<Vec<u8>> {
    let compressed = lz4_compress::compress(src.as_slice());
    Ok(compressed)
}

pub fn decompress_with_lz4(src: &[u8]) -> Result<Vec<u8>> {
    let ret = lz4_compress::decompress(src);
    if ret.is_ok() {
        return Ok(ret.unwrap());
    }
    Err(Error::new(ErrorKind::InvalidData, ret.err().unwrap()))
}
