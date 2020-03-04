use std::io::{Result};

pub fn compress_with_lz4(src: &Vec<u8>) -> Result<Vec<u8>> {
    return lz4::block::compress(src, None, false);
}

pub fn decompress_with_lz4(src: &Vec<u8>) -> Result<Vec<u8>> {
    return lz4::block::decompress(src, None);
}
