use std::io::Result;
use compress::lz4 as LZ4;

pub fn compress_with_lz4_old(src: &[u8], dst: &mut Vec<u8>) -> usize {
    LZ4::encode_block(src, dst)
}

pub fn decompress_with_lz4_old(src: &[u8], dst: &mut Vec<u8>) -> usize {
    LZ4::decode_block(src, dst)
}

pub fn compress_with_lz4(src: &Vec<u8>) -> Result<Vec<u8>> {
    return lz4::block::compress(src, None, false);
}

pub fn decompress_with_lz4(src: &Vec<u8>) -> Result<Vec<u8>> {
    return lz4::block::decompress(src, None);
}
