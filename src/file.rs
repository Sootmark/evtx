//! The file header and chunk iteration.

use common::bytes::Reader;
use common::checksum::Crc32;

use crate::chunk::{Chunk, CHUNK_SIZE};
use crate::error::{Error, ErrorKind, Result};

/// Size of the file header block; the first chunk starts right after it.
pub const FILE_HEADER_SIZE: usize = 4096;
const FILE_SIGNATURE: &[u8; 8] = b"ElfFile\0";
/// The header checksum covers the first 120 bytes.
const CHECKSUMMED_HEADER: usize = 120;
const DIRTY_FLAG: u32 = 0x1;
const FULL_FLAG: u32 = 0x2;

/// The `.evtx` file header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    /// Number of the oldest chunk.
    pub first_chunk: u64,
    /// Number of the newest chunk.
    pub last_chunk: u64,
    /// Identifier the next written record will get.
    pub next_record_id: u64,
    /// Format major version (3 on Vista and later).
    pub major_version: u16,
    /// Format minor version.
    pub minor_version: u16,
    /// Chunks the header claims; the file may hold more (see [`EvtxFile::chunks`]).
    pub chunk_count: u16,
    /// The log wasn't closed cleanly: the header may lag behind the chunks.
    pub is_dirty: bool,
    /// The log reached its maximum size.
    pub is_full: bool,
    /// Whether the header checksum matches.
    pub checksum_valid: bool,
}

/// A parsed `.evtx` file borrowing its bytes.
#[derive(Debug, Clone)]
pub struct EvtxFile<'a> {
    data: &'a [u8],
    header: FileHeader,
}

impl<'a> EvtxFile<'a> {
    /// Parse the file header.
    ///
    /// # Errors
    /// [`ErrorKind::NotEvtx`] if the signature is wrong, or a read error if
    /// the header is truncated.
    pub fn new(data: &'a [u8]) -> Result<Self> {
        Ok(Self {
            data,
            header: read_header(data)?,
        })
    }

    /// The file header.
    #[must_use]
    pub const fn header(&self) -> &FileHeader {
        &self.header
    }

    /// Every chunk present in the file, in file order.
    ///
    /// The file is walked by size rather than trusting the header's chunk
    /// count, which lags behind in dirty logs. Unused (all-zero) chunk slots
    /// are skipped. A file that ends inside a chunk (a truncated copy) yields
    /// [`ErrorKind::TruncatedChunk`] for the partial chunk, never silence.
    pub fn chunks(&self) -> impl Iterator<Item = Result<Chunk<'a>>> + '_ {
        let data = self.data;
        let body = data.len().saturating_sub(FILE_HEADER_SIZE);
        let slots = body / CHUNK_SIZE;
        let whole = (0..slots).filter_map(move |slot| {
            let start = FILE_HEADER_SIZE + slot * CHUNK_SIZE;
            let bytes = &data[start..start + CHUNK_SIZE];
            let unused = bytes[..8].iter().all(|&b| b == 0);
            (!unused).then(|| Chunk::new(bytes, start as u64))
        });
        let tail_start = FILE_HEADER_SIZE + slots * CHUNK_SIZE;
        let tail = data.get(tail_start..).unwrap_or_default();
        let partial = (!tail.is_empty() && tail.iter().any(|&b| b != 0)).then(|| {
            Err(Error::new(
                tail_start as u64,
                ErrorKind::TruncatedChunk(tail.len()),
            ))
        });
        whole.chain(partial)
    }
}

fn read_header(data: &[u8]) -> Result<FileHeader> {
    let read = |e: common::bytes::Error| Error::from_read(0, &e);
    let mut r = Reader::new(data);
    if r.array::<8>().map_err(read)? != *FILE_SIGNATURE {
        return Err(Error::new(0, ErrorKind::NotEvtx));
    }
    let first_chunk = r.u64_le().map_err(read)?;
    let last_chunk = r.u64_le().map_err(read)?;
    let next_record_id = r.u64_le().map_err(read)?;
    r.skip(4).map_err(read)?; // header size
    let minor_version = r.u16_le().map_err(read)?;
    let major_version = r.u16_le().map_err(read)?;
    r.skip(2).map_err(read)?; // header block size
    let chunk_count = r.u16_le().map_err(read)?;
    r.seek(CHECKSUMMED_HEADER).map_err(read)?;
    let flags = r.u32_le().map_err(read)?;
    let checksum = r.u32_le().map_err(read)?;
    Ok(FileHeader {
        first_chunk,
        last_chunk,
        next_record_id,
        major_version,
        minor_version,
        chunk_count,
        is_dirty: flags & DIRTY_FLAG != 0,
        is_full: flags & FULL_FLAG != 0,
        checksum_valid: Crc32::of(&data[..CHECKSUMMED_HEADER]) == checksum,
    })
}
