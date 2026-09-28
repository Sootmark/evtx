//! Chunks and the records inside them.

use common::bytes::Reader;
use common::checksum::Crc32;

use crate::binxml::Parser;
use crate::error::{Error, ErrorKind, Result};
use crate::record::Record;
use crate::tree::Node;

/// Every chunk is 64 KiB.
pub const CHUNK_SIZE: usize = 65_536;
const CHUNK_SIGNATURE: &[u8; 8] = b"ElfChnk\0";
/// Records start after the header and the name/template offset tables.
const RECORDS_START: usize = 512;
/// The header checksum covers bytes 0..120 and 128..512.
const CHECKSUM_GAP: core::ops::Range<usize> = 120..128;
/// Where the header checksum itself is stored (inside the gap).
const HEADER_CHECKSUM_OFFSET: usize = 124;
const RECORD_SIGNATURE: [u8; 4] = [0x2a, 0x2a, 0x00, 0x00];
/// Signature (4), size (4), record id (8), written time (8).
const RECORD_HEADER_SIZE: usize = 24;
/// The trailing copy of the record size.
const RECORD_TRAILER_SIZE: usize = 4;

/// A chunk's header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkHeader {
    /// First record number in the chunk.
    pub first_record_number: u64,
    /// Last record number in the chunk.
    pub last_record_number: u64,
    /// First record identifier in the chunk.
    pub first_record_id: u64,
    /// Last record identifier in the chunk.
    pub last_record_id: u64,
    /// Where unused space starts (records end here).
    pub free_space_offset: u32,
    /// Whether the header checksum matches.
    pub header_checksum_valid: bool,
    /// Whether the checksum over the records area matches.
    pub records_checksum_valid: bool,
}

/// One 64 KiB chunk.
#[derive(Debug, Clone)]
pub struct Chunk<'a> {
    data: &'a [u8],
    offset: u64,
    header: ChunkHeader,
}

/// A record that couldn't be decoded, located by its start offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DamagedRecord {
    /// File offset where the record starts.
    pub offset: u64,
    /// Why it couldn't be decoded.
    pub error: Error,
}

impl<'a> Chunk<'a> {
    /// Parse the header of the chunk occupying `data`, found at file `offset`.
    ///
    /// # Errors
    /// [`ErrorKind::BadChunkSignature`], or a read error if truncated.
    pub fn new(data: &'a [u8], offset: u64) -> Result<Self> {
        Ok(Self {
            data,
            offset,
            header: read_header(data, offset)?,
        })
    }

    /// The chunk header.
    #[must_use]
    pub const fn header(&self) -> &ChunkHeader {
        &self.header
    }

    /// File offset of the chunk.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// The chunk's records, in order. A record that can't be decoded yields
    /// a [`DamagedRecord`]; iteration continues with the next record when
    /// the damaged record's size is trustworthy, and stops otherwise.
    #[must_use]
    pub fn records(&self) -> Records<'a> {
        let end = (self.header.free_space_offset as usize).clamp(RECORDS_START, self.data.len());
        Records {
            chunk: self.clone(),
            parser: Parser::new(self.data, self.offset),
            position: RECORDS_START,
            end,
        }
    }
}

fn read_header(data: &[u8], offset: u64) -> Result<ChunkHeader> {
    let read = |e: common::bytes::Error| Error::from_read(offset, &e);
    let mut r = Reader::new(data);
    if r.array::<8>().map_err(read)? != *CHUNK_SIGNATURE {
        return Err(Error::new(offset, ErrorKind::BadChunkSignature));
    }
    let first_record_number = r.u64_le().map_err(read)?;
    let last_record_number = r.u64_le().map_err(read)?;
    let first_record_id = r.u64_le().map_err(read)?;
    let last_record_id = r.u64_le().map_err(read)?;
    r.skip(8).map_err(read)?; // header size, last record offset
    let free_space_offset = r.u32_le().map_err(read)?;
    let records_checksum = r.u32_le().map_err(read)?;
    r.seek(HEADER_CHECKSUM_OFFSET).map_err(read)?;
    let header_checksum = r.u32_le().map_err(read)?;
    let records_end = (free_space_offset as usize).clamp(RECORDS_START, data.len());
    Ok(ChunkHeader {
        first_record_number,
        last_record_number,
        first_record_id,
        last_record_id,
        free_space_offset,
        header_checksum_valid: header_checksum == header_crc(data),
        records_checksum_valid: records_checksum == Crc32::of(&data[RECORDS_START..records_end]),
    })
}

fn header_crc(data: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(&data[..CHECKSUM_GAP.start]);
    crc.update(&data[CHECKSUM_GAP.end..RECORDS_START]);
    crc.finalize()
}

/// Iterator over a chunk's records. See [`Chunk::records`].
pub struct Records<'a> {
    chunk: Chunk<'a>,
    parser: Parser<'a>,
    position: usize,
    end: usize,
}

impl Iterator for Records<'_> {
    type Item = core::result::Result<Record, DamagedRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position + RECORD_HEADER_SIZE > self.end {
            return None;
        }
        let start = self.position;
        let offset = self.chunk.offset + start as u64;
        let damaged = |error| DamagedRecord { offset, error };
        match self.frame(start) {
            Ok(frame) => {
                self.position = start + frame.size;
                Some(self.decode(&frame).map_err(damaged))
            }
            Err(error) => {
                // The record's size can't be trusted, so the next record
                // can't be found: stop this chunk.
                self.position = self.end;
                Some(Err(damaged(error)))
            }
        }
    }
}

/// A record's header fields and the extent of its BinXML body.
struct Frame {
    /// Chunk offset where the record starts.
    start: usize,
    size: usize,
    id: u64,
    written: u64,
    body: core::ops::Range<usize>,
}

impl Records<'_> {
    fn frame(&self, start: usize) -> Result<Frame> {
        let offset = self.chunk.offset + start as u64;
        let read = |e: common::bytes::Error| Error::from_read(self.chunk.offset, &e);
        let mut r = Reader::new(&self.chunk.data[..self.end]);
        r.seek(start).map_err(read)?;
        if r.array::<4>().map_err(read)? != RECORD_SIGNATURE {
            return Err(Error::new(offset, ErrorKind::BadRecordSignature));
        }
        let size_field = r.u32_le().map_err(read)?;
        let size = size_field as usize;
        let fits = size >= RECORD_HEADER_SIZE + RECORD_TRAILER_SIZE && start + size <= self.end;
        if !fits {
            return Err(Error::new(offset, ErrorKind::BadRecordSize(size_field)));
        }
        let id = r.u64_le().map_err(read)?;
        let written = r.u64_le().map_err(read)?;
        r.seek(start + size - RECORD_TRAILER_SIZE).map_err(read)?;
        if r.u32_le().map_err(read)? != size_field {
            return Err(Error::new(offset, ErrorKind::BadRecordSize(size_field)));
        }
        Ok(Frame {
            start,
            size,
            id,
            written,
            body: start + RECORD_HEADER_SIZE..start + size - RECORD_TRAILER_SIZE,
        })
    }

    fn decode(&mut self, frame: &Frame) -> Result<Record> {
        let offset = self.chunk.offset + frame.start as u64;
        let nodes = self.parser.record(frame.body.start, frame.body.end)?;
        let root = nodes
            .into_iter()
            .find_map(|node| match node {
                Node::Element(element) => Some(element),
                _ => None,
            })
            .ok_or(Error::new(offset, ErrorKind::NoRootElement))?;
        Ok(Record {
            offset,
            id: frame.id,
            written: frame.written,
            root,
        })
    }
}
