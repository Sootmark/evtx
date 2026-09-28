//! Errors, located by absolute file offset.

use core::fmt;

/// A parsing failure at a known file offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// Absolute offset in the `.evtx` file.
    pub offset: u64,
    /// What went wrong.
    pub kind: ErrorKind,
}

/// The kind of parsing failure. New kinds may be added.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The file doesn't start with `ElfFile\0`.
    NotEvtx,
    /// A chunk doesn't start with `ElfChnk\0`.
    BadChunkSignature,
    /// A record doesn't start with `**\0\0`.
    BadRecordSignature,
    /// A record's size is impossible or disagrees with its trailing copy.
    BadRecordSize(u32),
    /// Data ended early or a size read from the file was out of range.
    Read(common::bytes::ErrorKind),
    /// An unknown BinXML token.
    UnknownToken(u8),
    /// An unknown value type.
    UnknownValueType(u8),
    /// Elements, templates or embedded XML nested deeper than allowed.
    TooDeep,
    /// A record contains no root element.
    NoRootElement,
    /// The file ends inside a chunk: this many bytes of it are present.
    TruncatedChunk(usize),
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEvtx => f.write_str("not an EVTX file (bad file signature)"),
            Self::BadChunkSignature => f.write_str("bad chunk signature"),
            Self::BadRecordSignature => f.write_str("bad record signature"),
            Self::BadRecordSize(size) => write!(f, "impossible record size {size}"),
            Self::Read(read) => f.write_str(&describe_read(read)),
            Self::UnknownToken(token) => write!(f, "unknown BinXML token 0x{token:02x}"),
            Self::UnknownValueType(ty) => write!(f, "unknown value type 0x{ty:02x}"),
            Self::TooDeep => f.write_str("nesting too deep"),
            Self::NoRootElement => f.write_str("record has no root element"),
            Self::TruncatedChunk(length) => write!(
                f,
                "file ends inside a chunk ({length} of 65536 bytes present)"
            ),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at offset {}", self.kind, self.offset)
    }
}

impl std::error::Error for Error {}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    pub(crate) const fn new(offset: u64, kind: ErrorKind) -> Self {
        Self { offset, kind }
    }

    /// Convert a reader error from a buffer that starts at `base` in the file.
    pub(crate) fn from_read(base: u64, error: &common::bytes::Error) -> Self {
        Self::new(
            base + error.offset as u64,
            ErrorKind::Read(error.kind.clone()),
        )
    }
}

fn describe_read(kind: &common::bytes::ErrorKind) -> String {
    use common::bytes::ErrorKind as Read;
    match kind {
        Read::UnexpectedEof { needed, available } => {
            format!("unexpected end of data (needed {needed} bytes, {available} available)")
        }
        Read::LimitExceeded { requested, limit } => {
            format!("size {requested} exceeds the limit of {limit}")
        }
        Read::Invalid { expected } => format!("invalid data (expected {expected})"),
        Read::OutOfBounds { position, len } => {
            format!("position {position} outside a {len}-byte buffer")
        }
    }
}
