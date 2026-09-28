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

/// The kind of parsing failure.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match &self.kind {
            ErrorKind::NotEvtx => "not an EVTX file (bad file signature)".to_owned(),
            ErrorKind::BadChunkSignature => "bad chunk signature".to_owned(),
            ErrorKind::BadRecordSignature => "bad record signature".to_owned(),
            ErrorKind::BadRecordSize(size) => format!("impossible record size {size}"),
            ErrorKind::Read(read) => describe_read(read),
            ErrorKind::UnknownToken(token) => format!("unknown BinXML token 0x{token:02x}"),
            ErrorKind::UnknownValueType(ty) => format!("unknown value type 0x{ty:02x}"),
            ErrorKind::TooDeep => "nesting too deep".to_owned(),
            ErrorKind::NoRootElement => "record has no root element".to_owned(),
        };
        write!(f, "{what} at offset {}", self.offset)
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
