//! Typed BinXML values.

use core::fmt;

use common::bytes::Reader;
use common::text;
use common::time::Ts;
use common::win;

use crate::tree::Node;

/// Flag bit marking an array of the base type.
const ARRAY_FLAG: u8 = 0x80;

/// A BinXML value type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueType {
    Null,
    String,
    AnsiString,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Real32,
    Real64,
    Bool,
    Binary,
    Guid,
    SizeT,
    FileTime,
    SystemTime,
    Sid,
    HexInt32,
    HexInt64,
    BinXml,
}

impl ValueType {
    /// Decode a type byte into its base type and whether it's an array.
    pub(crate) fn from_byte(byte: u8) -> Option<(Self, bool)> {
        let is_array = byte & ARRAY_FLAG != 0;
        let base = match byte & !ARRAY_FLAG {
            0x00 => Self::Null,
            0x01 => Self::String,
            0x02 => Self::AnsiString,
            0x03 => Self::Int8,
            0x04 => Self::UInt8,
            0x05 => Self::Int16,
            0x06 => Self::UInt16,
            0x07 => Self::Int32,
            0x08 => Self::UInt32,
            0x09 => Self::Int64,
            0x0a => Self::UInt64,
            0x0b => Self::Real32,
            0x0c => Self::Real64,
            0x0d => Self::Bool,
            0x0e => Self::Binary,
            0x0f => Self::Guid,
            0x10 => Self::SizeT,
            0x11 => Self::FileTime,
            0x12 => Self::SystemTime,
            0x13 => Self::Sid,
            0x14 => Self::HexInt32,
            0x15 => Self::HexInt64,
            0x21 => Self::BinXml,
            _ => return None,
        };
        Some((base, is_array))
    }

    /// Size of one element for fixed-size types.
    const fn fixed_size(self) -> Option<usize> {
        match self {
            Self::Int8 | Self::UInt8 => Some(1),
            Self::Int16 | Self::UInt16 => Some(2),
            Self::Int32 | Self::UInt32 | Self::Real32 | Self::Bool | Self::HexInt32 => Some(4),
            Self::Int64 | Self::UInt64 | Self::Real64 | Self::FileTime | Self::HexInt64 => Some(8),
            Self::Guid | Self::SystemTime => Some(16),
            _ => None,
        }
    }
}

/// A Windows `SYSTEMTIME`, kept as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemTime {
    /// Year.
    pub year: u16,
    /// Month, 1–12.
    pub month: u16,
    /// Day of week, 0 = Sunday.
    pub day_of_week: u16,
    /// Day of month, 1–31.
    pub day: u16,
    /// Hour, 0–23.
    pub hour: u16,
    /// Minute, 0–59.
    pub minute: u16,
    /// Second, 0–59.
    pub second: u16,
    /// Milliseconds, 0–999.
    pub milliseconds: u16,
}

impl fmt::Display for SystemTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.milliseconds
        )
    }
}

/// A typed value from a record.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// No value.
    Null,
    /// UTF-16 text (invalid code units escaped, see [`common::text`]).
    String(String),
    /// Single-byte text, decoded as Latin-1 so no byte is lost.
    AnsiString(String),
    /// Signed 8-bit integer.
    I8(i8),
    /// Unsigned 8-bit integer.
    U8(u8),
    /// Signed 16-bit integer.
    I16(i16),
    /// Unsigned 16-bit integer.
    U16(u16),
    /// Signed 32-bit integer.
    I32(i32),
    /// Unsigned 32-bit integer.
    U32(u32),
    /// Signed 64-bit integer.
    I64(i64),
    /// Unsigned 64-bit integer.
    U64(u64),
    /// 32-bit float.
    F32(f32),
    /// 64-bit float.
    F64(f64),
    /// Boolean.
    Bool(bool),
    /// Raw bytes.
    Binary(Vec<u8>),
    /// A GUID, as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
    Guid(String),
    /// A pointer-sized integer.
    SizeT(u64),
    /// A raw FILETIME; see [`Value::as_ts`].
    FileTime(u64),
    /// A `SYSTEMTIME`.
    SystemTime(SystemTime),
    /// A SID, as `S-1-…`.
    Sid(String),
    /// A 32-bit integer displayed in hex.
    HexInt32(u32),
    /// A 64-bit integer displayed in hex.
    HexInt64(u64),
    /// Embedded BinXML.
    Xml(Vec<Node>),
    /// An array of values.
    Array(Vec<Value>),
}

impl Value {
    /// The value as a timestamp, if it is one.
    #[must_use]
    pub fn as_ts(&self) -> Option<Ts> {
        match self {
            Self::FileTime(raw) => Some(Ts::from_filetime(*raw)),
            _ => None,
        }
    }
}

/// Why a value couldn't be decoded.
#[derive(Debug)]
pub(crate) enum ValueError {
    Read(common::bytes::Error),
    UnsupportedArray,
    /// Embedded BinXML needs the chunk context; the BinXML parser handles it.
    EmbeddedXml,
}

impl From<common::bytes::Error> for ValueError {
    fn from(error: common::bytes::Error) -> Self {
        Self::Read(error)
    }
}

/// Decode a non-BinXML value occupying all of `bytes`.
pub(crate) fn decode(ty: ValueType, is_array: bool, bytes: &[u8]) -> Result<Value, ValueError> {
    if !is_array {
        return decode_one(ty, bytes);
    }
    match (ty, ty.fixed_size()) {
        (ValueType::String, _) => Ok(Value::Array(split_utf16_strings(bytes))),
        (_, Some(size)) => bytes
            .chunks_exact(size)
            .map(|item| decode_one(ty, item))
            .collect::<Result<_, _>>()
            .map(Value::Array),
        _ => Err(ValueError::UnsupportedArray),
    }
}

fn decode_one(ty: ValueType, bytes: &[u8]) -> Result<Value, ValueError> {
    let mut r = Reader::new(bytes);
    Ok(match ty {
        ValueType::Null => Value::Null,
        ValueType::String => Value::String(trim_nuls(text::utf16le(bytes).text)),
        ValueType::AnsiString => {
            Value::AnsiString(trim_nuls(bytes.iter().map(|&b| char::from(b)).collect()))
        }
        ValueType::Int8 => Value::I8(r.u8()? as i8),
        ValueType::UInt8 => Value::U8(r.u8()?),
        ValueType::Int16 => Value::I16(r.i16_le()?),
        ValueType::UInt16 => Value::U16(r.u16_le()?),
        ValueType::Int32 => Value::I32(r.i32_le()?),
        ValueType::UInt32 => Value::U32(r.u32_le()?),
        ValueType::Int64 => Value::I64(r.i64_le()?),
        ValueType::UInt64 => Value::U64(r.u64_le()?),
        ValueType::Real32 => Value::F32(f32::from_bits(r.u32_le()?)),
        ValueType::Real64 => Value::F64(r.f64_le()?),
        ValueType::Bool => Value::Bool(r.u32_le()? != 0),
        ValueType::Binary => Value::Binary(bytes.to_vec()),
        ValueType::Guid => Value::Guid(format!("{{{}}}", win::read_guid(&mut r)?.to_uppercase())),
        ValueType::SizeT => Value::SizeT(if bytes.len() == 4 {
            u64::from(r.u32_le()?)
        } else {
            r.u64_le()?
        }),
        ValueType::FileTime => Value::FileTime(r.u64_le()?),
        ValueType::SystemTime => Value::SystemTime(read_system_time(&mut r)?),
        ValueType::Sid => Value::Sid(win::sid_to_string(bytes)?.0),
        ValueType::HexInt32 => Value::HexInt32(r.u32_le()?),
        ValueType::HexInt64 => Value::HexInt64(r.u64_le()?),
        ValueType::BinXml => return Err(ValueError::EmbeddedXml),
    })
}

fn read_system_time(r: &mut Reader<'_>) -> common::bytes::Result<SystemTime> {
    Ok(SystemTime {
        year: r.u16_le()?,
        month: r.u16_le()?,
        day_of_week: r.u16_le()?,
        day: r.u16_le()?,
        hour: r.u16_le()?,
        minute: r.u16_le()?,
        second: r.u16_le()?,
        milliseconds: r.u16_le()?,
    })
}

fn trim_nuls(mut s: String) -> String {
    s.truncate(s.trim_end_matches('\0').len());
    s
}

fn split_utf16_strings(bytes: &[u8]) -> Vec<Value> {
    let decoded = text::utf16le(bytes).text;
    let body = decoded.strip_suffix('\0').unwrap_or(&decoded);
    body.split('\0')
        .map(|s| Value::String(s.to_owned()))
        .collect()
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => Ok(()),
            Self::String(s) | Self::AnsiString(s) | Self::Guid(s) | Self::Sid(s) => f.write_str(s),
            Self::I8(n) => write!(f, "{n}"),
            Self::U8(n) => write!(f, "{n}"),
            Self::I16(n) => write!(f, "{n}"),
            Self::U16(n) => write!(f, "{n}"),
            Self::I32(n) => write!(f, "{n}"),
            Self::U32(n) => write!(f, "{n}"),
            Self::I64(n) => write!(f, "{n}"),
            Self::U64(n) | Self::SizeT(n) => write!(f, "{n}"),
            Self::F32(n) => write!(f, "{n}"),
            Self::F64(n) => write!(f, "{n}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Binary(bytes) => bytes.iter().try_for_each(|b| write!(f, "{b:02X}")),
            Self::FileTime(raw) => write!(f, "{}", Ts::from_filetime(*raw)),
            Self::SystemTime(st) => write!(f, "{st}"),
            Self::HexInt32(n) => write!(f, "0x{n:x}"),
            Self::HexInt64(n) => write!(f, "0x{n:x}"),
            Self::Xml(nodes) => f.write_str(&crate::xml::render_nodes(nodes)),
            Self::Array(items) => {
                let parts: Vec<String> = items.iter().map(ToString::to_string).collect();
                f.write_str(&parts.join(", "))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn decodes_type_bytes() {
        assert_eq!(ValueType::from_byte(0x01), Some((ValueType::String, false)));
        assert_eq!(ValueType::from_byte(0x81), Some((ValueType::String, true)));
        assert_eq!(ValueType::from_byte(0x21), Some((ValueType::BinXml, false)));
        assert_eq!(ValueType::from_byte(0x42), None);
    }

    #[test]
    fn strings_drop_trailing_nuls() {
        let value = decode(ValueType::String, false, &utf16("svchost.exe\0")).unwrap();
        assert_eq!(value, Value::String("svchost.exe".into()));
    }

    #[test]
    fn string_arrays_split_on_nul() {
        let value = decode(ValueType::String, true, &utf16("a\0bc\0")).unwrap();
        assert_eq!(value.to_string(), "a, bc");
    }

    #[test]
    fn integers_and_hex_render_like_event_viewer() {
        assert_eq!(
            decode(ValueType::HexInt32, false, &0xc000_006d_u32.to_le_bytes())
                .unwrap()
                .to_string(),
            "0xc000006d"
        );
        assert_eq!(
            decode(ValueType::UInt16, false, &4624u16.to_le_bytes())
                .unwrap()
                .to_string(),
            "4624"
        );
        assert_eq!(
            decode(ValueType::Bool, false, &1u32.to_le_bytes())
                .unwrap()
                .to_string(),
            "true"
        );
    }

    #[test]
    fn guids_are_braced_uppercase() {
        let bytes = [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let value = decode(ValueType::Guid, false, &bytes).unwrap();
        assert_eq!(value.to_string(), "{00112233-4455-6677-8899-AABBCCDDEEFF}");
    }

    #[test]
    fn filetimes_render_as_iso_and_convert_to_ts() {
        let value = decode(
            ValueType::FileTime,
            false,
            &125_911_584_000_000_000_u64.to_le_bytes(),
        )
        .unwrap();
        assert_eq!(value.to_string(), "2000-01-01T00:00:00.0000000Z");
        assert!(value.as_ts().is_some());
    }

    #[test]
    fn short_values_are_errors_not_panics() {
        assert!(decode(ValueType::UInt64, false, &[1, 2, 3]).is_err());
        assert!(decode(ValueType::Sid, false, &[1]).is_err());
    }
}
