//! The BinXML token stream: elements, attributes, names, templates and
//! substitutions.
//!
//! Offsets inside BinXML (names, template definitions) are relative to the
//! start of the chunk, so the parser always reads through the whole chunk
//! buffer, bounded by the end of the record being parsed.

use std::collections::HashMap;

use common::bytes::{self, Reader};
use common::text;

use crate::error::{Error, ErrorKind, Result};
use crate::tree::{Attribute, Element, Node};
use crate::value::{self, Value, ValueError, ValueType};

/// Maximum nesting of elements, templates and embedded XML.
const MAX_DEPTH: u8 = 64;
/// Maximum substitutions in one template instance.
const MAX_SUBSTITUTIONS: u64 = 4_096;
/// Bytes before a template body: next offset (4), GUID (16), data size (4).
const TEMPLATE_HEADER_SIZE: usize = 24;
/// Offset of the data size inside a template definition header.
const TEMPLATE_SIZE_OFFSET: usize = 20;
/// Bytes of a name structure besides its characters: next offset (4),
/// hash (2), character count (2), terminating NUL (2).
const NAME_OVERHEAD: usize = 10;

/// Set on tokens that are followed by more of the same kind (attributes)
/// or that carry attributes (start elements).
const MORE_FLAG: u8 = 0x40;

mod token {
    pub const END_OF_STREAM: u8 = 0x00;
    pub const OPEN_START_ELEMENT: u8 = 0x01;
    pub const CLOSE_START_ELEMENT: u8 = 0x02;
    pub const CLOSE_EMPTY_ELEMENT: u8 = 0x03;
    pub const END_ELEMENT: u8 = 0x04;
    pub const VALUE: u8 = 0x05;
    pub const ATTRIBUTE: u8 = 0x06;
    pub const CDATA: u8 = 0x07;
    pub const CHAR_REF: u8 = 0x08;
    pub const ENTITY_REF: u8 = 0x09;
    pub const PI_TARGET: u8 = 0x0a;
    pub const PI_DATA: u8 = 0x0b;
    pub const TEMPLATE_INSTANCE: u8 = 0x0c;
    pub const NORMAL_SUBSTITUTION: u8 = 0x0d;
    pub const OPTIONAL_SUBSTITUTION: u8 = 0x0e;
    pub const FRAGMENT_HEADER: u8 = 0x0f;
}

/// Size of a fragment header after its token: major, minor, flags.
const FRAGMENT_HEADER_SIZE: usize = 3;

/// Where the parser is in the document.
#[derive(Clone, Copy)]
struct Context<'v> {
    depth: u8,
    /// Values of the enclosing template instance.
    substitutions: Option<&'v [Value]>,
    /// Inside an embedded BinXML value, where start elements have no
    /// dependency identifier.
    in_embedded_value: bool,
}

impl Context<'_> {
    const fn root() -> Self {
        Self {
            depth: 0,
            substitutions: None,
            in_embedded_value: false,
        }
    }

    fn deeper(self, at: u64) -> Result<Self> {
        if self.depth >= MAX_DEPTH {
            return Err(Error::new(at, ErrorKind::TooDeep));
        }
        Ok(Self {
            depth: self.depth + 1,
            ..self
        })
    }
}

/// Parses BinXML inside one chunk, caching the chunk's names.
pub(crate) struct Parser<'c> {
    chunk: &'c [u8],
    /// File offset of the chunk, for error locations.
    base: u64,
    /// Names by chunk offset, with their size in bytes.
    names: HashMap<usize, Name>,
}

#[derive(Clone)]
struct Name {
    text: String,
    /// Bytes the name structure occupies in the chunk.
    size: usize,
}

impl<'c> Parser<'c> {
    pub(crate) fn new(chunk: &'c [u8], base: u64) -> Self {
        Self {
            chunk,
            base,
            names: HashMap::new(),
        }
    }

    /// Parse the BinXML of a record occupying `start..end` of the chunk.
    pub(crate) fn record(&mut self, start: usize, end: usize) -> Result<Vec<Node>> {
        let mut r = self.reader(start, end)?;
        self.fragment(&mut r, Context::root())
    }

    fn reader(&self, start: usize, end: usize) -> Result<Reader<'c>> {
        let bounded = self
            .chunk
            .get(..end)
            .ok_or_else(|| self.out_of_chunk(end))?;
        let mut r = Reader::new(bounded);
        r.seek(start).map_err(|e| self.read_error(&e))?;
        Ok(r)
    }

    fn fragment(&mut self, r: &mut Reader<'c>, ctx: Context<'_>) -> Result<Vec<Node>> {
        let mut nodes = Vec::new();
        while r.remaining() > 0 {
            let at = self.at(r);
            match self.u8(r)? {
                token::END_OF_STREAM => break,
                token::FRAGMENT_HEADER => self.skip(r, FRAGMENT_HEADER_SIZE)?,
                token::TEMPLATE_INSTANCE => nodes.extend(self.template_instance(r, ctx)?),
                t if t & !MORE_FLAG == token::OPEN_START_ELEMENT => {
                    nodes.push(Node::Element(self.element(r, t, ctx)?));
                }
                other => return Err(Error::new(at, ErrorKind::UnknownToken(other))),
            }
        }
        Ok(nodes)
    }

    fn element(&mut self, r: &mut Reader<'c>, token: u8, ctx: Context<'_>) -> Result<Element> {
        let ctx = ctx.deeper(self.at(r))?;
        if !ctx.in_embedded_value {
            self.u16(r)?; // dependency identifier
        }
        self.u32(r)?; // data size
        let name = self.name(r)?;
        let attributes = if token & MORE_FLAG == 0 {
            Vec::new()
        } else {
            self.attributes(r, ctx)?
        };
        let at = self.at(r);
        let children = match self.u8(r)? {
            token::CLOSE_START_ELEMENT => self.content(r, ctx)?,
            token::CLOSE_EMPTY_ELEMENT => Vec::new(),
            other => return Err(Error::new(at, ErrorKind::UnknownToken(other))),
        };
        Ok(Element {
            name,
            attributes,
            children,
        })
    }

    fn attributes(&mut self, r: &mut Reader<'c>, ctx: Context<'_>) -> Result<Vec<Attribute>> {
        self.u32(r)?; // attribute list size
        let mut attributes = Vec::new();
        loop {
            let at = self.at(r);
            let token = self.u8(r)?;
            if token & !MORE_FLAG != token::ATTRIBUTE {
                return Err(Error::new(at, ErrorKind::UnknownToken(token)));
            }
            let name = self.name(r)?;
            if let Some(value) = self.attribute_value(r, ctx)? {
                attributes.push(Attribute { name, value });
            }
            if token & MORE_FLAG == 0 {
                return Ok(attributes);
            }
        }
    }

    /// The value parts of an attribute, or `None` when an optional
    /// substitution removed it.
    fn attribute_value(
        &mut self,
        r: &mut Reader<'c>,
        ctx: Context<'_>,
    ) -> Result<Option<Vec<Node>>> {
        let mut parts = Vec::new();
        let mut removed = false;
        while let Some(&next) = r.peek(1).ok().and_then(|b| b.first()) {
            let base = next & !MORE_FLAG;
            let is_value_part = matches!(
                base,
                token::VALUE
                    | token::NORMAL_SUBSTITUTION
                    | token::OPTIONAL_SUBSTITUTION
                    | token::CHAR_REF
                    | token::ENTITY_REF
            );
            if !is_value_part {
                break;
            }
            match self.content_part(r, ctx)? {
                Some(nodes) => parts.extend(nodes),
                None => removed = true,
            }
        }
        Ok((!removed || !parts.is_empty()).then_some(parts))
    }

    /// Children of an element, up to its end token.
    fn content(&mut self, r: &mut Reader<'c>, ctx: Context<'_>) -> Result<Vec<Node>> {
        let mut children = Vec::new();
        loop {
            let at = self.at(r);
            let token = self.peek_u8(r)?;
            match token & !MORE_FLAG {
                token::END_ELEMENT => {
                    self.u8(r)?;
                    return Ok(children);
                }
                token::OPEN_START_ELEMENT => {
                    self.u8(r)?;
                    children.push(Node::Element(self.element(r, token, ctx)?));
                }
                token::TEMPLATE_INSTANCE => {
                    self.u8(r)?;
                    children.extend(self.template_instance(r, ctx)?);
                }
                token::PI_TARGET => {
                    self.u8(r)?;
                    children.push(self.processing_instruction(r)?);
                }
                token::VALUE
                | token::NORMAL_SUBSTITUTION
                | token::OPTIONAL_SUBSTITUTION
                | token::CDATA
                | token::CHAR_REF
                | token::ENTITY_REF => {
                    children.extend(self.content_part(r, ctx)?.unwrap_or_default());
                }
                _ => return Err(Error::new(at, ErrorKind::UnknownToken(token))),
            }
        }
    }

    /// One text-like part: a value, substitution, CDATA or reference.
    /// `None` means an optional substitution that resolved to nothing.
    fn content_part(&mut self, r: &mut Reader<'c>, ctx: Context<'_>) -> Result<Option<Vec<Node>>> {
        let at = self.at(r);
        let token = self.u8(r)?;
        let node = match token & !MORE_FLAG {
            token::VALUE => {
                self.u8(r)?; // value type: always a UTF-16 string here
                Node::Value(Value::String(self.counted_utf16(r)?))
            }
            token::CDATA => Node::CData(self.counted_utf16(r)?),
            token::CHAR_REF => Node::CharRef(self.u16(r)?),
            token::ENTITY_REF => Node::EntityRef(self.name(r)?),
            token::NORMAL_SUBSTITUTION => return self.substitution(r, ctx, false),
            token::OPTIONAL_SUBSTITUTION => return self.substitution(r, ctx, true),
            other => return Err(Error::new(at, ErrorKind::UnknownToken(other))),
        };
        Ok(Some(vec![node]))
    }

    fn substitution(
        &mut self,
        r: &mut Reader<'c>,
        ctx: Context<'_>,
        optional: bool,
    ) -> Result<Option<Vec<Node>>> {
        let at = self.at(r);
        let index = usize::from(self.u16(r)?);
        self.u8(r)?; // declared type; the substitution array carries the real one
        let value = ctx
            .substitutions
            .and_then(|values| values.get(index))
            .ok_or_else(|| invalid(at, "a substitution index inside the template's value array"))?;
        Ok(match value {
            Value::Null if optional => None,
            Value::Xml(nodes) => Some(nodes.clone()),
            other => Some(vec![Node::Value(other.clone())]),
        })
    }

    fn template_instance(&mut self, r: &mut Reader<'c>, ctx: Context<'_>) -> Result<Vec<Node>> {
        let ctx = ctx.deeper(self.at(r))?;
        self.u8(r)?; // unknown
        self.u32(r)?; // template identifier
        let definition = self.u32(r)? as usize;
        if definition == r.position() {
            self.skip_inline_template(r)?;
        }
        let values = self.substitution_values(r, ctx)?;
        let (start, end) = self.template_body(definition)?;
        let mut body = self.reader(start, end)?;
        let body_ctx = Context {
            substitutions: Some(&values),
            in_embedded_value: false,
            ..ctx
        };
        self.fragment(&mut body, body_ctx)
    }

    fn skip_inline_template(&self, r: &mut Reader<'c>) -> Result<()> {
        self.skip(r, TEMPLATE_SIZE_OFFSET)?;
        let size = self.u32(r)? as usize;
        self.skip(r, size)
    }

    /// Start and end (chunk offsets) of the template body defined at `definition`.
    fn template_body(&self, definition: usize) -> Result<(usize, usize)> {
        let mut header = self.reader(definition, self.chunk.len())?;
        self.skip(&mut header, TEMPLATE_SIZE_OFFSET)?;
        let size = self.u32(&mut header)? as usize;
        let start = definition + TEMPLATE_HEADER_SIZE;
        let end = start
            .checked_add(size)
            .filter(|&end| end <= self.chunk.len())
            .ok_or_else(|| self.out_of_chunk(start))?;
        Ok((start, end))
    }

    fn substitution_values(&mut self, r: &mut Reader<'c>, ctx: Context<'_>) -> Result<Vec<Value>> {
        let at = self.at(r);
        let count = bytes::checked_count(
            u64::from(self.u32(r)?),
            4,
            MAX_SUBSTITUTIONS,
            r.remaining(),
            r.position(),
        )
        .map_err(|e| self.read_error(&e))?;
        let mut descriptors = Vec::with_capacity(count);
        for _ in 0..count {
            let size = usize::from(self.u16(r)?);
            let ty = self.u8(r)?;
            self.u8(r)?; // padding
            descriptors.push((size, ty));
        }
        let mut values = Vec::with_capacity(count);
        for (size, type_byte) in descriptors {
            let start = r.position();
            let bytes = r.bytes(size).map_err(|e| self.read_error(&e))?;
            let (ty, is_array) = ValueType::from_byte(type_byte)
                .ok_or(Error::new(at, ErrorKind::UnknownValueType(type_byte)))?;
            let value = match value::decode(ty, is_array, bytes) {
                Ok(value) => value,
                Err(ValueError::EmbeddedXml) => {
                    Value::Xml(self.embedded_xml(start, start + size, ctx)?)
                }
                Err(ValueError::Read(e)) => {
                    return Err(Error::from_read(self.base + start as u64, &e))
                }
                Err(ValueError::UnsupportedArray) => {
                    return Err(Error::new(
                        self.base + start as u64,
                        ErrorKind::UnknownValueType(type_byte),
                    ))
                }
            };
            values.push(value);
        }
        Ok(values)
    }

    fn embedded_xml(&mut self, start: usize, end: usize, ctx: Context<'_>) -> Result<Vec<Node>> {
        let mut r = self.reader(start, end)?;
        let ctx = Context {
            in_embedded_value: true,
            substitutions: None,
            ..ctx.deeper(self.base + start as u64)?
        };
        self.fragment(&mut r, ctx)
    }

    fn processing_instruction(&mut self, r: &mut Reader<'c>) -> Result<Node> {
        let target = self.name(r)?;
        let at = self.at(r);
        if self.u8(r)? != token::PI_DATA {
            return Err(invalid(at, "processing instruction data"));
        }
        let data = self.counted_utf16(r)?;
        Ok(Node::ProcessingInstruction { target, data })
    }

    /// A name reference; the name itself may be defined inline, right here.
    fn name(&mut self, r: &mut Reader<'c>) -> Result<String> {
        let offset = self.u32(r)? as usize;
        let name = self.name_at(offset)?;
        if offset == r.position() {
            self.skip(r, name.size)?;
        }
        Ok(name.text)
    }

    fn name_at(&mut self, offset: usize) -> Result<Name> {
        if let Some(name) = self.names.get(&offset) {
            return Ok(name.clone());
        }
        let mut r = self.reader(offset, self.chunk.len())?;
        self.skip(&mut r, 6)?; // next offset, hash
        let units = usize::from(self.peek_u16(&r)?);
        let name = Name {
            text: self.counted_utf16(&mut r)?,
            size: NAME_OVERHEAD + units * 2,
        };
        self.names.insert(offset, name.clone());
        Ok(name)
    }

    /// A u16 character count followed by that many UTF-16 code units.
    fn counted_utf16(&self, r: &mut Reader<'c>) -> Result<String> {
        let count = usize::from(self.u16(r)?);
        let bytes = r.bytes(count * 2).map_err(|e| self.read_error(&e))?;
        Ok(text::utf16le(bytes).text)
    }

    fn at(&self, r: &Reader<'_>) -> u64 {
        self.base + r.position() as u64
    }

    fn u8(&self, r: &mut Reader<'c>) -> Result<u8> {
        r.u8().map_err(|e| self.read_error(&e))
    }

    fn peek_u8(&self, r: &Reader<'c>) -> Result<u8> {
        r.peek(1).map(|b| b[0]).map_err(|e| self.read_error(&e))
    }

    fn peek_u16(&self, r: &Reader<'c>) -> Result<u16> {
        r.peek(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .map_err(|e| self.read_error(&e))
    }

    fn u16(&self, r: &mut Reader<'c>) -> Result<u16> {
        r.u16_le().map_err(|e| self.read_error(&e))
    }

    fn u32(&self, r: &mut Reader<'c>) -> Result<u32> {
        r.u32_le().map_err(|e| self.read_error(&e))
    }

    fn skip(&self, r: &mut Reader<'c>, n: usize) -> Result<()> {
        r.skip(n).map_err(|e| self.read_error(&e))
    }

    fn read_error(&self, error: &bytes::Error) -> Error {
        Error::from_read(self.base, error)
    }

    fn out_of_chunk(&self, position: usize) -> Error {
        Error::new(
            self.base,
            ErrorKind::Read(bytes::ErrorKind::OutOfBounds {
                position,
                len: self.chunk.len(),
            }),
        )
    }
}

fn invalid(at: u64, expected: &'static str) -> Error {
    Error::new(at, ErrorKind::Read(bytes::ErrorKind::Invalid { expected }))
}
