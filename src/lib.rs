//! Windows Event Log (`.evtx`) parser.
//!
//! ```no_run
//! let bytes = std::fs::read("Security.evtx")?;
//! let file = evtx::EvtxFile::new(&bytes)?;
//! for chunk in file.chunks() {
//!     for record in chunk?.records() {
//!         match record {
//!             Ok(record) => println!("{} {:?}", record.id, record.system().event_id),
//!             Err(damaged) => eprintln!("skipped record at {}: {}", damaged.offset, damaged.error),
//!         }
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Damage is contained: a corrupt record is reported and skipped, a corrupt
//! chunk doesn't stop the next one, and hostile input never panics.

mod binxml;
mod chunk;
mod error;
mod file;
mod record;
mod tree;
mod value;
mod xml;

pub use chunk::{Chunk, ChunkHeader, DamagedRecord, Records, CHUNK_SIZE};
pub use error::{Error, ErrorKind, Result};
pub use file::{EvtxFile, FileHeader, FILE_HEADER_SIZE};
pub use record::{DataItem, Record, System};
pub use tree::{Attribute, Element, Node};
pub use value::{SystemTime, Value};
pub use xml::render as render_xml;
