//! Hostile input: the parser must report damage, never panic.

use evtx::{ErrorKind, EvtxFile, CHUNK_SIZE, FILE_HEADER_SIZE};
use proptest::prelude::*;

/// Parse everything; count what comes out. Panics are the only failure.
fn parse_all(bytes: &[u8]) -> (usize, usize) {
    let Ok(file) = EvtxFile::new(bytes) else {
        return (0, 0);
    };
    let (mut records, mut damaged) = (0, 0);
    for chunk in file.chunks().flatten() {
        for record in chunk.records() {
            if let Ok(record) = record {
                records += 1;
                let _ = (record.to_xml(), record.system(), record.data());
            } else {
                damaged += 1;
            }
        }
    }
    (records, damaged)
}

fn file_with_one_chunk(chunk_body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; FILE_HEADER_SIZE + CHUNK_SIZE];
    bytes[..8].copy_from_slice(b"ElfFile\0");
    let chunk = &mut bytes[FILE_HEADER_SIZE..];
    chunk[..8].copy_from_slice(b"ElfChnk\0");
    let n = chunk_body.len().min(CHUNK_SIZE - 8);
    chunk[8..8 + n].copy_from_slice(&chunk_body[..n]);
    bytes
}

fn real_log() -> Option<Vec<u8>> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/security.evtx"
    ))
    .ok()
}

#[test]
fn rejects_non_evtx_files() {
    let error = EvtxFile::new(b"MZ\x90\x00 definitely not a log").unwrap_err();
    assert_eq!(error.kind, ErrorKind::NotEvtx);
    assert!(EvtxFile::new(b"ElfFile\0").is_err(), "truncated header");
}

#[test]
fn a_bad_chunk_does_not_stop_the_file() {
    let mut bytes = file_with_one_chunk(&[]);
    bytes.extend(std::iter::repeat(0xAB).take(CHUNK_SIZE)); // garbage second chunk
    let file = EvtxFile::new(&bytes).unwrap();
    let chunks: Vec<_> = file.chunks().collect();
    assert_eq!(chunks.len(), 2);
    assert!(chunks[0].is_ok());
    assert_eq!(
        chunks[1].as_ref().unwrap_err().kind,
        ErrorKind::BadChunkSignature
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn random_chunk_bodies_never_panic(body in proptest::collection::vec(any::<u8>(), 0..2_048)) {
        parse_all(&file_with_one_chunk(&body));
    }

    #[test]
    fn corrupted_real_chunks_never_panic(
        flips in proptest::collection::vec((0..CHUNK_SIZE, any::<u8>()), 1..40),
    ) {
        let Some(log) = real_log() else { return Ok(()) };
        let mut bytes = log[..FILE_HEADER_SIZE + CHUNK_SIZE].to_vec();
        for (at, value) in flips {
            bytes[FILE_HEADER_SIZE + at] = value;
        }
        parse_all(&bytes);
    }
}
