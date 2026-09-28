//! Real Windows 10 event logs (not redistributable, git-ignored). Tests skip
//! when a fixture is absent. Expected counts come from the fixture README of
//! the earlier evtx-parser project, produced by an independent parser.

use std::path::PathBuf;

use evtx::EvtxFile;

struct Summary {
    records: usize,
    damaged: usize,
    bad_chunks: usize,
}

fn fixture(name: &str) -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(path).ok()
}

fn summarize(bytes: &[u8]) -> Summary {
    let file = EvtxFile::new(bytes).expect("a valid file header");
    let mut summary = Summary {
        records: 0,
        damaged: 0,
        bad_chunks: 0,
    };
    for chunk in file.chunks() {
        let Ok(chunk) = chunk else {
            summary.bad_chunks += 1;
            continue;
        };
        for record in chunk.records() {
            match record {
                Ok(_) => summary.records += 1,
                Err(damaged) => {
                    eprintln!("damaged record at {}: {}", damaged.offset, damaged.error);
                    summary.damaged += 1;
                }
            }
        }
    }
    summary
}

fn assert_counts(name: &str, expected_records: usize) {
    let Some(bytes) = fixture(name) else {
        eprintln!("skipping: tests/fixtures/{name} not present");
        return;
    };
    let summary = summarize(&bytes);
    assert_eq!(summary.bad_chunks, 0, "{name}: bad chunks");
    assert_eq!(summary.damaged, 0, "{name}: damaged records");
    assert_eq!(summary.records, expected_records, "{name}: record count");
}

#[test]
fn security_log() {
    assert_counts("security.evtx", 10_667);
}

#[test]
fn application_log() {
    assert_counts("application.evtx", 1_934);
}

#[test]
fn system_log() {
    assert_counts("system.evtx", 1_416);
}

#[test]
fn setup_log() {
    assert_counts("setup.evtx", 24);
}

#[test]
fn empty_log() {
    assert_counts("hardware-events.evtx", 0);
}

#[test]
fn checksums_written_by_windows_validate() {
    let Some(bytes) = fixture("system.evtx") else { return };
    let file = EvtxFile::new(&bytes).unwrap();
    assert!(file.header().checksum_valid, "file header CRC-32");
    for chunk in file.chunks() {
        let chunk = chunk.unwrap();
        assert!(chunk.header().header_checksum_valid, "chunk header CRC-32 at {}", chunk.offset());
        assert!(chunk.header().records_checksum_valid, "records CRC-32 at {}", chunk.offset());
    }
}
