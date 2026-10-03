//! Every record of openly licensed logs against omerbenamram's `evtx_dump`
//! (its output in `tests/oracle/*.tsv.zlib`, written by
//! `tests/oracle/generate.py`): record id, event id, time created to the
//! microsecond, provider, channel and computer.
//!
//! - `cc0`: [EVTX-to-MITRE-Attack] (CC0-1.0), 293 logs of attacks on
//!   Windows 10 and Windows Server. Twenty of them, one per channel, are in
//!   `tests/fixtures/cc0/`; set `SOOTMARK_EVTX_CC0` to the whole set.
//! - `omer`: the samples of [omerbenamram/evtx] (MIT or Apache-2.0):
//!   dirty, damaged and forwarded logs among them. Set
//!   `SOOTMARK_EVTX_SAMPLES` to its `samples/` folder.
//!
//! CI downloads both sets at the commits `.github/workflows/ci.yml` names.
//!
//! [EVTX-to-MITRE-Attack]: https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack
//! [omerbenamram/evtx]: https://github.com/omerbenamram/evtx

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sootmark_evtx::EvtxFile;

/// Records `evtx_dump` reads and this crate reports as damaged.
const DAMAGED_HERE: &[(&str, &str)] = &[
    // Slack rendered as an event by evtx_dump: record id 0, no provider,
    // a SID of revision 0.
    ("Microsoft-Windows-HelloForBusiness%4Operational.evtx", "0"),
];

/// Expected records of `set`, by file: one line of System fields each.
fn expected(set: &str) -> BTreeMap<String, Vec<String>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/oracle/{set}.tsv.zlib"));
    let tsv = common::deflate::zlib_decompress(&std::fs::read(path).unwrap(), 64 << 20).unwrap();
    let mut files: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in String::from_utf8(tsv).unwrap().lines() {
        let (file, fields) = line.split_once('\t').unwrap();
        let lines = files.entry(file.to_owned()).or_default();
        let record_id = fields.split('\t').next().unwrap();
        let damaged_here = DAMAGED_HERE.contains(&(file, record_id));
        if record_id != "#errors" && !damaged_here {
            lines.push(fields.to_owned());
        }
    }
    files
}

/// This crate's records of the log at `path`, as `expected` lines.
fn ours(path: &Path) -> Vec<String> {
    let bytes = std::fs::read(path).unwrap();
    let file = EvtxFile::new(&bytes).unwrap();
    let text = |value: Option<String>| value.unwrap_or_default().replace(['\t', '\n', '\r'], " ");
    let number = |value: Option<u64>| value.map_or(String::new(), |v| v.to_string());
    let mut lines = Vec::new();
    for chunk in file.chunks().flatten() {
        for record in chunk.records().flatten() {
            let system = record.system();
            let time = system
                .time_created
                .and_then(|t| t.to_iso8601())
                .map(|t| format!("{}Z", &t[..26]))
                .unwrap_or_default();
            lines.push(
                [
                    number(system.record_id),
                    number(system.event_id.map(u64::from)),
                    time,
                    text(system.provider),
                    text(system.channel),
                    text(system.computer),
                ]
                .join("\t"),
            );
        }
    }
    lines
}

/// Check the logs of `set` found under `root` (all of them when `whole`);
/// how many were checked and their records.
fn check(set: &str, root: &Path, whole: bool) -> (usize, usize) {
    let (mut files, mut records) = (0, 0);
    for (name, expected) in expected(set) {
        let path: PathBuf = root.join(&name);
        if !path.exists() {
            assert!(!whole, "{set}: {name} missing from {}", root.display());
            continue;
        }
        let ours = ours(&path);
        if let Some(i) =
            (0..expected.len().max(ours.len())).find(|&i| ours.get(i) != expected.get(i))
        {
            panic!(
                "{set}: {name}, record {i} of {} (evtx_dump) vs {} (here):\n  evtx_dump: {:?}\n  here:      {:?}",
                expected.len(),
                ours.len(),
                expected.get(i),
                ours.get(i)
            );
        }
        files += 1;
        records += ours.len();
    }
    (files, records)
}

#[test]
fn vendored_cc0_logs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cc0");
    let (files, records) = check("cc0", &root, false);
    assert_eq!((files, records), (20, 284));
}

#[test]
fn every_cc0_log() {
    let Some(root) = std::env::var_os("SOOTMARK_EVTX_CC0") else {
        eprintln!("skipped: set SOOTMARK_EVTX_CC0 to EVTX-to-MITRE-Attack");
        return;
    };
    let (files, records) = check("cc0", Path::new(&root), true);
    assert_eq!((files, records), (293, 12_812));
}

#[test]
fn every_evtx_sample() {
    let Some(root) = std::env::var_os("SOOTMARK_EVTX_SAMPLES") else {
        eprintln!("skipped: set SOOTMARK_EVTX_SAMPLES to omerbenamram/evtx's samples");
        return;
    };
    let (files, records) = check("omer", Path::new(&root), true);
    assert_eq!((files, records), (27, 102_120));
}
