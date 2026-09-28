# evtx

A Windows Event Log (`.evtx`) parser, written from the format up: file and chunk headers, checksums, BinXML, templates, substitutions and every value type found in real logs.

```toml
[dependencies]
sootmark-evtx = "0.1"
```

```rust
let bytes = std::fs::read("Security.evtx")?;
let file = sootmark_evtx::EvtxFile::new(&bytes)?;
for chunk in file.chunks() {
    for record in chunk?.records() {
        match record {
            Ok(record) => {
                let system = record.system();
                println!("{} {:?} {:?}", record.id, system.event_id, system.time_created);
            }
            Err(damaged) => eprintln!("skipped record at {}: {}", damaged.offset, damaged.error),
        }
    }
}
```

## What you get

- `EvtxFile` → `chunks()` → `records()`: each `Record` has its file offset, record id, written time and a typed element tree.
- `record.system()`: provider, event id, level, `TimeCreated`, record id, process/thread id, channel, computer, user SID.
- `record.data()`: `<EventData>` items or the `<UserData>` payload.
- `record.to_xml()`: the event as XML, the way Event Viewer shows it.
- Typed values: integers, hex integers, GUIDs (`{…}` like Windows), SIDs, FILETIMEs (100 ns, lossless), SYSTEMTIMEs, binary, string arrays, embedded XML.

## Damage is contained

Evidence is hostile. A corrupt record is reported with its offset and skipped; a corrupt chunk doesn't stop the next one; chunks are found by walking the file, not by trusting a dirty header's chunk count. Checksums are reported, not enforced.

## Verification

| Check | Result |
|---|---|
| Record counts on real Windows 10 logs (Security, System, Application, Setup, empty) | exact match with known counts, 0 damaged records |
| Differential test against the independent `evtx` crate, field by field, 14,041 records | 0 mismatches in System fields and EventData (after normalising documented formatting differences: GUID braces, trailing padding, 100 ns vs µs) |
| Random bytes behind valid signatures, and randomly corrupted real chunks | no panic (20,000 corrupted chunks in a long run; 256 per CI run) |
| Throughput (one thread, release) | 55–255 MiB/s depending on template density |

The real logs come from a training image and are not redistributable. Put local copies in `tests/fixtures/` to run those suites; without them they are skipped.

## Quality

`#![forbid(unsafe_code)]`, `clippy::pedantic` clean, `cargo-deny` (permissive licences, no network crates). Nesting of elements, templates and embedded XML is capped, and every size read from the file is bounds-checked.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
