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
| Every record of 320 openly licensed logs against [omerbenamram/evtx](https://github.com/omerbenamram/evtx)'s `evtx_dump`: record id, event id, time created, provider, channel, computer | 114,932 records match; one more, slack that `evtx_dump` renders as an event (record id 0, invalid SID), is reported here as damaged |
| Random bytes behind valid signatures, and randomly corrupted chunks | no panic (256 per CI run) |

The logs: [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) (CC0-1.0, 293 logs of attacks on Windows 10 and Windows Server: Security, Sysmon, PowerShell, Defender, RDP, forwarded events, …; twenty of them in `tests/fixtures/cc0/`) and omerbenamram/evtx's samples (MIT or Apache-2.0: dirty, damaged and forwarded logs). `evtx_dump`'s output is in `tests/oracle/`, with the script that writes it; CI downloads both sets at pinned commits and runs `tests/open_samples.rs` on all of them.

## Quality

`#![forbid(unsafe_code)]`, `clippy::pedantic` clean, `cargo-deny` (permissive licences, no network crates). Nesting of elements, templates and embedded XML is capped, and every size read from the file is bounds-checked.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
