//! Count records in `.evtx` files: `cargo run --release --example count -- <files>`.

use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for path in std::env::args().skip(1) {
        let bytes = std::fs::read(&path)?;
        let started = Instant::now();
        let file = sootmark_evtx::EvtxFile::new(&bytes)?;
        let (mut records, mut damaged) = (0usize, 0usize);
        for chunk in file.chunks() {
            for record in chunk?.records() {
                if record.is_ok() {
                    records += 1;
                } else {
                    damaged += 1;
                }
            }
        }
        let elapsed = started.elapsed();
        let mb = bytes.len() as f64 / 1_048_576.0;
        println!("{path}: {records} records, {damaged} damaged, {mb:.1} MiB in {elapsed:.2?} ({:.0} MiB/s)", mb / elapsed.as_secs_f64());
    }
    Ok(())
}
