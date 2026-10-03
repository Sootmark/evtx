#!/usr/bin/env python3
"""Expected records for tests/open_samples.rs, from omerbenamram's evtx_dump.

    generate.py <evtx_dump> <root> > expected.tsv

Every `.evtx` under <root> (sorted by path) is dumped as JSON lines; each
record becomes one line of System fields:

    file  record_id  event_id  time  provider  channel  computer

`time` is TimeCreated to the microsecond: evtx_dump prints 6, 7 or 9
fractional digits, and only 6 are always right. A file's
records that evtx_dump could not read are counted on a `#errors` line.
"""

import json
import os
import subprocess
import sys


def field(value):
    """A value as one TSV field: text, numbers, or empty."""
    if value is None:
        return ""
    if isinstance(value, dict):
        return field(value.get("#text"))
    return str(value).replace("\t", " ").replace("\n", " ").replace("\r", " ")


def micros(time):
    """An ISO time with exactly 6 fractional digits."""
    if "." not in time:
        return time
    whole, fraction = time.rstrip("Z").split(".")
    return f"{whole}.{(fraction + '000000')[:6]}Z"


def main():
    dump, root = sys.argv[1], sys.argv[2]
    files = sorted(
        os.path.relpath(os.path.join(d, f), root)
        for d, _, names in os.walk(root)
        for f in names
        if f.lower().endswith(".evtx")
    )
    out = sys.stdout
    for name in files:
        run = subprocess.run(
            [dump, "-o", "jsonl", "-t", "1", os.path.join(root, name)],
            capture_output=True,
            check=False,
        )
        errors = sum(1 for line in run.stderr.decode(errors="replace").splitlines()
                     if line.startswith("Failed to dump the next record"))
        for line in run.stdout.decode(errors="replace").splitlines():
            system = json.loads(line)["Event"].get("System", {})
            attrs = lambda key: (system.get(key) or {}).get("#attributes", {})
            time = micros(attrs("TimeCreated").get("SystemTime", ""))
            out.write("\t".join([
                name,
                field(system.get("EventRecordID")),
                field(system.get("EventID")),
                time,
                field(attrs("Provider").get("Name")),
                field(system.get("Channel")),
                field(system.get("Computer")),
            ]) + "\n")
        out.write(f"{name}\t#errors\t{errors}\n")


main()
