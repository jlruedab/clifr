#!/usr/bin/env python3
"""Compare captured vmstat/iostat outputs with clifr's reconstruction:
the layout exactly (lines, words, the column where each word ends), the
numbers within a tolerance. Usage: bench/vmstatcompare.py CLIFR OUTDIR [STYLE [TZ]] (OUTDIR from
bench/vmstatcheck.sh; TZ: the captured host's zone, e.g. UTC in the test VMs)."""
import math, os, re, subprocess, sys
from datetime import datetime, timedelta

clifr, out = sys.argv[1], sys.argv[2]
style = sys.argv[3] if len(sys.argv) > 3 else ""
tz = sys.argv[4] if len(sys.argv) > 4 else ""
num = re.compile(r'^-?\d+(\.\d+)?$')

def words(line):
    return [(m.group(), m.end()) for m in re.finditer(r'\S+', line)]

total = bad_layout = 0
worst = []
n = 1
while os.path.exists(f"{out}/cmd-{n}.txt"):
    cmd = open(f"{out}/cmd-{n}.txt").read().strip()
    at = datetime.strptime(open(f"{out}/at-{n}.txt").read().strip(), "%Y-%m-%d %H:%M:%S.%f")
    at = (at + timedelta(seconds=1)).strftime("%Y-%m-%d %H:%M:%S")
    args = [clifr, "--plain", "--data-dir", f"{out}/rec", "--at", at]
    if style:
        args += ["--style", style]
    if tz:
        args += ["--tz", tz]
    r = subprocess.run(args + [cmd], capture_output=True, text=True)
    real = [l for l in open(f"{out}/out-{n}.txt").read().split("\n")]
    got = r.stdout.split("\n")
    n += 1
    # iostat's first line names the host, kernel and date: compare words only.
    msgs, maxd = [], 0.0
    if len(real) != len(got):
        msgs.append(f"{len(got)} lines, real {len(real)}")
    for i, (a, b) in enumerate(zip(real, got)):
        wa, wb = words(a), words(b)
        if len(wa) != len(wb):
            msgs.append(f"line {i+1}: {len(wb)} words, real {len(wa)}:\n    real  {a!r}\n    clifr {b!r}")
            continue
        for (x, ex), (y, ey) in zip(wa, wb):
            if num.match(x) and num.match(y):
                fx, fy = float(x), float(y)
                d = abs(fx - fy) / max(abs(fx), abs(fy), 1)
                if abs(fx - fy) > 1 and d > maxd:
                    maxd = d
                if ex != ey and i > 0:
                    msgs.append(f"line {i+1}: {x!r} ends at {ey}, real {ex}")
            elif x != y and not (i == 0 and cmd.startswith("iostat")):
                msgs.append(f"line {i+1}: {y!r}, real {x!r}")
    total += 1
    if msgs:
        bad_layout += 1
    print(f"{'DIFF' if msgs else 'same'}  {cmd:<16} values within {100*maxd:.1f}%" + ("" if not msgs else "\n  " + "\n  ".join(msgs[:6])))
    if r.returncode != 0:
        print("  clifr:", r.stderr.strip().split("\n")[-1])
print(f"{total - bad_layout} of {total} laid out the same")
