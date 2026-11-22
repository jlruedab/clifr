# htop 3.0.5's screen: what clifr knows of it

htop 3.0.5 (Ubuntu 22.04) is GPL-2.0-only ("Released under the GNU GPLv2",
README "GPL-2.0"; htop moved to GPLv2+ in 3.1.1). Its source code was never
read for clifr: `internal/query/htop30.go` is written from this description,
which comes from its output only. Do not read htop 3.0.5's (or 3.1.0's or
earlier) code when changing it; describe new findings here from captures.

Captures (bench/results/htop-captures-20261122, as root, a fresh htoprc that
htop 3.0.5 wrote itself, `hide_userland_threads=1`, in tmux):

- `check-ubuntu2204/`: 200 and 80 columns, 300 lines, 4 CPUs; default, `-t`,
  `-s PERCENT_MEM`, `-u root`, `-p 1`, `-C`, with a clifrd recording.
- `c30-ubuntu2204-4cpu/`: widths 41, 60, 79, 80, 81, 120, 121, 200, 201
  under a two-thread CPU load (`xz -T2`), and a tree.
- `c30-ubuntu2204-{6,12,24,40}cpu/`: widths 80, 81, 200, 201, each with the
  htoprc htop wrote on that CPU count.
- `ubuntu2204/`: the default with user threads shown.

## Header

- The first and the last header lines are empty; the meters are in between.
  There is no screen tabs line: the column titles follow the empty line.
- Two columns: each `cw = (COLS - 4) / 2` wide (rounded down); the left one
  starts at column 2, the right one at `2 + cw`. At odd widths the last
  column is left unused (41: cw 18, right at 20; 201 the same as 200).
- Every meter is given `M = cw - 2` columns and draws in `M - 1`: a bar meter
  is its 3-column caption, `[`, the bar, `]` (Mem at 200 columns: `[` at 5,
  `]` at 96); a text meter is cut to `M - 1` columns (41 columns: `Tasks:
  55; 1 ru`).
- The meters, by the number of CPUs as htop writes them into a new htoprc:
  4 CPUs `AllCPUs Memory Swap` / `Tasks LoadAverage Uptime`; 6 `LeftCPUs` /
  `RightCPUs`; 12 `LeftCPUs2` / `RightCPUs2`; 24 `LeftCPUs4` / `RightCPUs4`;
  40 `LeftCPUs8` / `RightCPUs8` (each half's CPU meters first in its column).
  The left half has `(n + 1) / 2` CPUs.
- A group of CPU meters in `ncol` columns over `M` columns: `colwidth = (M -
  ncol) / ncol + 1`, `diff = M - colwidth * ncol`; CPU `i` of the group is in
  column `c = i / nrows` (`nrows = ceil(count / ncol)`), row `i % nrows`, at
  `x + c * colwidth + min(c, diff)`, drawn in `colwidth - 1` columns. Checked
  at 6, 12, 24, 40 CPUs and 80 and 200 columns (40 CPUs at 80 columns: only
  each caption and `]`, the starts 2 7 12 17 22 26 30).
- A CPU meter's caption is its number in 3 columns; its text `N.N%`, right
  aligned in the bar; a text longer than the bar shows its start (`[0.0]`).
  The bar's parts (monochrome `-C`: `|`, `#`, `*`, ... per part): nice, user,
  system (a system-only 0.7% is one `*`). Each part is rounded up to whole
  columns.
- Mem: three parts, `|` used, `#` buffers, `*` cache, and the text `USED/TOTAL`
  (2026-11-22 05:23:17: MemTotal 8126784, MemFree 7338032, Buffers 24032,
  Cached 358044, SReclaimable 45748, Shmem 12724 kB; bar 90 columns: `|||||#*****`,
  `365M/7.75G`): used = total - free - buffers - (cached + SReclaimable -
  Shmem), cache = cached + SReclaimable - Shmem.
- Sizes as `365M`, `7.75G`, `0K` (KiB below 1024, else one unit up with 2
  decimals below 10, 1 below 100, none above). Not seen: values where the
  rounding would carry (9.995, 99.95).
- Swp: `USED/TOTAL` (no swap in the captures: `0K/0K`; the parts are not seen).
- Tasks with threads and kernel threads hidden: `Tasks: 54; 1 running`; with
  user threads shown: `Tasks: 53, 39 thr; 1 running` (kernel threads never
  counted while hidden).
- `Load average: 0.00 0.00 0.00`, `Uptime: 00:06:41` (days not seen).

## Process list

- Titles: `    PID USER      PRI  NI  VIRT   RES   SHR S CPU%▽MEM%   TIME+  Command`
  (PID right-aligned in 7 with pid_max 4194304); the sort column's trailing
  space is the arrow (`▽` largest first, `△` the tree's PID).
- USER: 9 columns cut, then a space (`systemd-t`, `messagebu`).
- PRI: `RT` for real-time (multipathd), NI as a number.
- VIRT/RES/SHR: `12012`, `  98M` (100352 KiB or so: no decimal), `1277M`,
  `480M`. Larger values not seen.
- CPU%: 4 columns: `0.0`, `0.7`, `200.` and `199.` (the 5-character
  `200.0` cut to 4); MEM% `4.2`.
- TIME+: `0:52.52`, `1:14.69` (an hour or more not seen).
- The tree view (`-t`): the same drawing as later releases (`├─ `, `└─ `,
  `│  `), sorted by PID.
