# Writes utmp (glibc x86_64 layout) and lines.txt (clifrd's "utmp" source lines).
import struct, ipaddress
T0 = 1795143600  # 2026-11-20 03:00:00 UTC
recs = [
  # type, pid, line, id, user, host, term, exit, session, sec, usec, addr
  (2, 0, "~", "~~", "reboot", "6.8.0-generic", 0, 0, 0, T0, 120000, ""),
  (1, 0x4e*256 + 0x33, "~", "~~", "runlevel", "6.8.0-generic", 0, 0, 0, T0+5, 0, ""),
  (5, 812, "tty9", "9", "", "", 0, 0, 0, T0+7, 0, ""),
  (6, 845, "tty1", "tty1", "LOGIN", "", 0, 0, 845, T0+8, 0, ""),
  (7, 1, "tty7", "tty7", "alice", "", 0, 0, 1, T0+60, 0, ""),
  (7, 1, "tty8", "tty8", "bob", "10.1.2.3", 0, 0, 1, T0+3600, 500000, "10.1.2.3"),
  (7, 1, "ttyS9", "S9", "carol_long_name", "ws1.example:0", 0, 0, 1, T0+7200, 0, ""),
  (7, 1, "pts/7", "ts/7", "dave", "fe80::1", 0, 0, 1, T0+7300, 0, "fe80::1"),
  (7, 99999, "pts/8", "ts/8", "eve", "10.9.9.9", 0, 0, 99999, T0+7400, 0, "10.9.9.9"),
  (8, 4242, "pts/3", "ts/3", "", "", 0, 0, 4242, T0+7500, 0, ""),
  (3, 0, "|", "", "", "", 0, 0, 0, T0+7600, 0, ""),
]
out, lines = b"", []
for (typ, pid, line, id_, user, host, term, ex, sess, sec, usec, addr) in recs:
    a = b"\0"*16
    if addr:
        ip = ipaddress.ip_address(addr)
        a = ip.packed if ip.version == 6 else ip.packed + b"\0"*12
    r = struct.pack("<hhi32s4s32s256shhiii16s20s", typ, 0, pid, line.encode(), id_.encode(), user.encode(),
                    host.encode(), term, ex, sess, sec, usec, a, b"\0"*20)
    assert len(r) == 384, len(r)
    out += r
    lines.append("\t".join(map(str, [typ, pid, line, id_, user, host, term, ex, sess, sec, usec, addr])))
open("utmp", "wb").write(out)
open("lines.txt", "w").write("\n".join(lines) + "\n")
