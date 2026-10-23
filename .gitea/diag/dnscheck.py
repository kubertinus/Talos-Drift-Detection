"""Temporary CI diagnostics: why can't Wolfi images resolve names inside BuildKit?"""
import os, platform, random, socket, struct

print("arch:", platform.machine(), "| python:", platform.python_version(), "| uid:", os.getuid())
for f in ("/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"):
    try:
        print(f, "->", os.path.realpath(f), "|", open(f).read().strip().replace("\n", " ; ")[:200])
    except OSError as e:
        print(f, "ERR", e)
try:
    print("routes:", [l.split()[:3] for l in open("/proc/net/route").read().splitlines()[1:]])
except OSError as e:
    print("routes ERR", e)
for host in ("pypi.org", "github.com"):
    for fam in (socket.AF_UNSPEC, socket.AF_INET):
        try:
            print("getaddrinfo", host, fam.name, "->", socket.getaddrinfo(host, 443, fam, socket.SOCK_STREAM)[0][4])
        except Exception as e:
            print("getaddrinfo", host, fam.name, "FAIL", repr(e))
ns = next((l.split()[1] for l in open("/etc/resolv.conf") if l.startswith("nameserver")), None)
q = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0) + b"".join(
    bytes([len(p)]) + p.encode() for p in "pypi.org".split(".")) + b"\x00" + struct.pack(">HH", 1, 1)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.sendto(q, (ns, 53)); r = s.recv(512)
    print("raw UDP DNS to", ns, "-> rcode", r[3] & 0xF, "answers", struct.unpack(">H", r[6:8])[0])
except Exception as e:
    print("raw UDP DNS to", ns, "FAIL", repr(e))
