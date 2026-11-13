"""Compare exact changes against an independent first-match packet evaluator."""
from ipaddress import IPv4Address, IPv4Network
from itertools import product
import json
from pathlib import Path
import random
import subprocess
import sys
from tempfile import TemporaryDirectory

binary, examples = (Path(value).resolve() for value in sys.argv[1:])
checks = 0


def check(condition, detail):
    global checks
    if not condition:
        raise AssertionError(detail)
    checks += 1


def invoke(*args, status=0):
    proc = subprocess.run([binary, *map(str, args)], capture_output=True, text=True, timeout=10)
    check(proc.returncode == status, (args, proc.returncode, proc.stderr))
    if status == 2:
        check(proc.stderr.startswith("policyplane:") and not proc.stdout, proc)
        return None
    check(not proc.stderr, proc.stderr)
    return json.loads(proc.stdout)


def direct(default, rules, protocol, source, destination, port):
    for key, action, proto, src, dst, lo, hi in rules:
        if proto in ("any", protocol) and source in src and destination in dst and lo <= port <= hi:
            return action, key
    return default, "(default)"


def covers(row, protocol, source, destination, port):
    if row["protocol"] != protocol:
        return False
    for field, point in (("source", source), ("destination", destination)):
        start, end = map(IPv4Address, row[field])
        if not start <= point <= end:
            return False
    return row["destinationPort"] is None or row["destinationPort"][0] <= port <= row["destinationPort"][1]


def emit(path, default, rules):
    lines = [f"default {default}"]
    for key, action, proto, src, dst, lo, hi in rules:
        ports = "*" if (lo, hi) == (0, 65535) else f"{lo}-{hi}"
        lines.append(f"{key} {action} {proto} {src} {dst} {ports}")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def generate(randomizer, label, ip_ranges):
    rules = []
    for index in range(8):
        proto = randomizer.choice(("tcp", "udp", "icmp", "any"))
        ports = (0, 65535) if proto in ("icmp", "any") else sorted(randomizer.sample(range(5), 2))
        rules.append((f"{label}{index}", randomizer.choice(("allow", "deny")), proto,
                      *randomizer.choices(ip_ranges, k=2), *ports))
    return randomizer.choice(("allow", "deny")), rules


before, after = (examples / f"{label}.policy" for label in ("before", "after"))
report = invoke("diff", before, after, "--fail-on-new-allow", status=3)
check(report["newlyAllowedRegions"] == 1 and report["newlyDeniedRegions"] == 1, report)
check(invoke("diff", after, after)["changes"] == [], "same policy")
check(invoke("audit", before)["rules"][-1]["reachable"] is False, "shadowed sample")
check(invoke("match", before, "tcp", "198.51.100.2", "192.0.2.7", 22) ==
      {"action": "deny", "rule": "drop-admin"}, "first-match precedence")

with TemporaryDirectory() as folder:
    left = Path(folder) / "left.policy"
    right = Path(folder) / "right.policy"
    ip_ranges = [IPv4Network(cidr) for cidr in ("0.0.0.0/0", "0.0.0.0/30", "0.0.0.2/31",
                                               "0.0.0.1/32", "255.255.255.255/32")]
    points = [IPv4Address(value) for value in (0, 1, 2, 3, 4, 2**32 - 1)]
    randomizer = random.Random(0x504c414e45)
    for index in range(9):
        before, before_rules = generate(randomizer, "L", ip_ranges)
        after, after_rules = generate(randomizer, "R", ip_ranges)
        emit(left, before, before_rules)
        emit(right, after, after_rules)
        report = invoke("diff", left, right)
        changes = report["changes"]
        check(sum(row["after"] == "allow" for row in changes) == report["newlyAllowedRegions"], report)
        check(sum(row["after"] == "deny" for row in changes) == report["newlyDeniedRegions"], report)
        seen = set()
        for proto in ("tcp", "udp", "icmp"):
            ports = [0] if proto == "icmp" else [0, 1, 2, 3, 4, 5, 65535]
            for src, dst, port in product(points, points, ports):
                old, old_rule = direct(before, before_rules, proto, src, dst, port)
                new, new_rule = direct(after, after_rules, proto, src, dst, port)
                seen.add(old_rule)
                hits = [row for row in changes if covers(row, proto, src, dst, port)]
                check(len(hits) == int(old != new), (index, proto, src, dst, port, hits))
                if hits:
                    row = hits[0]
                    check((row["before"], row["beforeRule"], row["after"], row["afterRule"]) ==
                          (old, old_rule, new, new_rule), row)
        observed = {rule["id"] for rule in invoke("audit", left)["rules"] if rule["reachable"]}
        check(observed == seen - {"(default)"}, (observed, seen))

    for source in (
        "", "default deny\ndefault allow", "default deny\nx allow tcp 1.2.3.4/24 * 80",
        "default deny\nx allow udp * * 65536", "default deny\nx allow icmp * * 1",
        "default deny\nx allow tcp * * 80\nx deny udp * * 53",
        "default deny\nx allow tcp 01.2.3.4 * 443", "default deny\nx allow tcp * * 2-1",
        "#" * (512 * 1024 + 1),
    ):
        left.write_text(source, encoding="ascii")
        invoke("audit", left, status=2)
    left.write_text("default deny\nlast allow udp 255.255.255.255 * 65535\n", encoding="ascii")
    check(invoke("match", left, "udp", "255.255.255.255", "0.0.0.0", 65535)["rule"] == "last",
          "maximum address and port")
    invoke("match", left, "icmp", "1.2.3.4", "1.2.3.4", 0, status=2)
    invoke("audit", Path(folder), status=2)

print(f"{checks} independent CLI and policy-decision checks")
