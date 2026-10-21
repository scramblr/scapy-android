#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# This file is part of scapy-android

"""
pii-guard: refuse commits and pushes that contain personal data.

Scans the lines added by commits (and their messages) for personal data:
device serials, IMEI/IMSI/ICCID, phone numbers, MAC addresses, public IP
addresses, GPS coordinates, Wi-Fi names, Android and advertising IDs.
Values to keep private are stored as salted SHA-256 hashes, outside the
repository, in ~/.config/pii-guard/private.json (or $PII_GUARD_DIR).

Findings are reported masked, never in full. To allow a finding on purpose,
add "pii-allow" on the line, or run the command with PII_ALLOW=1.
"""

import argparse
import getpass
import hashlib
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys

CONFIG_DIR = os.environ.get("PII_GUARD_DIR") or os.path.join(
    os.path.expanduser("~"), ".config", "pii-guard"
)
PRIVATE_FILE = os.path.join(CONFIG_DIR, "private.json")
ALLOW_MARKER = "pii-allow"

# Public resolvers and documentation addresses are not personal data
ALLOWED_IPS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2001:4860:4860::8888", "2001:4860:4860::8844",
}
CGNAT = ipaddress.ip_network("100.64.0.0/10")
CGNAT_PLACEHOLDERS = ipaddress.ip_network("100.64.0.0/24")
IPV6_GLOBAL = ipaddress.ip_network("2000::/3")  # pii-allow
IPV6_DOC = ipaddress.ip_network("2001:db8::/32")
PLACEHOLDERS = {"example", "test", "scapy", "ssid", "myssid", "xxx", "none"}

# Carrier names are allowed, but deserve a reminder
CARRIERS = re.compile(
    r"\b(verizon|t-mobile|at&t|sprint|u\.?s\.? cellular|cricket wireless|"  # pii-allow
    r"mint mobile|google fi|boost mobile|tracfone|straight talk|"  # pii-allow
    r"xfinity mobile|spectrum mobile|vodafone|telstra|optus|telus|"  # pii-allow
    r"rogers wireless|deutsche telekom|movistar|telcel|airtel|jio)\b",  # pii-allow
    re.I,
)

# git commit/push, with options before the subcommand (git -C dir commit ...)
RE_GIT_ACTION = re.compile(
    r"\bgit(?:\s+(?:-[Cc]\s+\S+|-{1,2}[\w-]+(?:=\S+)?))*\s+(commit|push)\b"
)
RE_GH_POST = re.compile(r"\bgh\s+(?:issue|pr|release|gist|repo\s+edit)\b")
RE_TOKEN = re.compile(r"[A-Za-z0-9]+(?:[:._-][A-Za-z0-9]+)*")
RE_LONG_NUMBER = re.compile(r"(?<![\w.])\d(?:[ -]?\d){14,19}(?![\w.])")
RE_PHONE = re.compile(
    r"(?<![\w+])(?:\+\d{1,3}[ .-]?\(?\d{1,4}\)?(?:[ .-]?\d{2,4}){2,4}"
    r"|\(?\b\d{3}\)?[ .-]\d{3}[ .-]\d{4})\b"
)
RE_MAC = re.compile(r"\b[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}\b")
RE_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
RE_IPV6 = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
RE_ADB = re.compile(
    r"^\s*(?!emulator-)([A-Za-z0-9]{8,})\s+"
    r"(?:device|offline|unauthorized|recovery|sideload)\b"
)
RE_GPS = re.compile(r"(?<![\w.])(-?\d{1,2}\.\d{4,})\s*,\s*(-?\d{1,3}\.\d{4,})(?![\w.])")
RE_SSID = re.compile(
    r"\b(?:e?ssid|wifi[_ -]?name|network[_ -]?name)\b[\"']?\s*[:=]\s*"
    r"[\"']?([^\"',;\s)]+)",
    re.I,
)
RE_DEVICE_ID = re.compile(
    r"\b(?:android[_ -]?id|advertising[_ -]?id|ad[_ -]?id|gaid|adid)\b"
    r"[\"']?\s*[:=]\s*[\"']?([0-9A-Fa-f-]{8,})",
    re.I,
)


def normalize(value):
    return re.sub(r"[\s:._()+-]", "", value).upper()


def mask(value, keep=4):
    """Keep up to `keep` characters, then replace the rest with obvious filler"""
    head, tail = value[:keep], value[keep:]
    return head + re.sub(r"[A-Za-z0-9]", "0", tail)


def is_masked(value):
    """Values that are already obfuscated, such as 2930000000"""
    tail = normalize(value)[4:]
    return bool(tail) and set(tail) <= {"0", "1"} or "31337" in value


def luhn(digits):
    total = 0
    for i, d in enumerate(reversed(digits)):
        d = int(d)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class Private:
    """Salted hashes of the values and networks to keep private"""

    def __init__(self):
        self.data = {"salt": secrets.token_hex(16), "values": [], "networks": []}
        if os.path.exists(PRIVATE_FILE):
            with open(PRIVATE_FILE, encoding="utf-8") as fd:
                self.data = json.load(fd)

    def save(self):
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(PRIVATE_FILE, "w", encoding="utf-8") as fd:
            json.dump(self.data, fd, indent=1)

    def digest(self, value):
        return hashlib.sha256(
            (self.data["salt"] + value).encode("utf-8")
        ).hexdigest()

    def add_value(self, value):
        value = normalize(value)
        if len(value) < 4:
            raise ValueError("value too short")
        h = self.digest(value)
        if h not in self.data["values"]:
            self.data["values"].append(h)

    def add_network(self, network, replacement):
        net = ipaddress.ip_network(network, strict=False)
        new = ipaddress.ip_network(replacement, strict=False)
        if net.version != new.version or net.prefixlen != new.prefixlen:
            raise ValueError("the replacement must have the same size")
        self.data["networks"].append({
            "hash": self.digest(str(net)),
            "prefixlen": net.prefixlen,
            "replacement": str(new),
        })

    def has_value(self, value):
        return self.digest(normalize(value)) in self.data["values"]

    def network_replacement(self, ip):
        """Return the replacement address if `ip` is in a private network"""
        for entry in self.data["networks"]:
            if ip.version != ipaddress.ip_network(entry["replacement"]).version:
                continue
            net = ipaddress.ip_network((ip, entry["prefixlen"]), strict=False)
            if self.digest(str(net)) == entry["hash"]:
                new = ipaddress.ip_network(entry["replacement"])
                host = int(ip) - int(net.network_address)
                return str(new.network_address + host)
        return None


def check_ip(text, private):
    """Yield (kind, masked value, suggestion) for the IPs of a line"""
    for regex, version in ((RE_IPV4, 4), (RE_IPV6, 6)):
        for match in regex.finditer(text):
            try:
                ip = ipaddress.ip_address(match.group())
            except ValueError:
                continue
            if ip.version != version or str(ip) in ALLOWED_IPS:
                continue
            replacement = private.network_replacement(ip)
            if replacement:
                yield "private network", mask(match.group()), replacement
            elif ip in CGNAT:
                if ip not in CGNAT_PLACEHOLDERS:
                    yield "carrier IP (CGNAT)", mask(match.group()), "100.64.0.1"
            elif version == 4 and ip.is_global:
                yield "public IP", mask(match.group()), "192.0.2.1"
            elif version == 6 and ip in IPV6_GLOBAL and ip not in IPV6_DOC:
                yield "public IPv6", mask(match.group()), "2001:db8::1"


def check_line(text, private):
    """Return the findings of one line: [(blocking, kind, masked, suggestion)]"""
    if ALLOW_MARKER in text:
        return []
    found = []
    for match in RE_TOKEN.finditer(text):
        for candidate in {match.group(), *re.split(r"[:._-]", match.group())}:
            if len(candidate) >= 4 and private.has_value(candidate):
                found.append((True, "private value", mask(candidate), None))
    for match in RE_LONG_NUMBER.finditer(text):
        digits = normalize(match.group())
        if len(digits) == 15:
            kind = "IMEI" if luhn(digits) else "IMEI/IMSI"
        elif digits.startswith("89") and len(digits) in (19, 20):
            kind = "ICCID"
        else:
            continue
        if not is_masked(digits):
            found.append((True, kind, mask(match.group()), None))
    for match in RE_PHONE.finditer(text):
        if 8 <= len(normalize(match.group())) <= 15 and not is_masked(match.group()):
            found.append((True, "phone number", mask(match.group()), None))
    for match in RE_MAC.finditer(text):
        mac = match.group().lower().replace("-", ":")
        if mac[9:] == "00:00:00" or mac == "ff:ff:ff:ff:ff:ff" or \
                mac.startswith("00:00:5e"):
            continue
        found.append((True, "MAC address", mask(mac, 9), None))
    for kind, masked, suggestion in check_ip(text, private):
        found.append((True, kind, masked, suggestion))
    match = RE_ADB.match(text)
    if match and not is_masked(match.group(1)):
        found.append((True, "adb serial", mask(match.group(1)), None))
    for match in RE_GPS.finditer(text):
        lat, lon = float(match.group(1)), float(match.group(2))
        if abs(lat) <= 90 and abs(lon) <= 180 and max(abs(lat), abs(lon)) >= 10:
            found.append((True, "GPS coordinates", mask(match.group()), None))
    for regex, kind in ((RE_SSID, "Wi-Fi name"), (RE_DEVICE_ID, "Android/ad ID")):
        for match in regex.finditer(text):
            value = match.group(1)
            if value.lower() not in PLACEHOLDERS and not is_masked(value):
                found.append((True, kind, mask(value), None))
    for match in CARRIERS.finditer(text):
        found.append((False, "carrier name", match.group(), None))
    return found


def git(*args):
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    ).stdout


def added_lines(diff, origin):
    """Yield (location, line) for the lines added by a unified diff.

    In the combined diff of a merge, only the lines new to every parent (the
    conflict resolutions) are yielded.
    """
    path, lineno, columns = "?", 0, 1
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else line[4:]
        elif line.startswith("@@"):
            # "@@ -a +b @@", or "@@@ -a -b +c @@@" for a merge with 2 parents
            columns = len(line) - len(line.lstrip("@")) - 1
            lineno = int(re.search(r"\+(\d+)", line).group(1))
        elif line.startswith("+" * columns):
            yield "%s%s:%d" % (origin, path, lineno), line[columns:]
            lineno += 1


def message_lines(text, origin, comments=False):
    """Yield (location, line) for a text, without git comments if asked"""
    for i, line in enumerate(text.splitlines(), 1):
        if not (comments and line.startswith("#")):
            yield "%smessage:%d" % (origin, i), line


def commit_lines(rev_range):
    """Yield the messages and added lines of the commits of a range.

    Commits already published by the upstream project (the remote named by
    "git config pii-guard.upstream") are skipped: syncing with upstream does
    not require allowing or masking anything.
    """
    args = rev_range.split()
    try:
        upstream = git("config", "--get", "pii-guard.upstream").strip()
    except subprocess.CalledProcessError:
        upstream = ""
    if upstream:
        # The second --not restores the meaning of the range that follows
        args = ["--not", "--remotes=%s" % upstream, "--not"] + args
    for sha in git("rev-list", *args).split():
        origin = "%s " % sha[:8]
        yield from message_lines(git("log", "-1", "--format=%B", sha), origin)
        yield from added_lines(
            git("show", "--format=", "--cc", "-U0", "--no-color", "--no-ext-diff",
                sha),
            origin,
        )


def pre_push_ranges(remote, stdin):
    """Revision ranges of the commits being pushed, from the pre-push input"""
    for line in stdin.splitlines():
        local_ref, local_sha, _, remote_sha = line.split()
        if set(local_sha) == {"0"}:
            continue  # branch deletion
        if set(remote_sha) == {"0"}:
            yield "%s --not --remotes=%s" % (local_sha, remote)
        else:
            yield "%s..%s" % (remote_sha, local_sha)


def report(lines, private):
    blocked = 0
    for location, line in lines:
        for blocking, kind, masked, suggestion in check_line(line, private):
            if blocking:
                blocked += 1
                hint = " -> use %s" % suggestion if suggestion else ""
                print("pii-guard: %s: %s %s%s" % (location, kind, masked, hint),
                      file=sys.stderr)
            else:
                print("pii-guard: %s: note: carrier name '%s' (allowed, check it "
                      "is appropriate to disclose)" % (location, masked),
                      file=sys.stderr)
    if blocked and os.environ.get("PII_ALLOW") == "1":
        print("pii-guard: %d finding(s) allowed by PII_ALLOW=1" % blocked,
              file=sys.stderr)
        return 0
    if blocked:
        print("pii-guard: %d finding(s). Obfuscate them (keep at most the first 4 "
              "characters), mark the line with '%s', or run with PII_ALLOW=1."
              % (blocked, ALLOW_MARKER), file=sys.stderr)
        return 1
    return 0


def claude_hook(stdin):
    """Claude Code PreToolUse hook: scan commits, pushes and GitHub posts"""
    event = json.loads(stdin)
    command = (event.get("tool_input") or {}).get("command") or ""
    actions = set(RE_GIT_ACTION.findall(command))
    if not actions and not RE_GH_POST.search(command):
        return 0
    os.chdir(event.get("cwd") or ".")
    lines = list(message_lines(command, "command "))
    try:
        if "commit" in actions:
            lines += added_lines(git("diff", "HEAD", "-U0", "--no-color"), "")
        if "push" in actions:
            lines += commit_lines("HEAD --not --remotes")
    except (subprocess.CalledProcessError, OSError):
        pass  # not a git repository, or no commit yet: scan the command only
    # Exit code 2 makes Claude Code refuse the command
    return 2 if report(lines, Private()) else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--staged", action="store_true", help="scan the staged changes")
    group.add_argument("--range", help="scan the commits of a revision range")
    group.add_argument("--message", help="scan a commit message file")
    group.add_argument("--pre-push", metavar="REMOTE", help="git pre-push hook mode")
    group.add_argument("--text", action="store_true", help="scan the standard input")
    group.add_argument("--claude-hook", action="store_true",
                       help="Claude Code PreToolUse hook mode")
    group.add_argument("--add", action="store_true",
                       help="add a private value (prompted, not echoed)")
    group.add_argument("--add-stdin", action="store_true",
                       help="add private values read from the standard input")
    group.add_argument("--add-network", nargs=2, metavar=("NETWORK", "REPLACEMENT"),
                       help="keep a network private, e.g. a LAN /24 and its "
                       "replacement")
    args = parser.parse_args()
    private = Private()

    if args.add or args.add_stdin:
        if args.add:
            values = [getpass.getpass("Value to keep private (not echoed): ")]
        else:
            values = [v for v in sys.stdin.read().split() if v]
        for value in values:
            private.add_value(value)
        private.save()
        print("pii-guard: %d value(s) added to %s" % (len(values), PRIVATE_FILE))
        return 0
    if args.add_network:
        private.add_network(*args.add_network)
        private.save()
        print("pii-guard: network added to %s" % PRIVATE_FILE)
        return 0
    if args.claude_hook:
        return claude_hook(sys.stdin.read())

    if args.staged:
        lines = added_lines(git("diff", "--cached", "-U0", "--no-color",
                                "--no-ext-diff"), "")
    elif args.range:
        lines = commit_lines(args.range)
    elif args.message:
        with open(args.message, encoding="utf-8", errors="replace") as fd:
            lines = message_lines(fd.read(), "", comments=True)
    elif args.pre_push:
        ranges = list(pre_push_ranges(args.pre_push, sys.stdin.read()))
        lines = (line for r in ranges for line in commit_lines(r))
    else:
        lines = message_lines(sys.stdin.read(), "")
    return report(lines, private)


if __name__ == "__main__":
    sys.exit(main())
