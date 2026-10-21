# scapy-android v1.0b - Scapy For Android

Running Scapy on Android in Termux, without root. Based on upstream Scapy
2.8.0 (`secdev/scapy`, branch `android-support`).

## Tested on

| | |
|---|---|
| Device | Google Pixel 7 Pro, unrooted |
| Android | 17 (SDK 37), kernel 6.1, SELinux enforcing |
| Termux | 0.118.3 (targetSdk 28) |
| Python | 3.14.8 |

## Why Scapy did not work

- Since Python 3.13 (PEP 738), `sys.platform` is `"android"`, not `"linux"`.
  Scapy did not recognize the platform, logged
  `Scapy currently does not support android! I/O will NOT work!`, and did not
  load its Linux backend.
- Android does not let apps open packet sockets (`AF_PACKET`, SELinux) or raw
  sockets (`SOCK_RAW`, no `CAP_NET_RAW`). Scapy uses them to send and sniff.
- Android does not let apps call `bind()` on `NETLINK_ROUTE` sockets or send
  `RTM_GETLINK` requests. Scapy uses both to list interfaces and routes.

## Android restrictions measured on the device (unrooted)

| Operation | Result |
|---|---|
| `AF_PACKET` socket | denied (EACCES) |
| `AF_INET` `SOCK_RAW` socket | denied (EPERM) |
| ICMP and ICMPv6 ping sockets (`SOCK_DGRAM`) | allowed (`ping_group_range` is `0 2147483647`) |
| Ping socket `bind()` outside the ephemeral port range | denied (EACCES) |
| `NETLINK_ROUTE` `bind()` | denied, but an unbound socket works |
| `RTM_GETLINK` | denied |
| `RTM_GETADDR`, `RTM_GETROUTE` (IPv4 and IPv6) | allowed |
| `SIOCGIFNAME`, `SIOCGIFFLAGS` ioctls | allowed |
| `SIOCGIFHWADDR` ioctl (MAC address) | denied |
| `/proc/net/*`, `/sys/class/net` | denied |
| Default routes | in per-network routing tables, not in the main table |

## What works without root

| Feature | Status |
|---|---|
| Import, without the CRITICAL message | works |
| Building, dissecting, `wrpcap()` / `rdpcap()` | works |
| Interface list (`conf.ifaces`) | works, without MAC addresses |
| IPv4 and IPv6 routes, default interface | works |
| `sr()` / `sr1()` / `send()` of `IP()/ICMP()` echo requests | works, with `L3PingSocket` |
| Custom ICMP id and payload | works (the kernel may choose the id on the wire; replies show the requested id) |
| Other packets (TCP, UDP, other ICMP types, spoofed source) | refused: needs root |
| `sniff()` and layer 2 | refused: needs root |

## Changes in v1.0b

- `scapy/consts.py`: new `ANDROID` flag. Android is handled as Linux.
- `scapy/arch/linux/rtnetlink.py`:
  - use an unbound netlink socket when `bind()` is denied, and handle denied
    requests;
  - build the interface list from addresses when `RTM_GETLINK` is denied;
  - read all the routing tables on Android, and prefer the default route of the
    network in use;
  - use the interface address for direct routes without a preferred source.
- `scapy/interfaces.py`: `get_working_if()` uses route metrics as a tie-breaker.
- `scapy/arch/linux/__init__.py`: new `L3PingSocket` (unprivileged ICMP echo)
  and `NotAvailablePacketSocket`.
- `scapy/config.py`: on Android without root, use `L3PingSocket` for layer 3
  and `NotAvailablePacketSocket` for layer 2 and sniffing.
- `test/linux.uts`: new "Android support" tests.

## Roadmap

- [ ] Loopback: ICMP echo to `127.0.0.1` still uses `L3RawSocket` and fails
      without root.
- [ ] IPv6 ICMP echo with ICMPv6 ping sockets (allowed on the device).
- [ ] Traceroute: read ICMP errors (time exceeded) with `IP_RECVERR`.
- [ ] DNS servers: Android does not expose them to apps. Read Termux's
      `$PREFIX/etc/resolv.conf` to remove the startup warning.
- [ ] Rooted devices (Android 11 and older): check full layer 2 / layer 3 send
      and sniff under `su`.
- [ ] Wi-Fi connected alongside mobile data: check the default route
      selection.
- [ ] Run the full test suite on desktop Linux.
- [ ] Propose the changes to upstream Scapy, following `CONTRIBUTING.md` and
      `AGENTS.md`.

## Running on a device

Copy the `scapy/` package and `test/` to Termux, then:

```console
PYTHONPATH=. python -c "from scapy.all import *; print(sr1(IP(dst='1.1.1.1')/ICMP(), timeout=2))"
PYTHONPATH=. python scapy/tools/UTscapy.py -t test/linux.uts -K needs_root -K netaccess -f text
```

## Personal data guard

Commits and pushes are checked for personal data by
`.config/pii-guard/pii_guard.py`. It runs as git hooks on the developer's
machine, and as a GitHub check on every push.

Enable the hooks once per clone:

```console
git config core.hooksPath .githooks
git config pii-guard.upstream origin
```

What is refused, unless allowed explicitly:

- device serial numbers (`adb devices` lines), IMEI, IMSI, ICCID and phone
  numbers;
- MAC addresses past the vendor prefix (the first 3 bytes): write them as `aa:bb:cc:00:00:00`;
- public and carrier IP addresses. Documentation ranges (`192.0.2.0/24`,
  `2001:db8::/32`), `100.64.0.0/24` placeholders and public DNS resolvers are
  fine;
- GPS coordinates, Wi-Fi names (SSIDs), Android and advertising IDs;
- values and networks listed privately (see below).

Carrier names are allowed, with a reminder to check that disclosing them is
appropriate.

Obfuscate values by keeping at most the first 4 characters, then obvious
filler: `0000`, `1111` or `31337`.

To allow a finding on purpose, add `pii-allow` on the line, or run the command
with `PII_ALLOW=1`.

### Private values

Values specific to one person (a device serial, a home network) are stored as
salted SHA-256 hashes in `~/.config/pii-guard/private.json`, outside the
repository:

```console
python .config/pii-guard/pii_guard.py --add                  # prompted, not echoed
python .config/pii-guard/pii_guard.py --add-network NETWORK REPLACEMENT
```

### Upstream Scapy

Commits that exist in upstream Scapy (the remote named by
`pii-guard.upstream`) are skipped, so syncing with upstream needs no override.
For a merge, only the lines written to resolve conflicts are checked.

### Edits on github.com

Edits made on GitHub's website are public as soon as they are saved, before
any check can run. The GitHub check reports them afterwards. If personal data
reaches the repository, rewrite the history and recreate the repository,
because the old commits stay reachable by their hash.
