<!-- start_ppi_description -->

# scapy-android v1.0b - Scapy For Android

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![Based on Scapy 2.8.0](https://img.shields.io/badge/based%20on-Scapy%202.8.0-informational.svg)](https://github.com/secdev/scapy)

**scapy-android** is a fork of [Scapy](https://github.com/secdev/scapy), the
Python packet manipulation program and library, that runs on Android in
[Termux](https://termux.dev), **without root**.

Upstream Scapy stops on Android with:

```
CRITICAL: Scapy currently does not support android! I/O will NOT work!
```

scapy-android removes that error and adapts Scapy to the restrictions Android
applies to apps. Packet building, dissection and pcap files work as on any
other system, and ICMP echo (ping) requests can be sent and matched with their
replies through `sr()` and `sr1()`, without root.

> This is an unofficial fork. It is not affiliated with or endorsed by the
> Scapy project. For Scapy on other platforms, use
> [secdev/scapy](https://github.com/secdev/scapy).

## Why upstream Scapy does not work on Android

- Since Python 3.13 ([PEP 738](https://peps.python.org/pep-0738/)),
  `sys.platform` is `"android"` instead of `"linux"`, so Scapy does not load
  its Linux backend.
- Android apps cannot open packet sockets or raw sockets, which Scapy uses to
  send and capture packets.
- Android apps cannot `bind()` route netlink sockets or list interfaces with
  `RTM_GETLINK`, which Scapy uses to read the network configuration.
- Android keeps its default routes in one routing table per network, not in
  the main table that Scapy reads.

## What works

| Feature | Without root | With root |
|---|---|---|
| Interactive shell and library | yes | yes |
| Building and dissecting packets, `wrpcap()` / `rdpcap()` | yes | yes |
| Interfaces (`conf.ifaces`) and routes (`conf.route`, `conf.route6`) | yes (no MAC addresses) | expected (not verified yet) |
| `sr()` / `sr1()` / `send()` of IPv4 ICMP echo requests | yes | expected (not verified yet) |
| TCP, UDP, other ICMP types, crafted IP headers | no: needs root | expected (not verified yet) |
| `sniff()`, layer 2 | no: needs root | expected (not verified yet) |

Without root, sending is limited to what Linux "ping sockets" allow: IPv4 ICMP
echo requests, with the source address and IP header set by the kernel. Other
packets stop with an explicit error:

```
Scapy_Exception: Without root privileges, only IP()/ICMP() echo requests can be sent (unprivileged ping sockets)
```

Sending a TCP SYN needs a raw socket whatever the destination port: the
`< 1024` privileged ports rule only applies to listening on a port.

## Quick start (Termux)

```bash
pkg install python git
git clone https://github.com/scramblr/scapy-android
cd scapy-android
./run_scapy
```

```python
>>> r = sr1(IP(dst="1.1.1.1")/ICMP(), timeout=2)
>>> r.summary()
'IP / ICMP 1.1.1.1 > 100.64.0.2 echo-reply 0'
>>> ans, unans = sr(IP(dst="8.8.8.8")/ICMP(seq=(1, 3))/b"hello", timeout=2)
>>> ans.summary()
>>> conf.ifaces
>>> conf.route
```

### Using it as a library

Run your scripts with the clone on the Python path. This also takes precedence
over a Scapy installed with `pip`:

```bash
PYTHONPATH=~/scapy-android python my_script.py
```

```python
from scapy.all import IP, ICMP, sr1

reply = sr1(IP(dst="1.1.1.1") / ICMP(), timeout=2, verbose=0)
print(reply.summary() if reply else "no reply")
```

To check which copy is used:

```bash
PYTHONPATH=~/scapy-android python -c "import scapy; print(scapy.__file__)"
```

<!-- stop_ppi_description -->

## Differences from upstream Scapy

| Area | Change |
|---|---|
| Platform | Android (`sys.platform == "android"`) is handled as Linux (`scapy/consts.py`). |
| Network configuration | Unbound netlink socket when `bind()` is denied; interfaces built from their addresses when `RTM_GETLINK` is denied; all routing tables read on Android; the default route of the network in use is preferred (`scapy/arch/linux/rtnetlink.py`). |
| Routes | Direct routes without a preferred source use the interface address. `get_working_if()` uses route metrics as a tie-breaker (`scapy/interfaces.py`). |
| Sockets | New `L3PingSocket` for unprivileged ICMP echo, and `NotAvailablePacketSocket` with an explicit error for layer 2 and sniffing (`scapy/arch/linux/__init__.py`), selected automatically without root (`scapy/config.py`). |
| Tests | "Android support" tests in `test/linux.uts`. |

Outside Android, only the two route changes above differ from upstream Scapy.

[ANDROID.md](ANDROID.md) has the details: the Android restrictions measured on
a device, the changes, and the roadmap.

## Tested on

| | |
|---|---|
| Device | Google Pixel 7 Pro, unrooted |
| Android | 17 (SDK 37), SELinux enforcing |
| Termux | 0.118.3 |
| Python | 3.14 |

Reports from other devices and Android versions are welcome in the issues.

## Roadmap

- ICMP echo to the loopback address (`127.0.0.1`) without root
- IPv6 ICMP echo with ICMPv6 ping sockets
- Traceroute, by reading ICMP errors (`IP_RECVERR`)
- DNS servers from Termux's `resolv.conf`
- Verification on rooted devices (Android 11 and older)
- Wi-Fi and mobile data connected at the same time

See [ANDROID.md](ANDROID.md#roadmap) for the current status.

## Running the tests

In Termux, from the clone:

```bash
PYTHONPATH=. python scapy/tools/UTscapy.py -t test/linux.uts -K needs_root -K netaccess -f text
```

## Learning Scapy

Everything that does not send or capture packets works as in upstream Scapy,
so its documentation applies:

- [Scapy documentation](https://scapy.readthedocs.io/en/latest/)
- [Interactive tutorial](https://scapy.readthedocs.io/en/latest/usage.html#interactive-tutorial)
- [Scapy in 15 minutes](https://github.com/secdev/scapy/blob/master/doc/notebooks/Scapy%20in%2015%20minutes.ipynb)

## License and credits

scapy-android is based on [Scapy](https://github.com/secdev/scapy), created by
Philippe Biondi and developed by the Scapy community.

The code, tests and tools are licensed under GPL v2, like Scapy (see
[LICENSE](LICENSE)). The documentation (everything unless marked otherwise in
`doc/`, and except the logo) is licensed under CC BY-NC-SA 2.5.

## Contributing

Issues and pull requests about Android support are welcome on this
repository. Changes that are not specific to Android belong in
[upstream Scapy](https://github.com/secdev/scapy): see
[CONTRIBUTING.md](CONTRIBUTING.md).
