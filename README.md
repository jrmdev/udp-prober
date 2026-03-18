# udp-prober

`udp-prober` is a fast Rust UDP scanner that sends protocol-aware UDP probes and reports live responders with human-readable, JSONL, or XML output. It is inspired by CiscoCXSecurity's `udp-proto-scanner`.

The scanner fans targets out across worker threads, rate-limits packet emission, retries on configurable intervals, and matches replies back to the probe that triggered them. The default scan set currently covers 38 probe and port combinations at `--rarity-max 6`.

## Features

- Fast multi-threaded IPv4 and IPv6 UDP scanning
- Protocol-aware probe catalog with 71 supported probes
- Human-readable, JSONL, and Nmap-shaped XML output
- Mixed IPv4/IPv6 target lists from CLI arguments or `--targets-file`
- `--blocklist` support for excluding IPv4/IPv6 addresses, ranges, and CIDR blocks
- Probe discovery helpers with `probes list` and `probes show`

## Build

```bash
cargo build --release
```

The binary will be available at `target/release/udp-prober`.

## Quick Start

Scan one host with the default probe set:

```bash
udp-prober scan 10.0.0.1
```

Scan an IPv6 host with the default probe set:

```bash
udp-prober scan 2001:db8::10
```

Scan specific probes only:

```bash
udp-prober scan --probe stun-bind --probe nat-pmp-addr 10.0.0.1
```

Scan targets from a file and emit JSONL:

```bash
udp-prober scan --targets-file targets.txt --format jsonl --threads 8
```

Scan a mixed IPv4/IPv6 target list with the default worker count of 4:

```bash
udp-prober scan 10.0.0.1 2001:db8::25
```

Run the broadest catalog pass up to rarity 9:

```bash
udp-prober scan --all-probes --rarity-max 9 --retries 0 10.0.0.1
```

Save machine-readable output for downstream parsing:

```bash
udp-prober scan --format jsonl --targets-file targets.txt > hits.jsonl
```

Generate Nmap-style XML:

```bash
udp-prober scan --format xml --probe sybaseanywhere --probe net-motion-mobility 127.0.0.1 > scan.xml
```

Inspect the probe catalog:

```bash
udp-prober probes list
udp-prober probes show stun-bind
```

## Command Notes

`udp-prober scan` accepts one or more IPv4 or IPv6 targets on the command line, or a newline-delimited list via `--targets-file`. Positional targets and target files may mix families. Single IPs, ranges, and CIDR entries are supported, with very large expansions rejected.

Useful flags:

- `--probe <NAME>` selects one or more specific probes.
- `--all-probes` enables the full catalog instead of the default set.
- `--rarity-max <1-9>` caps the included probes by rarity. The default is `6`.
- `--bandwidth <N>` controls send bandwidth. Suffixes like `k`, `M`, and `G` are supported.
- `--pps <N>` caps packet rate directly.
- `--retry-pps <N>` controls retry pacing.
- `--retries <N>` sets how many retransmits to attempt after the first send.
- `--rtt <DURATION>` sets the response wait window. Examples: `500ms`, `1s`.
- `--blocklist <TARGET>` skips listed IPv4/IPv6 addresses, ranges, and CIDR blocks.
- `--threads <N>` sets worker count. The default is `4`.
- `--format <human|jsonl|xml>` chooses the output format.

## Output

- `human`: one line per hit or warning, followed by a summary line
- `jsonl`: structured JSON events for hits, warnings, and the final summary
- `xml`: buffered XML output with an Nmap-like `<nmaprun>` document

## Supported Probes

The catalog currently includes the following probes. Legacy compatibility probes are marked in the description.

| Probe | Port(s) | Description |
| --- | --- | --- |
| `ike` | `500` | ISAKMP/IKE handshake probe for VPN gateways. |
| `echo` | `7` | Simple echo payload for classic UDP echo services. |
| `systat` | `11` | Basic payload for historical `systat` responders. |
| `daytime` | `13` | Lightweight query for daytime services. |
| `chargen` | `19` | Character generator request for legacy UDP services. |
| `time` | `37` | Minimal request for RFC 868 time services. |
| `net-support` | `5405` | NetSupport discovery probe. |
| `gtpv1` | `2123` | GTPv1 control-plane probe for mobile core gear. |
| `l2tp` | `1701` | L2TP control message for tunnel endpoints. |
| `rpc` | `111` | ONC RPC portmapper style probe. |
| `ntp` | `123` | Standard NTP request packet. |
| `snmp-public` | `161` | SNMP query using the `public` community string. |
| `ms-sql` | `1434` | SQL Server Browser ping. |
| `ms-sql-slam` | `1434` | Alternate SQL Server probe matching Slammer-era behavior. |
| `netop` | `6502` | NetOp remote-control discovery probe. |
| `tftp-legacy` | `69` | Legacy TFTP RRQ for `/etc/passwd`; compatibility only. |
| `tftp` | `69` | Safer TFTP RRQ for a synthetic filename. |
| `db2` | `523` | IBM DB2 discovery request. |
| `citrix` | `1604` | Citrix ICA browser discovery probe. |
| `rpc-check` | `111` | Alternate RPC check packet for portmapper detection. |
| `dns-version-bind-req` | `53` | CHAOS `version.bind` DNS query. |
| `help` | `42` | Text `help` request for old name service responders. |
| `nbt-stat` | `137` | NetBIOS node status query. |
| `snmp-v1-public` | `161` | SNMPv1 GET request with `public`. |
| `snmp-v3-get-request` | `161` | SNMPv3 GET request for reachable agents. |
| `dns-sd` | `5353` | Multicast DNS-SD services query. |
| `dns-status-request` | `53` | DNS status opcode request. |
| `sip-options` | `5060` | SIP `OPTIONS` request for VoIP endpoints. |
| `ntp-request` | `123` | Alternate NTP request packet. |
| `afs-version-request` | `7001` | AFS version query. |
| `citrix-alt` | `1604` | Alternate Citrix browser probe. |
| `kerberos` | `88` | Kerberos AS-REQ style discovery probe. |
| `dtls-session-req` | `443` | DTLS ClientHello style request over UDP. |
| `sqlping` | `1434` | Alias-style SQL browser ping. |
| `xdmcp` | `177` | XDMCP query for X display managers. |
| `quic` | `3310` | QUIC-style UDP probe used by the catalog. |
| `sybaseanywhere` | `2638` | SQL Anywhere discovery packet. |
| `net-motion-mobility` | `5008` | NetMotion Mobility server probe. |
| `ldap-search-req-udp` | `389` | UDP LDAP search request. |
| `ibm-db2-das-udp` | `523` | IBM DB2 DAS UDP probe variant. |
| `squeeze-center` | `3483` | Logitech SqueezeCenter discovery request. |
| `quake2-status` | `27910-27914` | Quake II `status` query across common server ports. |
| `quake3-getstatus` | `26000-26004, 27960-27964, 30720-30724, 44400` | Quake III `getstatus` query across common ports. |
| `serialnumberd` | `626` | Apple serialnumberd query. |
| `vuze-dht` | `17555, 49152-49156` | Vuze/Azureus DHT discovery packet. |
| `pc-anywhere` | `5632` | Symantec pcAnywhere probe. |
| `pc-duo` | `1505` | PC-Duo remote-control discovery probe. |
| `pc-duo-gw` | `2303` | PC-Duo gateway probe. |
| `memcached-stats` | `11211` | Legacy memcached `stats` request; compatibility only. |
| `memcached` | `11211` | Safer memcached `version` request. |
| `svrloc` | `427` | Service Location Protocol query. |
| `ard` | `3283` | Apple Remote Desktop discovery probe. |
| `quake1-server-info` | `26000-26004` | Quake I server info query. |
| `quake3-master-getservers` | `27950, 30710` | Quake III master server list request. |
| `back-orifice` | `19150` | Back Orifice discovery ping. |
| `murmur` | `64738` | Mumble/Murmur server ping. |
| `ventrilo` | `3784` | Ventrilo server status request. |
| `team-speak2` | `8767` | TeamSpeak 2 server query. |
| `team-speak3` | `9987` | TeamSpeak 3 server query. |
| `freelancer-status` | `2302` | Microsoft Freelancer game server status query. |
| `ase` | `1258, 2126, 3123, 12444, 13200, 23196, 26000, 27138, 27244, 27777, 28138` | All-Seeing Eye game server ping. |
| `andro-mouse` | `8888` | AndroMouse discovery packet. |
| `air-hid` | `13246` | Air HID discovery message. |
| `open-vpn` | `1194` | OpenVPN UDP control probe for the standard listener; packet-auth deployments may stay silent. |
| `ipmi-rmcp` | `623` | IPMI RMCP presence probe. |
| `coap-request` | `5683` | CoAP request for `/.well-known/core`. |
| `ubiquiti-discoveryv1` | `10001` | Ubiquiti device discovery version 1 packet. |
| `ubiquiti-discoveryv2` | `10001` | Ubiquiti device discovery version 2 packet. |
| `stun-bind` | `3478` | Safe STUN binding request from RFC 5389. |
| `nat-pmp-addr` | `5351` | NAT-PMP public address request. |
| `nfs-null` | `2049` | Safe NFS `NULL` procedure call over ONC RPC. |

## Notes

- `tftp-legacy` and `memcached-stats` are present for compatibility but are not enabled by default.
- `memcached` is also not enabled by default, even though it uses a safer `version` request.
- Use `udp-prober probes list` to see the current canonical names, ports, rarity, and default status directly from the binary.
