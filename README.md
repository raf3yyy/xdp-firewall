# xdpfw: XDP/eBPF firewall

A small firewall built with eBPF and XDP. It covers all four levels of the Networking challenge:

| Level | Feature | Where |
|---|---|---|
| 1 | Stateless drop of ICMP echo requests, logged to the trace pipe | `src/level1.bpf.c` (hardcoded); the `icmp` toggle in `src/xdpfw.bpf.c` |
| 2 | Block and unblock IPs at runtime through pinned BPF maps, without reloading | `blocklist` map + `xdpfw` CLI (`src/xdpfw.c`) |
| 3 | Per-source packet rate and SYN rate limiting with a temporary ban | `rate` LRU map, `rate_check()` |
| 4 | Stateful filtering: inbound traffic is allowed only for sessions this host started | TC egress program + `conntrack` LRU map |

## How it works

```
                inbound                                       outbound
 NIC ──► [XDP xdp_fw] ──► kernel stack ──► app ──► kernel stack ──► [TC tc_egress] ──► NIC
           │  1. blocklist hit?        → DROP                         │
           │  2. ICMP echo + icmp=on?  → DROP                         │ record new flow
           │  3. over pps / syn limit? → DROP + ban                   │ (TCP SYN, UDP, ICMP echo)
           │  4. conntrack=on and no                                  ▼
           │     matching flow?        → DROP   ◄──── lookup ── conntrack map
           ▼
         PASS
```

* **XDP** only sees ingress traffic. Outgoing packets are seen by a **TC egress** classifier attached to the same interface. Both programs share the `conntrack` map.
* All maps are pinned under `/sys/fs/bpf/xdpfw/`. The CLI opens those pins, so every change takes effect right away and the XDP program is never reloaded.
* The conntrack key is always stored from the inbound point of view (`src = remote`, `dst = local`). A reply packet can then be looked up directly with its own header fields.
* TCP state: the first entry is created as `SYN_SENT` when a SYN goes out. In that state only a SYN-ACK or RST is accepted inbound. The SYN-ACK moves the flow to `ESTABLISHED`, a FIN moves it to `CLOSING`, and an RST deletes it. Idle timeouts are 600s for established TCP, 30s for other TCP states, 60s for UDP and 30s for ICMP.
* Rate limiting uses a 1-second fixed window per source IP. A source that goes over `rate` packets/s or `syn` SYNs/s is banned for `ban` seconds. Both tables are LRU maps, so a flood from spoofed sources cannot fill them and stop new entries from being added.

## Build and install

Tested on Ubuntu 24.04 (kernel 6.8) on a Proxmox VM with virtio-net. XDP runs in native mode there.

```bash
apt install clang llvm libbpf-dev gcc make linux-tools-$(uname -r)
make && sudo make install          # installs /usr/local/sbin/xdpfw
```

## Usage

```bash
xdpfw load eth0                    # attach XDP + TC egress, pin maps (native, falls back to skb)
xdpfw unload

# Level 1
xdpfw set icmp on|off
cat /sys/kernel/tracing/trace_pipe # drop log (xdpfw set log on|off)

# Level 2
xdpfw block 203.0.113.7
xdpfw unblock 203.0.113.7
xdpfw list                         # blocked IPs + drop count for each

# Level 3
xdpfw set rate 1000                # packets/sec per source (0 = off)
xdpfw set syn 100                  # SYNs/sec per source (0 = off)
xdpfw set ban 10                   # ban length in seconds
xdpfw rates                        # live per-source table

# Level 4
xdpfw allow 22                     # expose a service (do this first if you are on ssh!)
xdpfw set conntrack on
xdpfw conns                        # connection table

xdpfw config | stats | flush <rates|conns|blocklist>
```

Level 1 can also be run on its own:

```bash
ip link set dev eth0 xdpgeneric obj build/level1.bpf.o sec xdp
ip link set dev eth0 xdpgeneric off
```

## Test results

The firewall ran on the VM (`192.168.11.60`). Test traffic came from another host on the LAN (`192.168.11.19`).

**Level 1:** ping was 100% lost, and every drop showed up in the trace pipe:
```
bpf_trace_printk: level1 DROP icmp-echo src=192.168.11.19 id=21804 seq=1
bpf_trace_printk: level1 DROP icmp-echo src=192.168.11.19 id=21804 seq=2
```

**Level 2:** after a block, the host could not reach the VM at all. After an unblock, traffic passed again right away. The XDP program id did not change.
```
BLOCKED IP         DROPS
192.168.11.19      38
10.1.2.3           0
```

**Level 3:** a SYN flood at about 1000 SYN/s (`hping3 -S -p 80 -i u1000`) with `syn=100`. The attacker was banned within the first second, while other sources kept passing:
```
SOURCE               PKTS/s   SYNS/s  STATUS
192.168.11.19             0        0  BANNED (7s left)
192.168.11.190           19        1  ok

dropped: rate limit      2785
dropped: syn flood       1
```
(The first drop is counted as `syn flood`. Later drops come from the ban and are counted as `rate limit`.)

**Level 4:** `conntrack=on` with port 22 allowed. Outbound HTTPS, DNS and ping from the VM all worked. Inbound ping and a connection to a listener on `:8080` were dropped:
```
PROTO LOCAL                  REMOTE                 STATE           OUT     IN  IDLE
udp   192.168.11.60:48286    192.168.11.1:53        UDP               1      1    6s
tcp   192.168.11.60:38344    172.66.147.243:443     CLOSING          12     13    6s
icmp  192.168.11.60:0        1.1.1.1:3693           ICMP              2      2    5s

xdpfw DROP unsolicited src=192.168.11.19 proto=6
```

## Limitations

* Only IPv4 is filtered. IPv6, ARP and other non-IPv4 traffic is passed through.
* The conntrack table is a simplified model, not a full TCP state machine. It does not check sequence numbers.
* Conntrack only tracks traffic that leaves through the interface the firewall is attached to.
* The rate-window counters are updated without locking, so counts can be slightly off when several CPUs process packets from the same source. That is accurate enough for spotting a flood.
* Blocking your own management IP, or turning conntrack on without `allow 22`, will cut your ssh session.
