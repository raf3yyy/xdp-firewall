/* Shared between the eBPF programs and the user-space CLI. */
#ifndef XDPFW_COMMON_H
#define XDPFW_COMMON_H

#ifndef __u32
#include <linux/types.h>
#endif

#define PIN_DIR "/sys/fs/bpf/xdpfw"

/* Index into the `config` array map. */
enum cfg_key {
	CFG_BLOCK_ICMP = 0,  /* 1 = drop inbound ICMP echo requests            */
	CFG_RATE_PPS,        /* max packets/sec per source IP, 0 = disabled     */
	CFG_SYN_PPS,         /* max TCP SYNs/sec per source IP, 0 = disabled    */
	CFG_BAN_SECS,        /* how long an offender stays banned               */
	CFG_CONNTRACK,       /* 1 = only allow inbound for local sessions       */
	CFG_LOG,             /* 1 = bpf_printk every drop to the trace pipe     */
	CFG_MAX,
};

/* Index into the per-CPU `stats` map. */
enum stat_key {
	ST_PASS = 0,
	ST_DROP_ICMP,
	ST_DROP_BLOCKLIST,
	ST_DROP_RATE,
	ST_DROP_SYN,
	ST_DROP_CONNTRACK,
	ST_CT_NEW,
	ST_MAX,
};

/* Per-source rate limiter state (1-second fixed window). */
struct rate_info {
	__u64 window_start; /* ns */
	__u64 banned_until; /* ns, 0 = not banned */
	__u32 pkts;         /* packets seen in the current window */
	__u32 syns;         /* SYNs seen in the current window */
};

/*
 * Connection key, always written from the *inbound* point of view:
 * src = remote peer, dst = this host.
 */
struct ct_key {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port; /* ICMP: echo id */
	__u16 dst_port; /* ICMP: 0 */
	__u8  proto;
	__u8  pad[3];
};

enum ct_state {
	CT_SYN_SENT = 1, /* we sent SYN, waiting for SYN-ACK */
	CT_ESTABLISHED,
	CT_CLOSING,      /* FIN seen */
	CT_UDP,
	CT_ICMP,
};

struct ct_val {
	__u64 last_seen; /* ns */
	__u64 pkts_in;
	__u64 pkts_out;
	__u8  state;
	__u8  pad[7];
};

#endif
