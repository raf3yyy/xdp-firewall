// SPDX-License-Identifier: GPL-2.0
/*
 * xdpfw - XDP firewall
 *
 *   xdp_fw      (XDP, ingress)  blocklist, ICMP rule, rate limiting, conntrack check
 *   tc_egress   (TC,  egress)   records locally initiated sessions for conntrack
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* linux/icmp.h pulls in libc headers, so define the bits we need. */
#define ICMP_ECHOREPLY 0
#define ICMP_ECHO      8
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct icmphdr {
	__u8  type;
	__u8  code;
	__sum16 checksum;
	union {
		struct { __be16 id; __be16 sequence; } echo;
		__be32 gateway;
	} un;
};
#include "common.h"

#define NSEC 1000000000ULL

/* Conntrack idle timeouts. */
#define CT_TCP_EST_TIMEOUT   (600 * NSEC)
#define CT_TCP_SHORT_TIMEOUT (30 * NSEC)
#define CT_UDP_TIMEOUT       (60 * NSEC)
#define CT_ICMP_TIMEOUT      (30 * NSEC)

/* ---------------------------------------------------------------- maps -- */

/* Level 2: admin-managed blocklist. key = IPv4 (network order), value = drops */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} blocklist SEC(".maps");

/* Inbound TCP/UDP ports always allowed while conntrack is on (e.g. ssh). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u16);  /* host order */
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} allow_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CFG_MAX);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, ST_MAX);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} stats SEC(".maps");

/* Level 3: per-source packet rate. LRU so a spoofed flood can't fill it. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 131072);
	__type(key, __u32);
	__type(value, struct rate_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rate SEC(".maps");

/* Level 4: connection table. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct ct_key);
	__type(value, struct ct_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack SEC(".maps");

/* ------------------------------------------------------------- helpers -- */

static __always_inline __u32 cfg(__u32 key)
{
	__u32 *v = bpf_map_lookup_elem(&config, &key);
	return v ? *v : 0;
}

static __always_inline void count(__u32 key)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &key);
	if (v)
		(*v)++;
}

#define LOG_DROP(why, ip, proto)                                              \
	do {                                                                  \
		if (cfg(CFG_LOG)) {                                           \
			__u32 _h = bpf_ntohl(ip);                             \
			bpf_printk("xdpfw DROP %s src=%d.%d.%d.%d proto=%d", why, \
				   _h >> 24, (_h >> 16) & 0xff, (_h >> 8) & 0xff, \
				   _h & 0xff, proto);                         \
		}                                                             \
	} while (0)

struct pkt {
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct icmphdr *icmp;
};

/* Bounds-checked header parsing. Returns 0 for IPv4, -1 otherwise. */
static __always_inline int parse(void *data, void *end, struct pkt *p)
{
	struct ethhdr *eth = data;
	void *cur = eth + 1;
	__u16 proto;

	if (cur > end)
		return -1;
	proto = eth->h_proto;

	if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vh = cur;
		if ((void *)(vh + 1) > end)
			return -1;
		proto = vh->h_vlan_encapsulated_proto;
		cur = vh + 1;
	}
	if (proto != bpf_htons(ETH_P_IP))
		return -1;

	p->ip = cur;
	if ((void *)(p->ip + 1) > end || p->ip->ihl < 5)
		return -1;
	cur = (void *)p->ip + p->ip->ihl * 4;

	/* Non-first fragments carry no L4 header. */
	if (p->ip->frag_off & bpf_htons(0x1fff))
		return 0;

	switch (p->ip->protocol) {
	case IPPROTO_TCP:
		p->tcp = cur;
		if ((void *)(p->tcp + 1) > end)
			p->tcp = 0;
		break;
	case IPPROTO_UDP:
		p->udp = cur;
		if ((void *)(p->udp + 1) > end)
			p->udp = 0;
		break;
	case IPPROTO_ICMP:
		p->icmp = cur;
		if ((void *)(p->icmp + 1) > end)
			p->icmp = 0;
		break;
	}
	return 0;
}

/* Level 3: returns 0 = ok, ST_DROP_RATE / ST_DROP_SYN = drop. */
static __always_inline int rate_check(__u32 src, int is_syn)
{
	__u32 pps = cfg(CFG_RATE_PPS), syn_pps = cfg(CFG_SYN_PPS);
	__u64 now = bpf_ktime_get_ns();
	struct rate_info *r, init = {};

	if (!pps && !syn_pps)
		return 0;

	r = bpf_map_lookup_elem(&rate, &src);
	if (!r) {
		init.window_start = now;
		init.pkts = 1;
		init.syns = is_syn;
		bpf_map_update_elem(&rate, &src, &init, BPF_ANY);
		return 0;
	}

	if (r->banned_until) {
		if (now < r->banned_until)
			return ST_DROP_RATE;
		r->banned_until = 0; /* ban expired */
	}

	if (now - r->window_start >= NSEC) {
		r->window_start = now;
		r->pkts = 0;
		r->syns = 0;
	}
	__sync_fetch_and_add(&r->pkts, 1);
	if (is_syn)
		__sync_fetch_and_add(&r->syns, 1);

	if (syn_pps && r->syns > syn_pps) {
		r->banned_until = now + (__u64)cfg(CFG_BAN_SECS) * NSEC;
		return ST_DROP_SYN;
	}
	if (pps && r->pkts > pps) {
		r->banned_until = now + (__u64)cfg(CFG_BAN_SECS) * NSEC;
		return ST_DROP_RATE;
	}
	return 0;
}

static __always_inline __u64 ct_timeout(__u8 state)
{
	switch (state) {
	case CT_ESTABLISHED: return CT_TCP_EST_TIMEOUT;
	case CT_UDP:         return CT_UDP_TIMEOUT;
	case CT_ICMP:        return CT_ICMP_TIMEOUT;
	default:             return CT_TCP_SHORT_TIMEOUT;
	}
}

/* Level 4: is this inbound packet part of a session we started? */
static __always_inline int ct_allow_inbound(struct pkt *p)
{
	struct ct_key k = {};
	struct ct_val *v;
	__u64 now = bpf_ktime_get_ns();
	__u16 dport = 0;

	k.src_ip = p->ip->saddr;
	k.dst_ip = p->ip->daddr;
	k.proto = p->ip->protocol;

	if (p->tcp) {
		k.src_port = p->tcp->source;
		k.dst_port = p->tcp->dest;
		dport = bpf_ntohs(p->tcp->dest);
	} else if (p->udp) {
		k.src_port = p->udp->source;
		k.dst_port = p->udp->dest;
		dport = bpf_ntohs(p->udp->dest);
	} else if (p->icmp) {
		/* Only replies to our pings are tracked; errors etc. dropped. */
		if (p->icmp->type != ICMP_ECHOREPLY)
			return 0;
		k.src_port = p->icmp->un.echo.id;
	} else {
		return 0; /* fragments / other protocols: unsolicited */
	}

	/* Services we explicitly expose (e.g. ssh) bypass the state check. */
	if (dport && bpf_map_lookup_elem(&allow_ports, &dport))
		return 1;

	v = bpf_map_lookup_elem(&conntrack, &k);
	if (!v)
		return 0;
	if (now - v->last_seen > ct_timeout(v->state)) {
		bpf_map_delete_elem(&conntrack, &k);
		return 0;
	}

	if (p->tcp) {
		if (v->state == CT_SYN_SENT) {
			/* Only a SYN-ACK or RST is a valid answer to our SYN. */
			if (!(p->tcp->syn && p->tcp->ack) && !p->tcp->rst)
				return 0;
			if (p->tcp->syn)
				v->state = CT_ESTABLISHED;
		}
		if (p->tcp->fin)
			v->state = CT_CLOSING;
		if (p->tcp->rst) {
			bpf_map_delete_elem(&conntrack, &k);
			return 1;
		}
	}
	v->last_seen = now;
	__sync_fetch_and_add(&v->pkts_in, 1);
	return 1;
}

/* ------------------------------------------------------------ programs -- */

SEC("xdp")
int xdp_fw(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	struct pkt p = {};
	__u64 *hits;
	__u32 src;
	int r;

	if (parse(data, end, &p) < 0)
		goto pass; /* non-IPv4 (ARP, IPv6, ...) is out of scope */
	src = p.ip->saddr;

	/* Level 2: dynamic blocklist */
	hits = bpf_map_lookup_elem(&blocklist, &src);
	if (hits) {
		__sync_fetch_and_add(hits, 1);
		count(ST_DROP_BLOCKLIST);
		LOG_DROP("blocklist", src, p.ip->protocol);
		return XDP_DROP;
	}

	/* Level 1: stateless protocol rule */
	if (p.icmp && p.icmp->type == ICMP_ECHO && cfg(CFG_BLOCK_ICMP)) {
		count(ST_DROP_ICMP);
		LOG_DROP("icmp-echo", src, p.ip->protocol);
		return XDP_DROP;
	}

	/* Level 3: rate limiting / SYN flood */
	r = rate_check(src, p.tcp && p.tcp->syn && !p.tcp->ack);
	if (r) {
		count(r);
		LOG_DROP(r == ST_DROP_SYN ? "syn-flood" : "rate-limit", src, p.ip->protocol);
		return XDP_DROP;
	}

	/* Level 4: stateful */
	if (cfg(CFG_CONNTRACK) && !ct_allow_inbound(&p)) {
		count(ST_DROP_CONNTRACK);
		LOG_DROP("unsolicited", src, p.ip->protocol);
		return XDP_DROP;
	}

pass:
	count(ST_PASS);
	return XDP_PASS;
}

/*
 * Egress hook: XDP only sees ingress, so outgoing packets are observed
 * with a TC classifier and recorded in the shared conntrack map.
 */
SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;
	struct pkt p = {};
	struct ct_key k = {};
	struct ct_val *v, nv = {};
	__u64 now = bpf_ktime_get_ns();

	if (parse(data, end, &p) < 0)
		return TC_ACT_OK;

	/* Key from the reply's (inbound) point of view. */
	k.src_ip = p.ip->daddr;
	k.dst_ip = p.ip->saddr;
	k.proto = p.ip->protocol;

	if (p.tcp) {
		k.src_port = p.tcp->dest;
		k.dst_port = p.tcp->source;
	} else if (p.udp) {
		k.src_port = p.udp->dest;
		k.dst_port = p.udp->source;
	} else if (p.icmp && p.icmp->type == ICMP_ECHO) {
		k.src_port = p.icmp->un.echo.id;
	} else {
		return TC_ACT_OK;
	}

	v = bpf_map_lookup_elem(&conntrack, &k);
	if (v) {
		v->last_seen = now;
		__sync_fetch_and_add(&v->pkts_out, 1);
		if (p.tcp) {
			if (p.tcp->rst)
				bpf_map_delete_elem(&conntrack, &k);
			else if (p.tcp->fin)
				v->state = CT_CLOSING;
		}
		return TC_ACT_OK;
	}

	/* New flow: only a pure SYN starts a TCP session. */
	if (p.tcp) {
		if (!p.tcp->syn || p.tcp->ack)
			return TC_ACT_OK;
		nv.state = CT_SYN_SENT;
	} else if (p.udp) {
		nv.state = CT_UDP;
	} else {
		nv.state = CT_ICMP;
	}
	nv.last_seen = now;
	nv.pkts_out = 1;
	bpf_map_update_elem(&conntrack, &k, &nv, BPF_ANY);
	count(ST_CT_NEW);
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
