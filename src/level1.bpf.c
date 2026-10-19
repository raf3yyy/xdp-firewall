// SPDX-License-Identifier: GPL-2.0
/*
 * Level 1: minimal stateless firewall with a hardcoded rule.
 * Drops every inbound ICMP echo request and logs it to the trace pipe.
 *
 *   ip link set dev eth0 xdpgeneric obj build/level1.bpf.o sec xdp
 *   cat /sys/kernel/tracing/trace_pipe
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* linux/icmp.h pulls in libc headers, so define the bits we need. */
#define ICMP_ECHOREPLY 0
#define ICMP_ECHO      8
struct icmphdr {
	__u8  type;
	__u8  code;
	__sum16 checksum;
	union {
		struct { __be16 id; __be16 sequence; } echo;
		__be32 gateway;
	} un;
};

SEC("xdp")
int xdp_drop_icmp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct icmphdr *icmp;

	/* Every access must be bounds-checked or the verifier rejects us. */
	if ((void *)(eth + 1) > end || eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > end || ip->protocol != IPPROTO_ICMP)
		return XDP_PASS;

	icmp = (void *)ip + ip->ihl * 4;
	if ((void *)(icmp + 1) > end)
		return XDP_PASS;

	if (icmp->type == ICMP_ECHO) {
		__u32 s = bpf_ntohl(ip->saddr);
		bpf_printk("level1 DROP icmp-echo src=%d.%d.%d.%d id=%d seq=%d",
			   s >> 24, (s >> 16) & 0xff, (s >> 8) & 0xff, s & 0xff,
			   bpf_ntohs(icmp->un.echo.id), bpf_ntohs(icmp->un.echo.sequence));
		return XDP_DROP;
	}
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
