// SPDX-License-Identifier: GPL-2.0
/*
 * xdpfw - control plane for the XDP firewall.
 *
 * `load` attaches the programs and pins every map under /sys/fs/bpf/xdpfw.
 * All other commands open the pinned maps, so rules change on the fly
 * without reloading the XDP program.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common.h"

#ifndef BPF_OBJ_PATH
#define BPF_OBJ_PATH "build/xdpfw.bpf.o"
#endif
#define STATE_FILE "/run/xdpfw.ifindex"

static const char *cfg_names[CFG_MAX] = {
	[CFG_BLOCK_ICMP] = "icmp",
	[CFG_RATE_PPS]   = "rate",
	[CFG_SYN_PPS]    = "syn",
	[CFG_BAN_SECS]   = "ban",
	[CFG_CONNTRACK]  = "conntrack",
	[CFG_LOG]        = "log",
};

static const char *stat_names[ST_MAX] = {
	[ST_PASS]           = "passed",
	[ST_DROP_ICMP]      = "dropped: icmp rule",
	[ST_DROP_BLOCKLIST] = "dropped: blocklist",
	[ST_DROP_RATE]      = "dropped: rate limit",
	[ST_DROP_SYN]       = "dropped: syn flood",
	[ST_DROP_CONNTRACK] = "dropped: unsolicited",
	[ST_CT_NEW]         = "conntrack: new flows",
};

static void usage(void)
{
	fprintf(stderr,
		"usage: xdpfw <command> [args]\n\n"
		"  load <iface> [skb|native]   attach firewall (default: native, falls back to skb)\n"
		"  unload                      detach and remove pinned maps\n"
		"  block <ip>                  add IP to blocklist\n"
		"  unblock <ip>                remove IP from blocklist\n"
		"  list                        show blocklist with drop counters\n"
		"  set <key> <value>           keys: icmp, rate, syn, ban, conntrack, log\n"
		"  config                      show current config\n"
		"  allow <port> | disallow <port>  inbound ports that bypass conntrack\n"
		"  stats                       packet counters\n"
		"  rates                       per-source rate table (banned sources marked)\n"
		"  conns                       connection tracking table\n"
		"  flush <rates|conns|blocklist>\n");
	exit(1);
}

static int open_map(const char *name)
{
	char path[256];
	int fd;

	snprintf(path, sizeof(path), PIN_DIR "/%s", name);
	fd = bpf_obj_get(path);
	if (fd < 0) {
		fprintf(stderr, "cannot open %s: %s (is the firewall loaded?)\n",
			path, strerror(errno));
		exit(1);
	}
	return fd;
}

static __u32 parse_ip(const char *s)
{
	struct in_addr a;

	if (inet_pton(AF_INET, s, &a) != 1) {
		fprintf(stderr, "invalid IPv4 address: %s\n", s);
		exit(1);
	}
	return a.s_addr;
}

static const char *ip_str(__u32 ip)
{
	static char buf[4][INET_ADDRSTRLEN];
	static int i;

	i = (i + 1) % 4;
	inet_ntop(AF_INET, &ip, buf[i], sizeof(buf[i]));
	return buf[i];
}

static __u64 now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts); /* same clock as bpf_ktime_get_ns */
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void set_cfg(int fd, __u32 key, __u32 val)
{
	if (bpf_map_update_elem(fd, &key, &val, BPF_ANY)) {
		perror("config update");
		exit(1);
	}
}

/* ---------------------------------------------------------- load/unload -- */

static int cmd_load(const char *ifname, const char *mode)
{
	struct bpf_object *obj;
	struct bpf_program *xdp, *tc;
	unsigned int ifindex = if_nametoindex(ifname);
	__u32 flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
	int err, cfd;
	FILE *f;

	if (!ifindex) {
		fprintf(stderr, "unknown interface %s\n", ifname);
		return 1;
	}

	LIBBPF_OPTS(bpf_object_open_opts, oopts, .pin_root_path = PIN_DIR);
	obj = bpf_object__open_file(BPF_OBJ_PATH, &oopts);
	if (!obj) {
		fprintf(stderr, "open %s failed\n", BPF_OBJ_PATH);
		return 1;
	}
	if ((err = bpf_object__load(obj))) {
		fprintf(stderr, "load failed: %s\n", strerror(-err));
		return 1;
	}
	xdp = bpf_object__find_program_by_name(obj, "xdp_fw");
	tc = bpf_object__find_program_by_name(obj, "tc_egress");

	/* XDP ingress */
	if (mode && !strcmp(mode, "skb")) {
		err = bpf_xdp_attach(ifindex, bpf_program__fd(xdp),
				     flags | XDP_FLAGS_SKB_MODE, NULL);
	} else {
		err = bpf_xdp_attach(ifindex, bpf_program__fd(xdp),
				     flags | XDP_FLAGS_DRV_MODE, NULL);
		if (err && !(mode && !strcmp(mode, "native"))) {
			fprintf(stderr, "native XDP unavailable, using skb mode\n");
			err = bpf_xdp_attach(ifindex, bpf_program__fd(xdp),
					     flags | XDP_FLAGS_SKB_MODE, NULL);
		}
	}
	if (err) {
		fprintf(stderr, "XDP attach failed: %s\n", strerror(-err));
		return 1;
	}

	/* TC egress, used by conntrack */
	LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);
	LIBBPF_OPTS(bpf_tc_opts, topts, .handle = 1, .priority = 1,
		    .prog_fd = bpf_program__fd(tc));
	err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "tc hook failed: %s\n", strerror(-err));
		return 1;
	}
	if ((err = bpf_tc_attach(&hook, &topts))) {
		fprintf(stderr, "tc attach failed: %s\n", strerror(-err));
		return 1;
	}

	/* Defaults */
	cfd = bpf_map__fd(bpf_object__find_map_by_name(obj, "config"));
	set_cfg(cfd, CFG_BLOCK_ICMP, 1);
	set_cfg(cfd, CFG_BAN_SECS, 10);
	set_cfg(cfd, CFG_LOG, 1);

	f = fopen(STATE_FILE, "w");
	if (f) {
		fprintf(f, "%u\n", ifindex);
		fclose(f);
	}
	printf("xdpfw attached to %s (ifindex %u), maps pinned in %s\n",
	       ifname, ifindex, PIN_DIR);
	return 0;
}

static int cmd_unload(void)
{
	static const char *maps[] = { "blocklist", "allow_ports", "config",
				      "stats", "rate", "conntrack" };
	unsigned int ifindex = 0;
	char path[256];
	FILE *f = fopen(STATE_FILE, "r");

	if (!f || fscanf(f, "%u", &ifindex) != 1) {
		fprintf(stderr, "firewall not loaded\n");
		return 1;
	}
	fclose(f);

	bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
	bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
	LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);
	hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS; /* removes the clsact qdisc */
	bpf_tc_hook_destroy(&hook);

	for (size_t i = 0; i < sizeof(maps) / sizeof(*maps); i++) {
		snprintf(path, sizeof(path), PIN_DIR "/%s", maps[i]);
		unlink(path);
	}
	unlink(STATE_FILE);
	rmdir(PIN_DIR);
	printf("xdpfw detached\n");
	return 0;
}

/* ------------------------------------------------------------ commands -- */

static int cmd_block(const char *s, int add)
{
	int fd = open_map("blocklist");
	__u32 ip = parse_ip(s);
	__u64 zero = 0;

	if (add) {
		if (bpf_map_update_elem(fd, &ip, &zero, BPF_NOEXIST)) {
			fprintf(stderr, "%s already blocked\n", s);
			return 1;
		}
		printf("blocked %s\n", s);
	} else {
		if (bpf_map_delete_elem(fd, &ip)) {
			fprintf(stderr, "%s not in blocklist\n", s);
			return 1;
		}
		printf("unblocked %s\n", s);
	}
	return 0;
}

static int cmd_list(void)
{
	int fd = open_map("blocklist");
	__u32 key, *prev = NULL;
	__u64 hits;
	int n = 0;

	printf("%-18s %s\n", "BLOCKED IP", "DROPS");
	while (!bpf_map_get_next_key(fd, prev, &key)) {
		if (!bpf_map_lookup_elem(fd, &key, &hits)) {
			printf("%-18s %llu\n", ip_str(key), (unsigned long long)hits);
			n++;
		}
		prev = &key;
	}
	printf("(%d entries)\n", n);
	return 0;
}

static int cmd_set(const char *name, const char *val)
{
	int fd = open_map("config");
	__u32 v;

	if (!strcmp(val, "on"))
		v = 1;
	else if (!strcmp(val, "off"))
		v = 0;
	else
		v = strtoul(val, NULL, 10);

	for (__u32 k = 0; k < CFG_MAX; k++) {
		if (!strcmp(name, cfg_names[k])) {
			set_cfg(fd, k, v);
			printf("%s = %u\n", name, v);
			return 0;
		}
	}
	fprintf(stderr, "unknown key %s\n", name);
	return 1;
}

static int cmd_config(void)
{
	int fd = open_map("config");
	__u32 v;

	for (__u32 k = 0; k < CFG_MAX; k++) {
		bpf_map_lookup_elem(fd, &k, &v);
		printf("%-10s %u\n", cfg_names[k], v);
	}
	return 0;
}

static int cmd_allow(const char *p, int add)
{
	int fd = open_map("allow_ports");
	__u16 port = atoi(p);
	__u8 one = 1;
	int err = add ? bpf_map_update_elem(fd, &port, &one, BPF_ANY)
		      : bpf_map_delete_elem(fd, &port);

	if (err) {
		fprintf(stderr, "failed: %s\n", strerror(errno));
		return 1;
	}
	printf("port %u %s\n", port, add ? "allowed" : "removed");
	return 0;
}

static int cmd_stats(void)
{
	int fd = open_map("stats");
	int ncpu = libbpf_num_possible_cpus();
	__u64 vals[ncpu];

	for (__u32 k = 0; k < ST_MAX; k++) {
		__u64 sum = 0;
		if (!bpf_map_lookup_elem(fd, &k, vals))
			for (int c = 0; c < ncpu; c++)
				sum += vals[c];
		printf("%-24s %llu\n", stat_names[k], (unsigned long long)sum);
	}
	return 0;
}

static int cmd_rates(void)
{
	int fd = open_map("rate");
	__u32 key, *prev = NULL;
	struct rate_info r;
	__u64 now = now_ns();

	printf("%-18s %8s %8s  %s\n", "SOURCE", "PKTS/s", "SYNS/s", "STATUS");
	while (!bpf_map_get_next_key(fd, prev, &key)) {
		if (!bpf_map_lookup_elem(fd, &key, &r)) {
			int fresh = now - r.window_start < 2000000000ULL;
			char st[64] = "ok";
			if (r.banned_until > now)
				snprintf(st, sizeof(st), "BANNED (%llus left)",
					 (unsigned long long)((r.banned_until - now) / 1000000000ULL) + 1);
			printf("%-18s %8u %8u  %s\n", ip_str(key),
			       fresh ? r.pkts : 0, fresh ? r.syns : 0, st);
		}
		prev = &key;
	}
	return 0;
}

static const char *ct_state_str(__u8 s)
{
	switch (s) {
	case CT_SYN_SENT:    return "SYN_SENT";
	case CT_ESTABLISHED: return "ESTABLISHED";
	case CT_CLOSING:     return "CLOSING";
	case CT_UDP:         return "UDP";
	case CT_ICMP:        return "ICMP";
	default:             return "?";
	}
}

static int cmd_conns(void)
{
	int fd = open_map("conntrack");
	struct ct_key key, *prev = NULL;
	struct ct_val v;
	__u64 now = now_ns();
	char local[32], remote[32];

	printf("%-5s %-22s %-22s %-12s %6s %6s %5s\n", "PROTO", "LOCAL", "REMOTE",
	       "STATE", "OUT", "IN", "IDLE");
	while (!bpf_map_get_next_key(fd, prev, &key)) {
		if (!bpf_map_lookup_elem(fd, &key, &v)) {
			const char *pr = key.proto == 6 ? "tcp" : key.proto == 17 ? "udp" : "icmp";
			snprintf(local, sizeof(local), "%s:%u", ip_str(key.dst_ip), ntohs(key.dst_port));
			snprintf(remote, sizeof(remote), "%s:%u", ip_str(key.src_ip), ntohs(key.src_port));
			printf("%-5s %-22s %-22s %-12s %6llu %6llu %4llus\n", pr, local, remote,
			       ct_state_str(v.state), (unsigned long long)v.pkts_out,
			       (unsigned long long)v.pkts_in,
			       (unsigned long long)((now - v.last_seen) / 1000000000ULL));
		}
		prev = &key;
	}
	return 0;
}

static int cmd_flush(const char *what)
{
	int fd = open_map(what);
	char key[64], next[64];

	while (!bpf_map_get_next_key(fd, NULL, next)) {
		memcpy(key, next, sizeof(key));
		bpf_map_delete_elem(fd, key);
	}
	printf("flushed %s\n", what);
	return 0;
}

int main(int argc, char **argv)
{
	const char *c;

	if (argc < 2)
		usage();
	c = argv[1];

	if (!strcmp(c, "load") && argc >= 3)
		return cmd_load(argv[2], argc > 3 ? argv[3] : NULL);
	if (!strcmp(c, "unload"))
		return cmd_unload();
	if (!strcmp(c, "block") && argc == 3)
		return cmd_block(argv[2], 1);
	if (!strcmp(c, "unblock") && argc == 3)
		return cmd_block(argv[2], 0);
	if (!strcmp(c, "list"))
		return cmd_list();
	if (!strcmp(c, "set") && argc == 4)
		return cmd_set(argv[2], argv[3]);
	if (!strcmp(c, "config"))
		return cmd_config();
	if (!strcmp(c, "allow") && argc == 3)
		return cmd_allow(argv[2], 1);
	if (!strcmp(c, "disallow") && argc == 3)
		return cmd_allow(argv[2], 0);
	if (!strcmp(c, "stats"))
		return cmd_stats();
	if (!strcmp(c, "rates"))
		return cmd_rates();
	if (!strcmp(c, "conns"))
		return cmd_conns();
	if (!strcmp(c, "flush") && argc == 3 &&
	    (!strcmp(argv[2], "rates") || !strcmp(argv[2], "conntrack") ||
	     !strcmp(argv[2], "conns") || !strcmp(argv[2], "blocklist")))
		return cmd_flush(!strcmp(argv[2], "rates") ? "rate" :
				 !strcmp(argv[2], "conns") ? "conntrack" : argv[2]);
	usage();
	return 1;
}
