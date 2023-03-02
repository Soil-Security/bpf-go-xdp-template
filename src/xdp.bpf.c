//+build ignore

#include "xdp.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
Attempt to parse the IPv4 source and destination addresses from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int parse_ip_addr(struct xdp_md *ctx, __u32 *ip_src_addr,
                                         __u32 *ip_dst_addr);

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
  __u32 ip_src, ip_dst;
  struct event *event;

  if (!parse_ip_addr(ctx, &ip_src, &ip_dst)) {
    goto done;
  }

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    goto done;
  }

  event->ip_src = ip_src;
  event->ip_dst = ip_dst;

  bpf_ringbuf_submit(event, 0);

done:
  return XDP_PASS;
}

static __always_inline int parse_ip_addr(struct xdp_md *ctx, __u32 *ip_src_addr,
                                         __u32 *ip_dst_addr) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // First, parse the ethernet header.
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return 0;
  }

  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    // The protocol is not IPv4, so we can't parse an IPv4 source address.
    return 0;
  }

  // Then parse the IP header.
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) {
    return 0;
  }

  // Return the source IP address in network byte order.
  *ip_src_addr = (__u32)(ip->saddr);
  *ip_dst_addr = (__u32)(ip->daddr);
  return 1;
}