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

static __always_inline int parse_event(struct xdp_md *ctx, struct event *e);

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
  struct event *event;

  event = (struct event *)bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (event == NULL) {
    goto done;
  }

  if (!parse_event(ctx, event)) {
    bpf_ringbuf_discard(event, 0);
    goto done;
  }

  bpf_ringbuf_submit(event, 0);

done:
  return XDP_PASS;
}

static __always_inline int parse_event(struct xdp_md *ctx, struct event *e) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = (struct ethhdr *)data;
  if (data + sizeof(struct ethhdr) > data_end) {
    return 0;
  }
  data += sizeof(struct ethhdr);

  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return 0;
  }

  struct iphdr *ip = (struct iphdr *)data;
  if (data + sizeof(struct iphdr) > data_end) {
    return 0;
  }
  data += sizeof(struct iphdr);

  // Return the source IP address in network byte order.
  e->ip_src = ip->saddr;
  e->ip_dst = ip->daddr;
  e->ip_protocol = ip->protocol;

  return 1;
}