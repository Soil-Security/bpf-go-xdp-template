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

static __always_inline void cursor_init(struct xdp_md *ctx, struct cursor *c) {
  c->data = (void *)(long)ctx->data;
  c->end = (void *)(long)ctx->data_end;
}

static __always_inline struct ethhdr *parse_ethhdr(struct cursor *c) {
  if (c->data + sizeof(struct ethhdr) > c->end) {
    return 0;
  }
  struct ethhdr *ret = c->data;
  c->data += sizeof(struct ethhdr);
  return ret;
}

static __always_inline struct iphdr *parse_iphdr(struct cursor *c) {
  if (c->data + sizeof(struct iphdr) > c->end) {
    return 0;
  }
  struct iphdr *ret = c->data;
  c->data += sizeof(struct iphdr);
  return ret;
}

static __always_inline struct udphdr *parse_udphdr(struct cursor *c) {
  if (c->data + sizeof(struct udphdr) > c->end) {
    return 0;
  }
  struct udphdr *ret = c->data;
  c->data += sizeof(struct udphdr);
  return ret;
}

static __always_inline struct dnshdr *parse_dnshdr(struct cursor *c) {
  if (c->data + sizeof(struct dnshdr) > c->end) {
    return 0;
  }
  struct dnshdr *ret = c->data;
  c->data += sizeof(struct dnshdr);
  return ret;
}

static __always_inline int parse_qname(struct cursor *c, char *qname) {
  __builtin_memset(qname, 0, DNS_NAME_MAX);
  __u8 label_cursor = 0;

  // The loop starts with '-1', because the first char will be '.'
  // and we want to bypass it, check (i == -1) statement for details.
  for (__s16 i = -1; i < 128; i++, c->data++) {
    if (c->data + 1 > c->end) {
      return -1; // packet is too short.
    }

    if (*(__u8 *)c->data == 0) {
      c->data += sizeof(__u8);
      break; // end of domain name.
    }

    if (label_cursor == 0) {
      // the cursor is on a label length byte.
      __u8 new_label_length = *(__u8 *)c->data;
      if (c->data + new_label_length > c->end) {
        return -1; // packet is too short.
      }
      label_cursor = new_label_length;
      if (i == -1) {
        // This is the first label, no need to set '.'
        continue;
      }
      qname[i] = '.';
      continue;
    }

    label_cursor--;
    qname[i] = *(char *)c->data;
  }

  return 1;
}

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
  struct cursor c = {.data = NULL, .end = NULL};

  struct ethhdr *eth;
  struct iphdr *ip;
  struct udphdr *udp;
  struct dnshdr *dns;

  cursor_init(ctx, &c);

  if (!(eth = parse_ethhdr(&c))) {
    return 0;
  }

  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return 0;
  }

  if (!(ip = parse_iphdr(&c))) {
    return 0;
  }

  if (ip->protocol != IPPROTO_UDP) {
    return 0;
  }

  if (!(udp = parse_udphdr(&c))) {
    return 0;
  }

  if (udp->source != bpf_htons(DNS_PORT)) {
    return 0;
  }

  if (!(dns = parse_dnshdr(&c))) {
    return 0;
  }

  if (dns->flags.qr != DNS_QR_RESPONSE) {
    return 0;
  }

  if (dns->flags.opcode != DNS_OPCODE_QUERY) {
    return 0;
  }

  if (dns->flags.rcode != DNS_RCODE_NO_ERROR) {
    return 0;
  }

  if (!parse_qname(&c, &e->qname.name[0])) {
    return 0;
  }

  bpf_printk("qname: %s", e->qname.name);

  e->ip_src = ip->saddr;
  e->ip_dst = ip->daddr;
  e->udp_src = bpf_ntohs(udp->source);
  e->udp_dst = bpf_ntohs(udp->dest);
  e->dns_id = bpf_ntohs(dns->id);
  e->dns_qdcount = bpf_ntohs(dns->qdcount);
  e->dns_ancount = bpf_ntohs(dns->ancount);

  return 1;
}
