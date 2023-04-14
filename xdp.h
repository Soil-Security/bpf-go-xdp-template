//+build ignore

#ifndef __XDP_H
#define __XDP_H

#include "vmlinux.h"

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/

#define DNS_PORT 53
#define DNS_NAME_MAX 256

#define DNS_QR_RESPONSE 1
#define DNS_OPCODE_QUERY 0
#define DNS_RCODE_NO_ERROR 0

struct cursor {
  void *data;
  void *end;
} __attribute__((packed));

struct dnshdr {
  __be16 id;
  struct {
    __u8 rd : 1;
    __u8 tc : 1;
    __u8 aa : 1;
    __u8 opcode : 4;
    __u8 qr : 1;
    __u8 rcode : 4;
    __u8 cd : 1;
    __u8 ad : 1;
    __u8 z : 1;
    __u8 ra : 1;
  } flags;
  __be16 qdcount;
  __be16 ancount;
  __be16 nscount;
  __be16 arcount;
} __attribute__((packed));

struct dnsqname {
  char name[DNS_NAME_MAX];
} __attribute__((packed));

struct dnsquestion {
  __be16 qtype;
  __be16 qclass;
} __attribute__((packed));

struct event {
  __u32 ip_src;
  __u32 ip_dst;
  __u16 udp_src;
  __u16 udp_dst;
  __u16 dns_id;
  __u16 dns_qdcount;
  __u16 dns_ancount;
  struct dnsqname qname;
} __attribute__((packed));

#endif /* __XDP_H */
