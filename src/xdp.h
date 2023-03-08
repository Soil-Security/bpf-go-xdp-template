//+build ignore

#ifndef __XDP_H
#define __XDP_H

#include "vmlinux.h"

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/

struct event {
  __u32 ip_src;
  __u32 ip_dst;
  __u8 ip_protocol;
  __u16 udp_src;
  __u16 udp_dst;
} __attribute__((packed));

#endif /* __XDP_H */
