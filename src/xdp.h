//+build ignore

#ifndef __XDP_H
#define __XDP_H

#include "vmlinux.h"

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/

struct event {
  __u32 ip_src;
  __u32 ip_dst;
};

#endif /* __XDP_H */
