//+build ignore

#ifndef __XDP_H
#define __XDP_H

#include "vmlinux.h"

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/

#define DNS_PORT 53

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

struct event {
    __u32 ip_src;
    __u32 ip_dst;
    __u16 udp_src;
    __u16 udp_dst;
} __attribute__((packed));

#endif /* __XDP_H */
