# bpf-xdp-go-template

A GitHub template repository with the scaffolding for a XDP program developed with [libbpf/libbpf] and BPF CO-RE.
The loader is written in Go and is using the [cilium/ebpf] library to manage BPF objects, i.e. load BPF programs,
access BPF maps, etc.

## Usage

Create a new repository from this template by clicking the **Use this template** button in the GitHub interface.
Once it's done, clone and change current directory to the cloned repository:

```
$ git clone https://github.com/$owner/$repo.git
$ cd $repo
$ git submodule update --init --recursive
```

Compile BPF program and Go loader:

```
$ make -C src
```

Run the application:

``` console
# ./src/xdp --interface=eth0
```

If everything is fine, you can start modifying the scaffolding to adjust the XDP program to your needs.
To verify that the `xdp_prog_func` XDP program was attached to the `eth0` interface inspect the output
of the `ip address show` command:

``` console
$ ip a show dev eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric/id:21 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:e1:bb:04 brd ff:ff:ff:ff:ff:ff
    inet 192.168.10.130/24 brd 192.168.10.255 scope global dynamic noprefixroute eth0
       valid_lft 1417sec preferred_lft 1417sec
    inet6 fe80::20c:29ff:fee1:bb04/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
```

Notice that there is the `xdpgeneric/id:21` entry, which indicates that the program was indeed attached,
and its id is `21`. You can further inspect the program with the `btftool` command:

``` console
# bpftool prog show id 21
21: xdp  name xdp_prog_func  tag 50fcfa8b9d387625  gpl
        loaded_at 2023-03-03T10:10:37+0100  uid 0
        xlated 208B  jited 123B  memlock 4096B  map_ids 3
        btf_id 147
```

``` console
# bpftool prog dump xlated name xdp_prog_func
int xdp_prog_func(struct xdp_md * ctx):
; void *data_end = (void *)(long)ctx->data_end;
   0: (79) r2 = *(u64 *)(r1 +8)
; void *data = (void *)(long)ctx->data;
   1: (79) r1 = *(u64 *)(r1 +0)
; if ((void *)(eth + 1) > data_end) {
   2: (bf) r3 = r1
   3: (07) r3 += 14
; if ((void *)(eth + 1) > data_end) {
   4: (2d) if r3 > r2 goto pc+19
; if (eth->h_proto != bpf_htons(ETH_P_IP)) {
   5: (69) r3 = *(u16 *)(r1 +12)
; if (eth->h_proto != bpf_htons(ETH_P_IP)) {
   6: (55) if r3 != 0x8 goto pc+17
   7: (bf) r3 = r1
   8: (07) r3 += 34
   9: (2d) if r3 > r2 goto pc+14
  10: (07) r1 += 14
; *ip_dst_addr = (__u32)(ip->daddr);
  11: (61) r7 = *(u32 *)(r1 +16)
; *ip_src_addr = (__u32)(ip->saddr);
  12: (61) r6 = *(u32 *)(r1 +12)
; event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  13: (18) r1 = map[id:68]
  15: (b7) r2 = 8
  16: (b7) r3 = 0
  17: (85) call bpf_ringbuf_reserve#231472
; if (!event) {
  18: (15) if r0 == 0x0 goto pc+5
; event->ip_dst = ip_dst;
  19: (63) *(u32 *)(r0 +4) = r7
; event->ip_src = ip_src;
  20: (63) *(u32 *)(r0 +0) = r6
; bpf_ringbuf_submit(event, 0);
  21: (bf) r1 = r0
  22: (b7) r2 = 0
  23: (85) call bpf_ringbuf_submit#232416
; return XDP_PASS;
  24: (b7) r0 = 2
  25: (95) exit
```

[libbpf/libbpf]: https://github.com/libbpf/libbpf
[libbpf/libbpf-bootstrap]: https://github.com/libbpf/libbpf-bootstrap
[cilium/ebpf]: https://github.com/cilium/ebpf
