# bpf-xdp-go-template

A GitHub template repository with the scaffolding for a XDP program developed with [libbpf/libbpf] and BPF CO-RE.
The loader is written in Go and leverages the [cilium/ebpf] library.

## Usage

Create a new repository from this template by clicking the **Use this template** button in the GitHub interface.
Once it's done, clone and change current directory to the cloned repository:

```
git clone https://github.com/$owner/$repo.git
cd $repo
git submodule update --init --recursive
```

Compile BPF application and Go loader:

```
make -C src
```

Run the application:

```
sudo ./src/xdp --interface=eth0
```

If everything is fine, you can start modifying the scaffolding to adjust the XDP program to your needs.

---

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
