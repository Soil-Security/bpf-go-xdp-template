# bpf-xdp-go-template

A GitHub template repository with the scaffolding for a XDP program developed with [libbpf/libbpf].
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

Run the loader program, which will attach the XDP program to the `eth0` interface.

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
and its id is `21`. XDP has three operation modes (native, offloaded, and generic) to accommodate easily
testing functions, custom hardware from vendors, and commonly built kernels without custom hardware.
The `xdpgeneric/id:21` entry indicates the generic operation mode, which is provided as a test-mode
for developers who want to write and run XDP programs without having the capabilities of native or offloaded XDP.

When you hit CTRL+C keys to stop the loader process, the XDP program will be detached from the `eth0` interface.


## Using Alternative Loaders

The `ip` command, available in iproute2, has the ability to act as a frontend to load XDP programs compiled
into an ELF file. Because loading an XDP program can be expressed as a configuration of a network interface,
the loader is implemented as part of the `ip link` command (man 8 ip-link), which is the one that does network
device configuration.

The syntax to load the XDP program is simple.

```
# ip link set dev eth0 xdp obj src/xdp.bpf.o program xdp_prog_func verbose
```

To detach the `xdp_prog_func` program and turn off XDP for the device.

```
# ip link set dev eth0 xdp off
```

Use bpftool to load and attche XDP programs.

```
# bpftool prog load src/xdp.bpf.o /sys/fs/bpf/xdp_prog_func
```

You can further inspect the program with the `btftool` command.

``` console
# bpftool prog show id 21
21: xdp  name xdp_prog_func  tag 50fcfa8b9d387625  gpl
        loaded_at 2023-03-03T10:10:37+0100  uid 0
        xlated 208B  jited 123B  memlock 4096B  map_ids 3
        btf_id 147
```

```
# bpftool net attach xdp id 21 dev eth0
```

``` console
# bpftool net list
xdp:
eth0(2) generic id 21

tc:

flow_dissector:
```

```
# bpftool net detach xdp dev eth0
```
```
# rm /sys/fs/bpf/xdp_prog_func
```

## Inspecting BPF Bytecode

The `file` utility shows that `xdp.bpf.o` is an ELF (Executable and Linkable Format) file, containing eBPF
code, for a 64-bit platform with LSB (lowest significant bit) architecture.

``` console
$ file src/xdp.bpf.o
src/xdp.bpf.o: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), not stripped
```

You can further inspect this object with `llvm-objdump` to see the eBPF instructions.

``` console
$ llvm-objdump -d src/xdp.bpf.o

src/xdp.bpf.o:  file format elf64-bpf

Disassembly of section xdp:

0000000000000000 <xdp_prog_func>:
       0:       61 12 04 00 00 00 00 00 r2 = *(u32 *)(r1 + 4)
       1:       61 11 00 00 00 00 00 00 r1 = *(u32 *)(r1 + 0)
       2:       bf 13 00 00 00 00 00 00 r3 = r1
       3:       07 03 00 00 0e 00 00 00 r3 += 14
       4:       2d 23 13 00 00 00 00 00 if r3 > r2 goto +19 <LBB0_5>
       5:       69 13 0c 00 00 00 00 00 r3 = *(u16 *)(r1 + 12)
       6:       55 03 11 00 08 00 00 00 if r3 != 8 goto +17 <LBB0_5>
       7:       bf 13 00 00 00 00 00 00 r3 = r1
       8:       07 03 00 00 22 00 00 00 r3 += 34
       9:       2d 23 0e 00 00 00 00 00 if r3 > r2 goto +14 <LBB0_5>
      10:       07 01 00 00 0e 00 00 00 r1 += 14
      11:       61 17 10 00 00 00 00 00 r7 = *(u32 *)(r1 + 16)
      12:       61 16 0c 00 00 00 00 00 r6 = *(u32 *)(r1 + 12)
      13:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0 ll
      15:       b7 02 00 00 08 00 00 00 r2 = 8
      16:       b7 03 00 00 00 00 00 00 r3 = 0
      17:       85 00 00 00 83 00 00 00 call 131
      18:       15 00 05 00 00 00 00 00 if r0 == 0 goto +5 <LBB0_5>
      19:       63 70 04 00 00 00 00 00 *(u32 *)(r0 + 4) = r7
      20:       63 60 00 00 00 00 00 00 *(u32 *)(r0 + 0) = r6
      21:       bf 01 00 00 00 00 00 00 r1 = r0
      22:       b7 02 00 00 00 00 00 00 r2 = 0
      23:       85 00 00 00 84 00 00 00 call 132

00000000000000c0 <LBB0_5>:
      24:       b7 00 00 00 02 00 00 00 r0 = 2
      25:       95 00 00 00 00 00 00 00 exit
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
