package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

func main() {
	if err := run(setupHandler()); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s", err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func run(ctx context.Context) error {
	var ifaceName string
	var hosts string
	flag.StringVar(&ifaceName, "interface", "lo", "name of the network interface")
	flag.StringVar(&hosts, "hosts", "", "host names to be tracked")
	flag.Parse()

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup network interface %q: %s", ifaceName, err)
	}

	var bpfObjects bpfObjects

	executable, err := os.Executable()
	if err != nil {
		return err
	}
	bpfObjectFile := path.Join(filepath.Dir(executable), "xdp.bpf.o")

	spec, err := ebpf.LoadCollectionSpec(bpfObjectFile)
	if err != nil {
		return err
	}

	err = spec.LoadAndAssign(&bpfObjects, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: ebpf.DefaultVerifierLogSize,
		},
	})
	if err != nil {
		var verifierError *ebpf.VerifierError
		if errors.As(err, &verifierError) {
			fmt.Fprintln(os.Stderr, strings.Join(verifierError.Log, "\n"))
		}
		return fmt.Errorf("failed loading and assigning BPF objects: %w", err)
	}
	defer bpfObjects.Close()

	err = updateHostsMap(bpfObjects.HostsMap, strings.Split(hosts, ","))
	if err != nil {
		return err
	}

	ringbufReader, err := ringbuf.NewReader(bpfObjects.EventsMap)
	if err != nil {
		return err
	}
	defer ringbufReader.Close()

	fmt.Println("Source\t\tDestination\t\tDNS.id")

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := ringbufReader.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					continue
				}

				printEvent(record.RawSample)
			}
		}
	}()

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   bpfObjects.XDPProg,
		Interface: iface.Index,
	})
	if err != nil {
		return err
	}
	defer link.Close()

	<-ctx.Done()

	return nil
}

func printEvent(raw []byte) {
	offset := 0
	srcIP := net.IP(raw[offset : offset+4])
	offset += 4
	dstIP := net.IP(raw[offset : offset+4])
	offset += 4
	srcPort := (int)(binary.LittleEndian.Uint16(raw[offset : offset+2]))
	offset += 2
	dstPort := (int)(binary.LittleEndian.Uint16(raw[offset : offset+2]))
	offset += 2

	dnsId := (int)(binary.LittleEndian.Uint16(raw[offset : offset+2]))
	offset += 2
	dnsQnCount := (int)(binary.LittleEndian.Uint16(raw[offset : offset+2]))
	offset += 2
	dnsAnCount := (int)(binary.LittleEndian.Uint16(raw[offset : offset+2]))
	offset += 2

	var qname [256]uint8
	_ = copy(qname[:], raw[offset:offset+256])
	qnameStr := unix.ByteSliceToString(qname[:])
	offset += 256

	fmt.Printf("%v:%d\t%v:%d\t%d\t%d\t%d\t%q\n",
		srcIP.To4().String(), srcPort,
		dstIP.To4().String(), dstPort,
		dnsId,
		dnsQnCount,
		dnsAnCount,
		qnameStr,
	)
}

var onlyOneSignalHandler = make(chan struct{})

func setupHandler() context.Context {
	close(onlyOneSignalHandler)

	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 2)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-c
		cancel()
		<-c
		os.Exit(1)
	}()

	return ctx
}

const DNSNameMax = 256

func updateHostsMap(m *ebpf.Map, hosts []string) error {
	var keys [][DNSNameMax]byte
	var values []bool

	for _, host := range hosts {
		keys = append(keys, hostToDomainNameBytes(host))
		values = append(values, true)
	}

	updateCount, err := m.BatchUpdate(keys, values, &ebpf.BatchOptions{
		Flags: uint64(ebpf.UpdateAny),
	})

	if err != nil {
		return fmt.Errorf("failed updating hosts in batch: %w", err)
	}

	if updateCount != len(hosts) {
		return fmt.Errorf("failed updating all hosts in batch: expected: %d actual: %d", len(hosts), updateCount)
	}

	return nil
}

func hostToDomainNameBytes(host string) [DNSNameMax]byte {
	buf := [DNSNameMax]byte{}
	copy(buf[:], host)
	return buf
}

type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return bpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

type bpfPrograms struct {
	XDPProg *ebpf.Program `ebpf:"xdp_prog_func"`
}

func (p *bpfPrograms) Close() error {
	return bpfClose(
		p.XDPProg,
	)
}

type bpfMaps struct {
	EventsMap *ebpf.Map `ebpf:"events"`
	HostsMap  *ebpf.Map `ebpf:"hosts"`
}

func (m *bpfMaps) Close() error {
	return bpfClose(
		m.EventsMap,
		m.HostsMap,
	)
}

func bpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}
