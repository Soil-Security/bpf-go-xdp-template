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
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
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
	flag.StringVar(&ifaceName, "interface", "lo", "name of the network interface")
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

	err = spec.LoadAndAssign(&bpfObjects, &ebpf.CollectionOptions{})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Fprintln(os.Stderr, strings.Join(verr.Log, "\n"))
		}
		return fmt.Errorf("failed loading and assigning BPF objects: %w", err)
	}
	defer bpfObjects.Close()

	ringbufReader, err := ringbuf.NewReader(bpfObjects.EventsMap)
	if err != nil {
		return err
	}
	defer ringbufReader.Close()

	fmt.Println("Source\t\tDestination\t\tProtocol")

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

	bpfObjects.XDPLink, err = link.AttachXDP(link.XDPOptions{
		Program:   bpfObjects.XDPProg,
		Interface: iface.Index,
	})
	if err != nil {
		return err
	}

	<-ctx.Done()

	return nil
}

func printEvent(raw []byte) {
	offset := 0
	srcIP := net.IP(raw[offset : offset+4])
	offset += 4
	dstIP := net.IP(raw[offset : offset+4])
	offset += 4
	protocol := (int)(raw[offset])
	offset++
	srcPort := (int)(binary.LittleEndian.Uint16(raw[offset : offset+2]))
	offset += 2
	dstPort := (int)(binary.LittleEndian.Uint16(raw[offset : offset+2]))
	offset += 2

	protocolStr := strconv.Itoa(protocol)
	switch protocol {
	case 17:
		protocolStr = "UDP"
	case 6:
		protocolStr = "TCP"
	}
	fmt.Printf("%v:%d\t%v:%d\t%v\n",
		srcIP.To4().String(), srcPort,
		dstIP.To4().String(), dstPort,
		protocolStr)
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

type bpfObjects struct {
	bpfPrograms
	bpfLinks
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return bpfClose(
		&o.bpfPrograms,
		&o.bpfLinks,
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

type bpfLinks struct {
	XDPLink link.Link
}

func (l *bpfLinks) Close() error {
	return bpfClose(
		l.XDPLink,
	)
}

type bpfMaps struct {
	EventsMap *ebpf.Map `ebpf:"events"`
}

func (m *bpfMaps) Close() error {
	return bpfClose(
		m.EventsMap,
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
