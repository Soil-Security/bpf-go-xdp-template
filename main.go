package main

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	bpfevents "github.com/danielpacak/bpf-events"
)

//go:embed xdp.bpf.o
var bpfELFBytes []byte

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
		return fmt.Errorf("unrecognized network interface %q: %s", ifaceName, err)
	}

	var bpfObjects bpfObjects

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfELFBytes))
	if err != nil {
		return fmt.Errorf("failed loading BPF object file: %w", err)
	}
	decoder := &bpfevents.Decoder{ByteOrder: spec.ByteOrder}

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
		return fmt.Errorf("failed loading BPF objects: %w", err)
	}
	defer bpfObjects.Close()

	ringbufReader, err := ringbuf.NewReader(bpfObjects.EventsMap)
	if err != nil {
		return err
	}
	defer ringbufReader.Close()

	fmt.Println("Source\t\tDestination")

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

				err = parseAndPrintEvent(record.RawSample, decoder)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: failed parsing and printing event: %v\n", err)
					continue
				}
			}
		}
	}()

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   bpfObjects.XDPProg,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("failed linking XDP program: %w", err)
	}
	defer link.Close()

	<-ctx.Done()

	return nil
}

type event struct {
	SrcIP   net.IP
	SrcPort int
	DstIP   net.IP
	DstPort int
}

func (e *event) unpack(buf []byte, decoder *bpfevents.Decoder) error {
	var off = 0
	var err error

	e.SrcIP, off, err = decoder.IPv4(buf, off)
	if err != nil {
		return err
	}

	e.DstIP, off, err = decoder.IPv4(buf, off)
	if err != nil {
		return err
	}

	e.SrcPort, off, err = decoder.Uint16AsInt(buf, off)
	if err != nil {
		return err
	}

	e.DstPort, _, err = decoder.Uint16AsInt(buf, off)
	if err != nil {
		return err
	}

	return nil
}

func parseAndPrintEvent(buf []byte, decoder *bpfevents.Decoder) error {
	e := event{}
	err := e.unpack(buf, decoder)
	if err != nil {
		return fmt.Errorf("failed unpacking event: %w", err)
	}

	fmt.Printf("%v:%d\t%v:%d\n",
		e.SrcIP.To4().String(), e.SrcPort,
		e.DstIP.To4().String(), e.DstPort,
	)

	return nil
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
