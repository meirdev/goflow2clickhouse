package main

import (
	"context"
	_ "embed"
	"flag"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	flowmessage "github.com/cloudflare/goflow/v3/pb"
	"github.com/cloudflare/goflow/v3/utils"

	log "github.com/sirupsen/logrus"
)

var (
	LogLevel = flag.String("loglevel", "info", "Log level")
	LogFmt   = flag.String("logfmt", "normal", "Log formatter")

	ListenAddresses = flag.String("listen", "sflow://:6343,netflow://:2055", "listen addresses")

	ClickHouse = flag.String("clickhouse", "clickhouse://127.0.0.1:9000/default", "ClickHouse connection string")

	Workers      = flag.Int("workers", 1, "Number of workers")
	BatchSize    = flag.Int("batchsize", 10000, "Batch size")
	BatchMaxTime = flag.Int("batchmaxtime", 10, "Max time in seconds to wait for a batch to be filled")

	MetricsAddr = flag.String("metrics.addr", ":8080", "Metrics address")
	MetricsPath = flag.String("metrics.path", "/metrics", "Metrics path")

	flows = make(chan *flowmessage.FlowMessage)
)

type FlowDb struct {
	Type          int32  `ch:"type"`
	TimeReceived  uint64 `ch:"time_received"`
	SequenceNum   uint32 `ch:"sequence_num"`
	SamplingRate  uint64 `ch:"sampling_rate"`
	FlowDirection uint32 `ch:"flow_direction"`

	SamplerAddress string `ch:"sampler_address"`

	TimeFlowStart uint64 `ch:"time_flow_start"`
	TimeFlowEnd   uint64 `ch:"time_flow_end"`

	Bytes   uint64 `ch:"bytes"`
	Packets uint64 `ch:"packets"`

	SrcAddr string `ch:"src_addr"`
	DstAddr string `ch:"dst_addr"`

	Etype uint32 `ch:"etype"`

	Proto uint32 `ch:"proto"`

	SrcPort uint32 `ch:"src_port"`
	DstPort uint32 `ch:"dst_port"`

	ForwardingStatus uint32 `ch:"forwarding_status"`
	TCPFlags         uint32 `ch:"tcp_flags"`
	IcmpType         uint32 `ch:"icmp_type"`
	IcmpCode         uint32 `ch:"icmp_code"`

	FragmentId     uint32 `ch:"fragment_id"`
	FragmentOffset uint32 `ch:"fragment_offset"`
}

type State struct {
	connection driver.Conn
}

func initTransport() (*State, error) {
	options, err := clickhouse.ParseDSN(*ClickHouse)
	if err != nil {
		return nil, err
	}

	conn, err := clickhouse.Open(options)
	if err != nil {
		return nil, err
	}

	state := &State{
		connection: conn,
	}

	return state, nil
}

func (s *State) Publish(msgs []*flowmessage.FlowMessage) {
	for _, msg := range msgs {
		flows <- msg
	}
}

func (s *State) Close() {
	s.connection.Close()
}

func (s *State) PushFlows() {
	batchMaxTime := time.Duration(*BatchMaxTime) * time.Second

	for {
		log.Debug("Start collecting flows")

		flowsBatch := make([]*FlowDb, 0, *BatchSize)

		t := time.NewTimer(batchMaxTime)

	inner:
		for len(flowsBatch) < *BatchSize {
			select {
			case <-t.C:
				break inner
			case msg := <-flows:
				flowsBatch = append(flowsBatch, &FlowDb{
					Type:             int32(msg.Type),
					TimeReceived:     msg.TimeReceived,
					SequenceNum:      msg.SequenceNum,
					SamplingRate:     msg.SamplingRate,
					FlowDirection:    msg.FlowDirection,
					SamplerAddress:   net.IP(msg.SamplerAddress).String(),
					TimeFlowStart:    msg.TimeFlowStart,
					TimeFlowEnd:      msg.TimeFlowEnd,
					Bytes:            msg.Bytes,
					Packets:          msg.Packets,
					SrcAddr:          net.IP(msg.SrcAddr).String(),
					DstAddr:          net.IP(msg.DstAddr).String(),
					Etype:            msg.Etype,
					Proto:            msg.Proto,
					SrcPort:          msg.SrcPort,
					DstPort:          msg.DstPort,
					ForwardingStatus: msg.ForwardingStatus,
					TCPFlags:         msg.TCPFlags,
					IcmpType:         msg.IcmpType,
					IcmpCode:         msg.IcmpCode,
					FragmentId:       msg.FragmentId,
					FragmentOffset:   msg.FragmentOffset,
				})
			}
		}

		log.Debugf("Collected %d flows", len(flowsBatch))

		if len(flowsBatch) > 0 {
			batch, err := s.connection.PrepareBatch(context.TODO(), "INSERT INTO flows")
			if err != nil {
				log.Error(err)
			}

			for _, flow := range flowsBatch {
				err := batch.AppendStruct(flow)
				if err != nil {
					log.Error(err)
				}
			}

			err = batch.Send()
			if err != nil {
				log.Error(err)
			}
		}
	}
}

func httpServer() {
	http.Handle(*MetricsPath, promhttp.Handler())
	log.Fatal(http.ListenAndServe(*MetricsAddr, nil))
}

func main() {
	flag.Parse()

	level, _ := log.ParseLevel(*LogLevel)
	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})

	transport, err := initTransport()
	if err != nil {
		log.Fatalf("Could not connect to ClickHouse: %v", err)
		os.Exit(1)
	}
	defer transport.Close()

	runtime.GOMAXPROCS(runtime.NumCPU())

	log.Info("Starting")

	go httpServer()

	wg := &sync.WaitGroup{}

	for _, listenAddress := range strings.Split(*ListenAddresses, ",") {
		listenAddrUrl, err := url.Parse(listenAddress)
		if err != nil {
			log.Errorf("Could not parse listen address %s", listenAddress)
			os.Exit(1)
		}

		hostname := listenAddrUrl.Hostname()
		port, err := strconv.ParseUint(listenAddrUrl.Port(), 10, 64)
		if err != nil {
			log.Errorf("Port could not be converted to integer %s", listenAddrUrl.Port())
			os.Exit(1)
		}

		var state interface {
			FlowRoutine(workers int, addr string, port int, reuseport bool) error
		}

		switch listenAddrUrl.Scheme {
		case "sflow":
			state = &utils.StateSFlow{
				Transport: transport,
				Logger:    log.StandardLogger(),
			}
		case "netflow":
			state = &utils.StateNetFlow{
				Transport: transport,
				Logger:    log.StandardLogger(),
			}
		case "nfl":
			state = &utils.StateNFLegacy{
				Transport: transport,
				Logger:    log.StandardLogger(),
			}
		default:
			log.Fatalf("Unknown scheme %s", listenAddrUrl.Scheme)
			os.Exit(1)
		}

		wg.Add(1)
		go func() {
			log.Infof("Listening for %s", listenAddrUrl.String())

			err := state.FlowRoutine(*Workers, hostname, int(port), false)
			if err != nil {
				log.Fatalf("Fatal error: could not listen to UDP (%v)", err)
			}
			wg.Done()
		}()
	}

	wg.Add(1)
	go func() {
		transport.PushFlows()
		wg.Done()
	}()

	wg.Wait()
}
