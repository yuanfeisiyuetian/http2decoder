// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// This binary provides an example of connecting up bidirectional streams from
// the unidirectional streams provided by gopacket/tcpassembly.
package main

import (
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"log"
	"os"
	"time"
)

var outputStream *os.File
var iface = flag.String("i", "eth0", "Interface to get packets from")
var snaplen = flag.Int("s", 16<<10, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp", "BPF filter for pcap")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var logfile = flag.String("o", "out.log", "Http2 logs file")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")
var scan = flag.Bool("c", false, "Scan detect")
var tcpfeature = flag.Bool("t", false, "Get tcp feature")

// timeout is the length of time to wait befor flushing connections and
// bidirectional stream pairs.
const timeout = time.Minute * 5

// 平均几分钟的tcp特征
const delta = 2

func main() {
	flag.Parse()
	var handle *pcap.Handle
	var err error
	outputStream, err = os.OpenFile(*logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	// open pcap stream
	if *fname != "" {
		log.Printf("Reading from pcap dump %q", *fname)
		handle, err = pcap.OpenOffline(*fname)
	} else {
		log.Printf("starting capture on interface %q", *iface)
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
		if err != nil {
			panic(err)
		}
	}
	// set BNF(包过滤)
	if err := handle.SetBPFFilter(*filter); err != nil {
		panic(err)
	}

	// Set up assembly
	streamFactory := &myFactory{bidiMap: make(map[key]*bidi)} //make 返回类型的引用而不是指针，与new相比
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	// Limit memory usage by auto-flushing connection state if we get over 100K
	// packets in memory, or over 1000 for a single stream.
	assembler.MaxBufferedPagesTotal = 100000
	assembler.MaxBufferedPagesPerConnection = 1000

	log.Println("reading in packets")
	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(timeout / 4)
	var t time.Time
	var st time.Time
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				if *scan {
					addtolist()
				}
				if *tcpfeature {
					Stafresh()
				}
				return
			}
			if *logAllPackets {
				log.Println(packet)
			}

			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			if *tcpfeature {
				nowtime := packet.Metadata().Timestamp
				if t.IsZero() {
					t = nowtime
					Tcpinit()
				}
				duration := nowtime.Sub(t)
				if duration.Minutes() >= delta {
					Stafresh()
					t = nowtime
				}
				Gettcpinfo(packet)
			}
			if *scan {
				nowtime := packet.Metadata().Timestamp
				if st.IsZero() {
					st = nowtime
					scaninit()
				}
				packageprocess(packet)
				duration := nowtime.Sub(t)
				if duration.Minutes() >= delta {
					st = nowtime
					addtolist()
				}
			}

			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past minute.
			log.Println("---- FLUSHING ----")
			assembler.FlushOlderThan(time.Now().Add(-timeout))
			streamFactory.collectOldStreams()
		}
	}
}
