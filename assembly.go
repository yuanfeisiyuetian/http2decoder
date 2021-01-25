package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"golang.org/x/net/http2"
	"log"
	"net/http"
	"time"
)

// key is used to map bidirectional streams to each other.
type key struct {
	net, transport gopacket.Flow
}

// String prints out the key in a human-readable fashion.
func (k key) String() string {
	return fmt.Sprintf("%v:%v", k.net, k.transport)
}

// myStream implements tcpassembly.Stream
type HTTP2Stream struct {
	bytes                          int64 // total bytes seen on this stream.
	bidi                           *bidi // maps to my bidirectional twin.
	done                           bool  // if true, we've seen the last packet we're going to for this stream.
	ReqSettings                    []http2.Setting
	RespSettings                   []http2.Setting
	isHTTP2, isRequest, isResponse bool
	Request                        http.Request
	Response                       http.Response
	SrcIP                          gopacket.Endpoint
	DstIP                          gopacket.Endpoint
	SrcPort                        gopacket.Endpoint
	DstPort                        gopacket.Endpoint
	Time                           time.Time
}

// bidi stores each unidirectional side of a bidirectional stream.
//
// When a new stream comes in, if we don't have an opposite stream, a bidi is
// created with 'a' set to the new stream.  If we DO have an opposite stream,
// 'b' is set to the new stream.
type bidi struct {
	key            key          // Key of the first stream, mostly for logging.
	a, b           *HTTP2Stream // the two bidirectional streams.
	lastPacketSeen time.Time    // last time we saw a packet from either stream.
}

// myFactory implements tcpassmebly.StreamFactory
type myFactory struct {
	// bidiMap maps keys to bidirectional stream pairs.
	bidiMap map[key]*bidi
}

// New handles creating a new tcpassembly.Stream.
func (f *myFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	// Create a new stream.
	s := &HTTP2Stream{
		Request: http.Request{
			Proto:      "HTTP/2.0",
			ProtoMajor: 2,
			ProtoMinor: 0,
		},
		Response: http.Response{
			Proto:      "HTTP/2.0",
			ProtoMajor: 2,
			ProtoMinor: 0,
		},
		SrcIP:   netFlow.Src(),
		DstIP:   netFlow.Dst(),
		SrcPort: tcpFlow.Src(),
		DstPort: tcpFlow.Dst(),
	}

	// Find the bidi bidirectional struct for this stream, creating a new one if
	// one doesn't already exist in the map.
	k := key{netFlow, tcpFlow}
	bd := f.bidiMap[k]
	if bd == nil {
		bd = &bidi{a: s, key: k}
		log.Printf("[%v] created first side of bidirectional stream", bd.key)
		// Register bidirectional with the reverse key, so the matching stream going
		// the other direction will find it.
		f.bidiMap[key{netFlow.Reverse(), tcpFlow.Reverse()}] = bd
	} else {
		log.Printf("[%v] found second side of bidirectional stream", bd.key)
		bd.b = s
		// Clear out the bidi we're using from the map, just in case.
		delete(f.bidiMap, k)
	}
	s.bidi = bd
	return s
}

// emptyStream is used to finish bidi that only have one stream, in
// collectOldStreams.
var emptyStream = &HTTP2Stream{done: true}

// collectOldStreams finds any streams that haven't received a packet within
// 'timeout', and sets/finishes the 'b' stream inside them.  The 'a' stream may
// still receive packets after this.
func (f *myFactory) collectOldStreams() {
	cutoff := time.Now().Add(-timeout)
	for k, bd := range f.bidiMap {
		if bd.lastPacketSeen.Before(cutoff) {
			log.Printf("[%v] timing out old stream", bd.key)
			bd.b = emptyStream   // stub out b with an empty stream.
			delete(f.bidiMap, k) // remove it from our map.
			bd.maybeFinish()     // if b was the last stream we were waiting for, finish up.
		}
	}
}

// Reassembled handles reassembled TCP stream data.
func (s *HTTP2Stream) Reassembled(rs []tcpassembly.Reassembly) {
	for _, r := range rs {
		s.Decoder(r.Bytes)
		// For now, we'll simply count the bytes on each side of the TCP stream.
		s.bytes += int64(len(r.Bytes))
		if r.Skip > 0 {
			s.bytes += int64(r.Skip)
		}
		// Mark that we've received new packet data.
		// We could just use time.Now, but by using r.Seen we handle the case
		// where packets are being read from a file and could be very old.
		if s.bidi.lastPacketSeen.Before(r.Seen) {
			s.bidi.lastPacketSeen = r.Seen
		}
	}
}

// ReassemblyComplete marks this stream as finished.
func (s *HTTP2Stream) ReassemblyComplete() {
	s.done = true
	if s.bidi.maybeFinish() {
		s.DumpJson()
	}
}

// maybeFinish will wait until both directions are complete, then print out
// stats.
func (bd *bidi) maybeFinish() bool {
	switch {
	case bd.a == nil:
		log.Fatalf("[%v] a should always be non-nil, since it's set when bidis are created", bd.key)
	case !bd.a.done:
		log.Printf("[%v] still waiting on first stream [%s]", bd.key, bd.lastPacketSeen)
	case bd.b == nil:
		log.Printf("[%v] no second stream yet", bd.key)
	case !bd.b.done:
		log.Printf("[%v] still waiting on second stream [%s]", bd.key, bd.lastPacketSeen)
	default:
		log.Printf("[%v] FINISHED, bytes: %d tx, %d rx", bd.key, bd.a.bytes, bd.b.bytes)
		return true
	}
	return false
}
