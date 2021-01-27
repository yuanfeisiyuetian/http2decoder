package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type JsonBody struct {
	Settings map[string]uint32
	SrcIP    string
	DstIP    string
	SrcPort  string
	DstPort  string
	Time     string
	Request  struct {
		Method string
		Host   string
		Path   string
		Proto  string
		Header map[string][]string
		Body   []byte
	}
	Response struct {
		StatusCode int
		Header     map[string][]string
		Body       []byte
	}
}

func (s *HTTP2Stream) DumpJson() {
	jb := JsonBody{}
	// Settings
	if jb.Settings == nil {
		jb.Settings = map[string]uint32{}
	}
	for _, v := range s.bidi.a.ReqSettings {
		jb.Settings[v.ID.String()] = v.Val
	}
	for _, v := range s.bidi.b.ReqSettings {
		jb.Settings[v.ID.String()] = v.Val
	}
	jb.SrcIP = s.SrcIP.String()
	jb.DstIP = s.DstIP.String()
	jb.SrcPort = s.SrcPort.String()
	jb.DstPort = s.DstPort.String()
	jb.Time = s.bidi.firstPacketSeen.String()
	// Request
	req := http.Request{}
	if s.bidi.a.isRequest {
		req = s.bidi.a.Request
	} else {
		req = s.bidi.b.Request
	}
	if req.Method == "" {
		return
	}
	jb.Request.Method = req.Method
	jb.Request.Host = req.Host
	jb.Request.Path = req.URL.Path
	jb.Request.Proto = req.Proto
	jb.Request.Header = req.Header
	if req.Body != nil {
		jb.Request.Body, _ = ioutil.ReadAll(req.Body)
	}
	// Response
	rsp := http.Response{}
	if s.bidi.a.isResponse {
		rsp = s.bidi.a.Response
	} else {
		rsp = s.bidi.b.Response

	}
	jb.Response.StatusCode = rsp.StatusCode
	jb.Response.Header = rsp.Header
	if rsp.Body != nil {
		jb.Response.Body, _ = ioutil.ReadAll(rsp.Body)
	}
	fmt.Println("=======")
	enc := json.NewEncoder(outputStream)
	enc.Encode(jb)
}
