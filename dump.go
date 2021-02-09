package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
)

type JsonBody struct {
	//Settings map[string]uint32
	SrcIP    string
	DstIP    string
	SrcPort  string
	DstPort  string
	Time     string
	Streamid string
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
	//if jb.Settings == nil {
	//	jb.Settings = map[string]uint32{}
	//}
	//for _, v := range s.bidi.a.ReqSettings {
	//	jb.Settings[v.ID.String()] = v.Val
	//}
	//for _, v := range s.bidi.b.ReqSettings {
	//	jb.Settings[v.ID.String()] = v.Val
	//}
	jb.SrcIP = s.SrcIP.String()
	jb.DstIP = s.DstIP.String()
	jb.SrcPort = s.SrcPort.String()
	jb.DstPort = s.DstPort.String()
	//jb.Streamid = strconv.Itoa(int(s.Streamid))
	// Request
	req := map[uint32]http.Request{}
	if s.bidi.a.isRequest {
		req = s.bidi.a.Request
	} else {
		req = s.bidi.b.Request
	}
	// Response
	rsp := map[uint32]http.Response{}
	if s.bidi.a.isResponse {
		rsp = s.bidi.a.Response
	} else {
		rsp = s.bidi.b.Response
	}
	for k, v := range req {
		jb.Streamid = strconv.Itoa(int(k))
		if v.Method == "" {
			return
		}
		jb.Request.Method = v.Method
		jb.Request.Host = v.Host
		jb.Request.Path = v.URL.Path
		jb.Request.Proto = v.Proto
		jb.Request.Header = v.Header
		jb.Time = s.Time[k].String()
		if v.Body != nil {
			jb.Request.Body, _ = ioutil.ReadAll(v.Body)
		}
		jb.Response.StatusCode = rsp[k].StatusCode
		jb.Response.Header = rsp[k].Header
		if rsp[k].Body != nil {
			jb.Response.Body, _ = ioutil.ReadAll(rsp[k].Body)
		}
		fmt.Println("=======")
		enc := json.NewEncoder(outputStream)
		_ = enc.Encode(jb)
	}
}
