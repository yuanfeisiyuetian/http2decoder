package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
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
		Url    string
		Proto  string
		Header map[string][]string
		Body   string
	}
	Response struct {
		StatusCode int
		Header     map[string][]string
		Body       string
	}
}

func (s *HTTP2Stream) DumpJson() {
	jb := JsonBody{}
	//var Db *sqlx.DB = ConnectMysql()
	//defer Db.Close()

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
	jb.SrcIP = s.bidi.a.SrcIP.String()
	jb.DstIP = s.bidi.a.DstIP.String()
	jb.SrcPort = s.bidi.a.SrcPort.String()
	jb.DstPort = s.bidi.a.DstPort.String()
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
		jb.Request.Url = v.RequestURI
		jb.Request.Proto = v.Proto
		jb.Request.Header = v.Header
		jb.Time = s.bidi.a.Time[k].String()
		url, _ := url.QueryUnescape(jb.Request.Url)
		jb.Request.Url = url
		if v.Body != nil {
			//jb.Request.Body, _ = ioutil.ReadAll(v.Body)
			reqbody, _ := ioutil.ReadAll(v.Body)
			jb.Request.Body = string(reqbody)
			//jb.Request.Body = strconv.QuoteToASCII(string(reqbody))
		}
		jb.Response.StatusCode = rsp[k].StatusCode
		jb.Response.Header = rsp[k].Header
		if rsp[k].Body != nil {
			//jb.Response.Body, _ = ioutil.ReadAll(rsp[k].Body)
			resbody, _ := ioutil.ReadAll(rsp[k].Body)
			jb.Response.Body = string(resbody)
			//jb.Response.Body = strconv.QuoteToASCII(string(resbody))
		} else {
			jb.Response.Body = ""
		}

		//写入数据库
		//reqheader, err := json.Marshal(jb.Request.Header)
		//resheader, err := json.Marshal(jb.Response.Header)
		//reqbodytowrite := strconv.QuoteToASCII(jb.Request.Body)
		//resbodytowrite := strconv.QuoteToASCII(jb.Response.Body)
		//r, err := Db.Exec("insert into traffic_field(sid, time, srcip, srcport,desip,desport,url,method,status,reqheader,reqbody,resheader,resbody,pcap_id) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", jb.Streamid, jb.Time, jb.SrcIP, jb.SrcPort, jb.DstIP, jb.DstPort, jb.Request.Url, v.Method, jb.Response.StatusCode, reqheader, reqbodytowrite, resheader, resbodytowrite, 1)
		//if err != nil {
		//	fmt.Println("exec failed, ", err)
		//}
		//id, err := r.LastInsertId()
		//if err != nil {
		//	fmt.Println("exec failed, ", err)
		//}
		//fmt.Println("insert succ:", id)

		fmt.Println("=======")
		log.Println(jb)
		enc := json.NewEncoder(outputStream)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(jb)
	}
}
