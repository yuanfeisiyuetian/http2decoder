package main

import (
	"bytes"
	"fmt"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
)

const initialHeaderTableSize = 4096

func (s *HTTP2Stream) Decoder(buf []byte) uint32 {
	w := new(bytes.Buffer)
	if s.isreqfirst {
		s.reqFramer = http2.NewFramer(w, bytes.NewReader(buf))
		s.reqFramer.ReadMetaHeaders = hpack.NewDecoder(initialHeaderTableSize, nil)
		s.isreqfirst = false
	} else {
		if len(s.Request) != 0 {
			decode := s.reqFramer.ReadMetaHeaders
			s.reqFramer = http2.NewFramer(w, bytes.NewReader(buf))
			s.reqFramer.ReadMetaHeaders = decode
		} else {
			s.reqFramer = http2.NewFramer(w, bytes.NewReader(buf))
			s.reqFramer.ReadMetaHeaders = hpack.NewDecoder(initialHeaderTableSize, nil)
		}
	}
	if s.isresfirst {
		s.resFramer = http2.NewFramer(w, bytes.NewReader(buf))
		s.resFramer.ReadMetaHeaders = hpack.NewDecoder(initialHeaderTableSize, nil)
		s.isresfirst = false
	} else {
		if len(s.Response) != 0 {
			decode := s.resFramer.ReadMetaHeaders
			s.resFramer = http2.NewFramer(w, bytes.NewReader(buf))
			s.resFramer.ReadMetaHeaders = decode
		} else {
			s.resFramer = http2.NewFramer(w, bytes.NewReader(buf))
			s.resFramer.ReadMetaHeaders = hpack.NewDecoder(initialHeaderTableSize, nil)
		}
	}
	//log.Println("s.SrcIP",s.SrcIP.String(),"s.DstIP",s.DstIP.String(),"s.SrcPort",s.SrcPort.String(),"s.DstPort",s.DstPort.String())
	//log.Println("s.SrcIP",s.bidi.a.SrcIP.String(),"s.DstIP",s.bidi.a.DstIP.String(),"s.SrcPort",s.bidi.a.SrcPort.String(),"s.DstPort",s.bidi.a.DstPort.String())
	//log.Println("s.SrcIP",s.bidi.b.SrcIP.String(),"s.DstIP",s.bidi.b.DstIP.String(),"s.SrcPort",s.bidi.b.SrcPort.String(),"s.DstPort",s.bidi.b.DstPort.String())
	for {
		frame, err := s.reqFramer.ReadFrame()
		if s.SrcIP != s.bidi.a.SrcIP {
			frame, err = s.resFramer.ReadFrame()
		}
		log.Println(frame)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return s.Streamid
		} else if err != nil {
			log.Println("Error reading stream", err)
			continue
		} else {
			// Decoder the frame
			// fh := frame.Header()
			switch fm := frame.(type) {
			case *http2.SettingsFrame:
				//for i := 0; i < fm.NumSettings(); i++ {
				//	s.ReqSettings = append(s.ReqSettings, fm.Setting(i))
				//}
			case *http2.HeadersFrame:
			case *http2.MetaHeadersFrame:
				fmt.Println(fm.StreamID, fm.Type)
				pf := fm.PseudoFields()
				s.Streamid = fm.StreamID
				for _, hf := range pf {
					switch hf.Name {
					case ":method", ":path", ":scheme", ":authority":
						s.isRequest = true
						s.isResponse = false
					case ":status":
						s.isResponse = true
						s.isRequest = false
					}
				}
				if s.isRequest {
					request := s.Request[s.Streamid]
					request.Method = fm.PseudoValue("method")
					request.URL, _ = url.ParseRequestURI(fm.PseudoValue("path"))
					request.RequestURI = fm.PseudoValue("path")
					request.Host = fm.PseudoValue("authority")
					if request.Header == nil {
						request.Header = make(http.Header)
					}
					// RegularFields
					//if s.Request.Header == nil {
					//	s.Request.Header = make(http.Header)
					//}
					for _, hf := range fm.RegularFields() {
						request.Header.Add(http.CanonicalHeaderKey(hf.Name), hf.Value)
					}
					s.Request[s.Streamid] = request
					fmt.Println(s.Request)
				} else if s.isResponse {
					// PseudoValue
					response := s.Response[s.Streamid]
					response.StatusCode, _ = strconv.Atoi(fm.PseudoValue("status"))
					response.Status = http.StatusText(response.StatusCode)
					if response.Header == nil {
						response.Header = map[string][]string{}
					}
					for _, hf := range fm.RegularFields() {
						response.Header.Set(http.CanonicalHeaderKey(hf.Name), hf.Value)
					}
					s.Response[s.Streamid] = response
					fmt.Println(s.Response)
				}
			case *http2.WindowUpdateFrame:
				//fmt.Println(fm.StreamID, fm.Type)
			case *http2.PingFrame:
				//fmt.Println(fm.StreamID, fm.Type)
			case *http2.DataFrame:
				fmt.Println(fm.StreamID, fm.Type)
				s.Streamid = fm.StreamID
				if s.isRequest {
					request := s.Request[s.Streamid]
					if request.Body == nil {
						body := fm.Data()
						request.Body = ioutil.NopCloser(bytes.NewReader(body))
					} else {
						body, _ := ioutil.ReadAll(request.Body)
						body = append(body, fm.Data()...)
						request.Body = ioutil.NopCloser(bytes.NewReader(body))
					}
					s.Request[s.Streamid] = request
					fmt.Println(s.Request)
				} else if s.isResponse {
					response := s.Response[s.Streamid]
					if response.Body == nil {
						body := fm.Data()
						response.Body = ioutil.NopCloser(bytes.NewReader(body))
					} else {
						body, _ := ioutil.ReadAll(response.Body)
						body = append(body, fm.Data()...)
						response.Body = ioutil.NopCloser(bytes.NewReader(body))
					}
					s.Response[s.Streamid] = response
					fmt.Println(s.Response)
				}
			case *http2.RSTStreamFrame:
				//fmt.Println(fm.StreamID, fm.Type)
			case *http2.PriorityFrame:
				//fmt.Println(fm.StreamID, fm.Type)
			case *http2.GoAwayFrame:
				//fmt.Println(fm.StreamID, fm.Type)
			case *http2.PushPromiseFrame:
				// A client cannot push. Thus, servers MUST treat the receipt of a PUSH_PROMISE
				// frame as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
				//return ConnectionError(ErrCodeProtocol)
			default:
				fmt.Println(fm.Header())
			}
		}
	}
}
