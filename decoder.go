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
	if !s.isfirst {
		decode := s.Framer.ReadMetaHeaders
		s.Framer = http2.NewFramer(w, bytes.NewReader(buf))
		s.Framer.ReadMetaHeaders = decode
	}
	if s.isfirst {
		s.Framer = http2.NewFramer(w, bytes.NewReader(buf))
		s.Framer.ReadMetaHeaders = hpack.NewDecoder(initialHeaderTableSize, nil)
		s.isfirst = false
	}
	for {
		frame, err := s.Framer.ReadFrame()
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
				}

			case *http2.WindowUpdateFrame:
				//fmt.Println(fm.StreamID, fm.Type)
			case *http2.PingFrame:
				//fmt.Println(fm.StreamID, fm.Type)
			case *http2.DataFrame:
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
				} else {
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
				}
			case *http2.RSTStreamFrame:
				//fmt.Println(fm.StreamID, fm.Type)
			case *http2.PriorityFrame:
				//fmt.Println(fm.StreamID, fm.Type)
			case *http2.GoAwayFrame:
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
