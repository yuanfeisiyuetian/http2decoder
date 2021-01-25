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

func (s *HTTP2Stream) Decoder(buf []byte) {
	w := new(bytes.Buffer)
	framer := http2.NewFramer(w, bytes.NewReader(buf))
	framer.ReadMetaHeaders = hpack.NewDecoder(initialHeaderTableSize, nil)
	for {
		frame, err := framer.ReadFrame()
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", err)
			continue
		} else {
			// Decoder the frame
			// fh := frame.Header()
			switch fm := frame.(type) {
			case *http2.SettingsFrame:
				for i := 0; i < fm.NumSettings(); i++ {
					s.ReqSettings = append(s.ReqSettings, fm.Setting(i))
				}
			case *http2.HeadersFrame:
			case *http2.MetaHeadersFrame:
				pf := fm.PseudoFields()
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
					s.Request.Method = fm.PseudoValue("method")
					s.Request.URL, err = url.ParseRequestURI(fm.PseudoValue("path"))
					s.Request.RequestURI = fm.PseudoValue("path")
					s.Request.Host = fm.PseudoValue("authority")
					// RegularFields
					if s.Request.Header == nil {
						s.Request.Header = make(http.Header)
					}
					for _, hf := range fm.RegularFields() {
						s.Request.Header.Add(http.CanonicalHeaderKey(hf.Name), hf.Value)
					}
				} else if s.isResponse {
					// PseudoValue
					s.Response.StatusCode, _ = strconv.Atoi(fm.PseudoValue("status"))
					s.Response.Status = http.StatusText(s.Response.StatusCode)
					// RegularFields
					if s.Response.Header == nil {
						s.Response.Header = map[string][]string{}
					}
					for _, hf := range fm.RegularFields() {
						s.Response.Header.Set(http.CanonicalHeaderKey(hf.Name), hf.Value)
					}
					s.Response.StatusCode, _ = strconv.Atoi(fm.PseudoValue("status"))
				}

			case *http2.WindowUpdateFrame:
				//fmt.Println(fm.StreamID, fm.Type)
			case *http2.PingFrame:
				//fmt.Println(fm.StreamID, fm.Type)
			case *http2.DataFrame:
				if s.isRequest {
					if s.Request.Body == nil {
						body := fm.Data()
						s.Request.Body = ioutil.NopCloser(bytes.NewReader(body))
					} else {
						body, _ := ioutil.ReadAll(s.Request.Body)
						body = append(body, fm.Data()...)
						s.Request.Body = ioutil.NopCloser(bytes.NewReader(body))
					}
				} else {
					if s.Response.Body == nil {
						body := fm.Data()
						s.Response.Body = ioutil.NopCloser(bytes.NewReader(body))
					} else {
						body, _ := ioutil.ReadAll(s.Response.Body)
						body = append(body, fm.Data()...)
						s.Response.Body = ioutil.NopCloser(bytes.NewReader(body))
					}
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
	return
}
