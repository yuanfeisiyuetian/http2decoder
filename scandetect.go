package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"math"
)

var syn_sip map[string]int
var ack_sip map[string]int

//level是syn/ack的阈值
var level float64 = 0.95
var target int = 10

func doubtsip(sip string) string {
	ratio := float64(ack_sip[sip]) / float64(syn_sip[sip])
	if ratio > level {
		return ""
	} else {
		return sip
	}
}

var sip_dip map[string][]string
var sip_dpt map[string][]string

var sip_dip_dpt map[string][]string
var sip_dip_len map[string][]int
var sip_dip_syn map[string]int
var sip_dip_ack map[string]int
var sip_dpt_dip map[string][]string
var sip_dpt_len map[string][]int
var sip_dpt_syn map[string]int
var sip_dpt_ack map[string]int

type Sipfeature struct {
	sip_dip_dpt   float64
	sip_dip_len   float64
	sip_dip_flags float64
	sip_dpt_dip   float64
	sip_dpt_len   float64
	sip_dpt_flags float64
}

//calcEnt : 计算熵值
func calcEnt(data interface{}) float64 {
	var ent float64
	switch data.(type) {
	case []string:
		strdata := data.([]string)
		N := len(strdata)
		if N == 1 {
			ent = 0
		} else {
			newMap := make(map[string]int)
			for _, v := range strdata {
				_, ok := newMap[v]
				if ok {
					newMap[v]++
				} else {
					newMap[v] = 1
				}
			}
			for _, v := range newMap {
				p := float64(v) / float64(N)
				ent = ent + p*math.Log2(p)
			}
			ent = (0 - ent) / math.Log2(float64(N))
		}
	case []int:
		intdata := data.([]int)
		N := len(intdata)
		if N == 1 {
			ent = 0
		} else {
			newMap := make(map[int]int)
			for _, v := range intdata {
				_, ok := newMap[v]
				if ok {
					newMap[v]++
				} else {
					newMap[v] = 1
				}
			}
			for _, v := range newMap {
				p := float64(v) / float64(N)
				ent = ent + p*math.Log2(p)
			}
			ent = (0 - ent) / math.Log2(float64(N))
		}
	}
	return ent
}

var horizentalscanip []string
var pallelscanip []string

func alertip(sip string) {
	f := detectlist[sip]
	if f.sip_dip_dpt > 0.75 && f.sip_dip_len < 0.25 && f.sip_dip_flags < 0.25 {
		log.Println("horizentalscanip:", sip)
		horizentalscanip = append(horizentalscanip, sip)
	}
	if f.sip_dpt_dip > 0.75 && f.sip_dpt_len < 0.25 && f.sip_dpt_flags < 0.25 {
		log.Println("verticalscanip:", sip)
		pallelscanip = append(pallelscanip, sip)
	}
}

func scaninit() {
	syn_sip = make(map[string]int)
	ack_sip = make(map[string]int)
	sip_dip = make(map[string][]string)
	sip_dpt = make(map[string][]string)
	sip_dip_dpt = make(map[string][]string)
	sip_dip_len = make(map[string][]int)
	sip_dip_syn = make(map[string]int)
	sip_dip_ack = make(map[string]int)
	sip_dpt_dip = make(map[string][]string)
	sip_dpt_len = make(map[string][]int)
	sip_dpt_syn = make(map[string]int)
	sip_dpt_ack = make(map[string]int)
	detectlist = make(map[string]*Sipfeature)
}

func packageprocess(packet gopacket.Packet) {
	sip := packet.NetworkLayer().NetworkFlow().Src().String()
	dip := packet.NetworkLayer().NetworkFlow().Dst().String()
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcp, _ := tcpLayer.(*layers.TCP)
	dpt := tcp.DstPort.String()
	if tcp.SYN {
		syn_sip[sip]++
		sip_dip_syn[sip+dip]++
		sip_dpt_syn[sip+dpt]++
		if tcp.ACK {
			ack_sip[sip]++
			sip_dip_ack[sip+dip]++
			sip_dpt_ack[sip+dpt]++
		} else {
			_, ok := ack_sip[sip]
			if !ok {
				ack_sip[sip] = 0
			}
		}
	}
	sip_dip[sip] = append(sip_dip[sip], dip)
	sip_dpt[sip] = append(sip_dpt[sip], dpt)
	length := packet.Metadata().Length
	sip_dip_dpt[sip+dip] = append(sip_dip_dpt[sip+dip], dpt)
	sip_dip_len[sip+dip] = append(sip_dip_len[sip+dip], length)
	sip_dpt_dip[sip+dpt] = append(sip_dpt_dip[sip+dpt], dip)
	sip_dpt_len[sip+dpt] = append(sip_dpt_len[sip+dpt], length)
}

var detectlist map[string]*Sipfeature

func addtolist() {
	for k, _ := range syn_sip {
		sip := doubtsip(k)
		if sip == "" {
			continue
		} else {
			//去重
			ipMap := make(map[string]int)
			for _, v := range sip_dip[sip] {
				_, ok := ipMap[v]
				if ok {
					ipMap[v]++
				} else {
					ipMap[v] = 1
				}
			}
			portMap := make(map[string]int)
			for _, v := range sip_dpt[sip] {
				_, ok := portMap[v]
				if ok {
					portMap[v]++
				} else {
					portMap[v] = 1
				}
			}
			if len(ipMap) < target && len(portMap) < target {
				continue
			} else {
				if len(portMap) >= target {
					for dip, _ := range ipMap {
						sipfeature := Sipfeature{
							sip_dip_dpt:   calcEnt(sip_dip_dpt[sip+dip]),
							sip_dip_len:   calcEnt(sip_dip_len[sip+dip]),
							sip_dip_flags: float64(sip_dip_ack[sip+dip]) / float64(sip_dip_syn[sip+dip]),
						}
						detectlist[sip] = &sipfeature
					}
				}
				if len(ipMap) >= target {
					for dpt, _ := range portMap {
						_, ok := detectlist[sip]
						if ok {
							sipfeature := detectlist[sip]
							sipfeature.sip_dpt_dip = calcEnt(sip_dpt_dip[sip+dpt])
							sipfeature.sip_dpt_len = calcEnt(sip_dpt_len[sip+dpt])
							sipfeature.sip_dpt_flags = float64(sip_dpt_ack[sip+dpt]) / float64(sip_dpt_syn[sip+dpt])
						} else {
							sipfeature := Sipfeature{
								sip_dpt_dip:   calcEnt(sip_dpt_dip[sip+dpt]),
								sip_dpt_len:   calcEnt(sip_dpt_len[sip+dpt]),
								sip_dpt_flags: float64(sip_dpt_ack[sip+dpt]) / float64(sip_dpt_syn[sip+dpt]),
							}
							detectlist[sip] = &sipfeature
						}
					}
				}
				alertip(sip)
			}
		}
	}
}
