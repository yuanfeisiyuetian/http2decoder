package main

import (
	"container/list"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/jmoiron/sqlx"
	"github.com/montanaflynn/stats"
	"time"
)

type Pack struct {
	isipv4, isipv6       bool
	istcp, isudp, issctp bool
	netFlow              gopacket.Flow
	trafficFlow          gopacket.Flow
	Protocol             layers.IPProtocol
	Timestamp            time.Time
	Length               int
	IsICMP               bool
	ack, syn             bool
}

//vkey is the key of vertical scan
type vkey struct {
	src_dst gopacket.Flow
	srcport gopacket.Endpoint
}

//hkey is the key of horizental scan
type hkey struct {
	srcip   gopacket.Endpoint
	spt_dpt gopacket.Flow
}

type Packlist struct {
	vkey       vkey
	hkey       hkey
	isv, ish   bool
	Numpacp    int
	Maxlenpcap int
	Minlenpcap int
	Avglenpcap int
	dispersity float64
	Numicmp    int
	Proto      map[string]int
	portlist   map[gopacket.Endpoint]bool
	iplist     map[gopacket.Endpoint]bool
	lenlist    []int
	Numreply   int
	Numtcpreq  int
	Numtcpres  int
}

var Sameiplist map[vkey]*Packlist
var Sameportlist map[hkey]*Packlist
var List *list.List
var limit int

// init map and set the limitation of linked list
func Init() {
	List = Newlist()
	limit = 6
}

//core code of scan detect
func Getipinfo(packet gopacket.Packet) {
	//decode packet
	pack := Pack{}
	pack.netFlow = packet.NetworkLayer().NetworkFlow()
	pack.trafficFlow = packet.TransportLayer().TransportFlow()
	if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
		pack.istcp = true
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN {
			pack.syn = true
		}
		if tcp.ACK {
			pack.ack = true
		}
	}
	if packet.TransportLayer().LayerType() == layers.LayerTypeUDP {
		pack.isudp = true
	}
	if packet.TransportLayer().LayerType() == layers.LayerTypeSCTP {
		pack.issctp = true
	}
	if packet.NetworkLayer().LayerType() == layers.LayerTypeICMPv4 || packet.NetworkLayer().LayerType() == layers.LayerTypeICMPv6 {
		pack.IsICMP = true
	}
	pack.Timestamp = packet.Metadata().Timestamp
	pack.Length = packet.Metadata().Length

	//put pack with same sip,dip in to Sameiplist slice
	vk := vkey{pack.netFlow, pack.trafficFlow.Src()}
	vkr := vkey{pack.netFlow.Reverse(), pack.trafficFlow.Dst()}

	if Sameiplist[vk] == nil && Sameiplist[vkr] == nil {
		//todo:the len of payload could have more statistic feature
		Sameiplist[vk] = &Packlist{isv: true, vkey: vk, Numpacp: 1, Maxlenpcap: pack.Length, Minlenpcap: pack.Length, Avglenpcap: pack.Length, Numicmp: 0, Proto: make(map[string]int), portlist: make(map[gopacket.Endpoint]bool)}
		Sameiplist[vk].portlist[pack.trafficFlow.Dst()] = true
		Sameiplist[vk].lenlist = append(Sameiplist[vk].lenlist, pack.Length)
		if pack.istcp && pack.syn {
			Sameiplist[vk].Numtcpreq++
		}
		List = Addtail(List, Sameiplist[vk])
	} else {
		if Sameiplist[vkr] != nil {
			ele := get(List, Sameiplist[vkr])
			List = adjustpositon(List, ele)
			Sameiplist[vkr].Numreply++
			if pack.istcp && pack.syn && pack.ack {
				Sameiplist[vkr].Numtcpres++
			}
		} else {
			//再次出现调整位置
			ele := get(List, Sameiplist[vk])
			List = adjustpositon(List, ele)
			//avg溢出问题，待修改
			Sameiplist[vk].Avglenpcap = ((Sameiplist[vk].Avglenpcap * Sameiplist[vk].Numpacp) + pack.Length) / (Sameiplist[vk].Numpacp + 1)
			Sameiplist[vk].Numpacp++
			if pack.Length > Sameiplist[vk].Maxlenpcap {
				Sameiplist[vk].Maxlenpcap = pack.Length
			}
			if pack.Length < Sameiplist[vk].Minlenpcap {
				Sameiplist[vk].Minlenpcap = pack.Length
			}
			data := stats.LoadRawData(Sameiplist[vk].lenlist)
			Sameiplist[vk].dispersity, _ = stats.Variance(data)
			Sameiplist[vk].portlist[pack.trafficFlow.Dst()] = true
			Sameiplist[vk].lenlist = append(Sameiplist[vk].lenlist, pack.Length)

		}
	}
	if pack.IsICMP {
		Sameiplist[vk].Numicmp++
	}

	//put pack with same sip,dpt in to Sameportlist slice
	hk := hkey{pack.netFlow.Src(), pack.trafficFlow}
	hkr := hkey{pack.netFlow.Dst(), pack.trafficFlow.Reverse()}
	if Sameportlist[hk] == nil && Sameportlist[hkr] == nil {
		Sameportlist[hk] = &Packlist{ish: true, hkey: hk, Numpacp: 1, Maxlenpcap: pack.Length, Minlenpcap: pack.Length, Avglenpcap: pack.Length, Numicmp: 0, Proto: make(map[string]int), iplist: make(map[gopacket.Endpoint]bool)}
		Sameportlist[hk].iplist[pack.netFlow.Dst()] = true
		Sameportlist[hk].lenlist = append(Sameportlist[hk].lenlist, pack.Length)
		if pack.istcp && pack.syn {
			Sameportlist[hk].Numtcpreq++
		}
		List = Addtail(List, Sameportlist[hk])
	} else {
		if Sameportlist[hkr] != nil {
			Sameportlist[hkr].Numreply++
			if pack.istcp && pack.syn && pack.ack {
				Sameportlist[hkr].Numtcpres++
			}
			ele := get(List, Sameportlist[hkr])
			List = adjustpositon(List, ele)
		} else {
			ele := get(List, Sameportlist[hk])
			List = adjustpositon(List, ele)
			//avg溢出问题，待修改
			Sameportlist[hk].Avglenpcap = ((Sameportlist[hk].Avglenpcap * Sameportlist[hk].Numpacp) + pack.Length) / (Sameportlist[hk].Numpacp + 1)
			Sameportlist[hk].Numpacp++
			if pack.Length > Sameportlist[hk].Maxlenpcap {
				Sameportlist[hk].Maxlenpcap = pack.Length
			}
			if pack.Length < Sameportlist[hk].Minlenpcap {
				Sameportlist[hk].Minlenpcap = pack.Length
			}
			data := stats.LoadRawData(Sameportlist[hk].lenlist)
			Sameportlist[hk].dispersity, _ = stats.Variance(data)
			Sameportlist[hk].iplist[pack.netFlow.Dst()] = true
			Sameportlist[hk].lenlist = append(Sameportlist[hk].lenlist, pack.Length)
		}
	}
	if pack.IsICMP {
		Sameportlist[hk].Numicmp++
	}
}

//test the out of scan detect
func printout() {
	for p := List.Front(); p != List.Back(); p = p.Next() {
		if t, ok := p.Value.(*Packlist); ok {
			if t.isv {
				fmt.Println("sip:", t.vkey.src_dst.Src(), "  vkey:", t.vkey.src_dst, "  reply:", t.Numreply, "  tcpreq:", t.Numtcpreq, "  tcpres:", t.Numtcpres, "  sum:", t.Numpacp, "  avg:", t.Avglenpcap, "  max:", t.Maxlenpcap, "  min:", t.Minlenpcap, "  dispersity:", t.dispersity, "  icmp:", t.Numicmp, "  dpt:", t.portlist, "  len:", t.lenlist)
			}
			if t.ish {
				fmt.Println("sip:", t.hkey.srcip, "  hkey:", t.hkey.spt_dpt, "  reply:", t.Numreply, "  tcpreq:", t.Numtcpreq, "  tcpres:", t.Numtcpres, "  sum:", t.Numpacp, "  avg:", t.Avglenpcap, "  max:", t.Maxlenpcap, "  min:", t.Minlenpcap, "  dispersity:", t.dispersity, "  icmp:", t.Numicmp, "  ip:", t.iplist, "  len:", t.lenlist)
			}
		}
	}
}

//tcp flow analyze
type Stafeature struct {
	Max       int
	Min       int
	Avg       int
	Streamavg int
	Num       int
	Sum       int
	tcpnum    int
}

var Servicelist map[string]*Stafeature

func Tcpinit() {
	Servicelist = make(map[string]*Stafeature)
}
func Gettcpinfo(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)
	srcip := ip.SrcIP.String()
	dstip := ip.DstIP.String()
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcp, _ := tcpLayer.(*layers.TCP)
	srcport := tcp.SrcPort.String()
	dstport := tcp.DstPort.String()
	src := srcip + ":" + srcport
	dst := dstip + ":" + dstport
	length := packet.Metadata().Length
	//testtime:=packet.Metadata().Timestamp
	//fmt.Println(testtime,length)
	if Servicelist[src] == nil && Servicelist[dst] == nil {
		if tcp.SYN && !tcp.ACK {
			Servicelist[dst] = &Stafeature{Avg: length, Max: length, Min: length, Streamavg: length, Num: 1, Sum: length, tcpnum: 1}
		}
	} else if Servicelist[dst] == nil {
		dst = src
	} else {
		sta := Servicelist[dst]
		if length < sta.Min {
			sta.Min = length
		}
		if length > sta.Max {
			sta.Max = length
		}
		sta.Num++
		sta.Sum = sta.Sum + length
		sta.Avg = sta.Sum / sta.Num
		sta.Streamavg = sta.Sum / sta.tcpnum
		if tcp.SYN && !tcp.ACK {
			sta.tcpnum++
		}
		Servicelist[dst] = sta
	}
}
func Stafresh() {
	var Db *sqlx.DB = ConnectMysql()
	defer Db.Close()
	fmt.Println("==ip:port===10s====max==min=avg==stravg==tcpnum==sum==num==")
	for k, v := range Servicelist {
		if v.Sum == 0 {
			continue
		}
		fmt.Println(k, " ", v.Max, v.Min, v.Avg, v.Streamavg, v.tcpnum, v.Sum, v.Num)

		//database operation
		//r, err := Db.Exec("insert into tcp_stat(ipport, max, min,avg,tcpnumsize) values(?, ?, ?, ?, ?)", k,v.Max,v.Min,v.Avg,v.Streamavg)
		//if err != nil {
		//	fmt.Println("exec failed, ", err)
		//}
		//id, err := r.LastInsertId()
		//if err != nil {
		//	fmt.Println("exec failed, ", err)
		//}
		//fmt.Println("insert succ:", id)

		//clear data every delta
		v.Clear()
	}
}
func (pack *Stafeature) Clear() {
	pack.Avg = 0
	pack.Streamavg = 0
	pack.Min = 9999999
	pack.Max = 0
	pack.Sum = 0
	pack.tcpnum = 1
	pack.Num = 0
}
