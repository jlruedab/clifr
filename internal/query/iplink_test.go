package query

import (
	"strings"
	"testing"

	"clifr/internal/store"
)

// Two links as iproute2 6.19 printed them on the test machine (ip -s -d
// link), lo and a wireless interface with an altname.
func TestPrintIPLink(t *testing.T) {
	none := func(l *store.LinkRow) {
		for _, p := range []*int64{&l.Master, &l.Link, &l.LinkNetnsID, &l.ProtoDown, &l.CarrierChanges} {
			*p = -1
		}
	}
	lo := store.LinkRow{Index: 1, Type: 772, Flags: 0x10049, Name: "lo", Qdisc: "noqueue", MTU: 65536, OperState: 0, LinkMode: 0,
		TxQLen: 1000, Promiscuity: 0, Allmulti: 0, MinMTU: 0, MaxMTU: 0, NetnsImmutable: 1, AddrGenMode: 0, NumTxQueues: 1,
		NumRxQueues: 1, GSOMaxSize: 65536, GSOMaxSegs: 65535, TSOMaxSize: 524280, TSOMaxSegs: 65535, GROMaxSize: 65536,
		GSOIPv4MaxSize: 65536, GROIPv4MaxSize: 65536, Address: make([]byte, 6), Broadcast: make([]byte, 6), HasStats: true}
	none(&lo)
	lo.Stats[stRxBytes], lo.Stats[stRxPackets], lo.Stats[stTxBytes], lo.Stats[stTxPackets] = 40769746, 712813, 40769746, 712813
	wl := store.LinkRow{Index: 4, Type: 1, Flags: 0x11043, Name: "wlp0s20f3", Qdisc: "noqueue", MTU: 1500, OperState: 6, LinkMode: 1,
		TxQLen: 1000, Promiscuity: 0, Allmulti: 0, MinMTU: 256, MaxMTU: 2304, NetnsImmutable: 1, AddrGenMode: 1, NumTxQueues: 1,
		NumRxQueues: 1, GSOMaxSize: 65536, GSOMaxSegs: 65535, TSOMaxSize: 65536, TSOMaxSegs: 65535, GROMaxSize: 65536,
		GSOIPv4MaxSize: 65536, GROIPv4MaxSize: 65536, ParentBus: "pci", ParentDev: "0000:00:14.3", AltNames: "wlxa0d365f1a0c7",
		Address: []byte{0xa0, 0xd3, 0x65, 0xf1, 0xa0, 0xc7}, Broadcast: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, HasStats: true}
	none(&wl)
	wl.Stats[stRxBytes], wl.Stats[stRxPackets], wl.Stats[stTxBytes], wl.Stats[stTxPackets] = 6692790788, 5139928, 316819365, 1659184
	var sb strings.Builder
	PrintIPLink(&sb, []store.LinkRow{lo, wl}, IPLinkOptions{Stats: 1, Details: true})
	want := `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0 allmulti 0 minmtu 0 maxmtu 0 netns-immutable addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 gso_ipv4_max_size 65536 gro_ipv4_max_size 65536 
    RX:  bytes packets errors dropped  missed   mcast           
      40769746  712813      0       0       0       0 
    TX:  bytes packets errors dropped carrier collsns           
      40769746  712813      0       0       0       0 
4: wlp0s20f3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DORMANT group default qlen 1000
    link/ether a0:d3:65:f1:a0:c7 brd ff:ff:ff:ff:ff:ff promiscuity 0 allmulti 0 minmtu 256 maxmtu 2304 netns-immutable addrgenmode none numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 gso_ipv4_max_size 65536 gro_ipv4_max_size 65536 parentbus pci parentdev 0000:00:14.3 
    RX:  bytes packets errors dropped  missed   mcast           
    6692790788 5139928      0       0       0       0 
    TX:  bytes packets errors dropped carrier collsns           
     316819365 1659184      0       0       0       0 
    altname wlxa0d365f1a0c7
`
	if sb.String() != want {
		t.Errorf("got\n%s\nwant\n%s", sb.String(), want)
	}
}
