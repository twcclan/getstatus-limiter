package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/hashicorp/golang-lru"
	"golang.org/x/time/rate"
)

const (
	// how many packets per second clients are allowed to send on average
	packetsPerSecond = 100

	// the number of packets a single client may send at most per second
	burst = 3000
)

var (
	// this is a lru cache used to hold the token buckets
	// that are used for rate limiting
	cache, _ = lru.New(10240)

	// a map that holds all IP addresses that were banned already
	// used to prevent double-banning an IP
	// TODO: should probably forget addresses after some time
	offenders = make(map[string]bool)

	// this map holds all local ipv4 addresses
	locals = make(map[string]bool)
)

type remote struct {
	limiter *rate.Limiter
	first   time.Time
	total   uint64
}

// store all local ipv4 addresses
func getLocalAddresses() {
	i, _ := net.Interfaces()

	for _, iface := range i {
		addrs, _ := iface.Addrs()

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			ipv4 := ip.To4()
			if ipv4 != nil {
				locals[ipv4.String()] = true
			}
		}
	}
}

// retrieve a token bucket from the cache, keyed by ip address
func getRemote(key string) *remote {
	if bkt, ok := cache.Get(key); ok {
		return bkt.(*remote)
	} else {
		r := &remote{
			limiter: rate.NewLimiter(packetsPerSecond, burst),
			first:   time.Now(),
			total:   0,
		}

		cache.Add(key, r)

		return r
	}
}

// handle a network packet
func handlePacket(p gopacket.Packet) {
	flow := p.NetworkLayer().NetworkFlow()

	// get the destination ip address
	dst := flow.Dst().String()

	// check if we need to count packets
	if !locals[dst] && !offenders[dst] {
		//log.Printf("%s -> %s", flow.Src(), flow.Dst())
		r := getRemote(dst)
		r.total++

		// if all tokens are used, ban the ip address
		// because it's most likely trying to abuse our bandwidth
		if !r.limiter.Allow() {
			offenders[dst] = true
			log.Printf("Offender %s, %d packets over %v", dst, r.total, time.Since(r.first))
			output, err := exec.Command("iptables", "-A", "INPUT", "-s", dst, "-j", "DROP").CombinedOutput()
			if err != nil {
				log.Printf("Failed banning IP: %s %s %s", dst, err.Error(), string(output))
			}
		}
	}
}

// build the filter string for pcap
// it only applies to outgoing packets, stateless ET packets
// this dramatically reduces the number of packets that need
// to be lifted into user space for us
func getFilterString() string {
	if len(locals) == 0 {
		return ""
	}

	addrs := make([]string, 0, len(locals))

	for ip := range locals {
		addrs = append(addrs, ip)
	}

	return fmt.Sprintf("(src host %s) and udp and udp[8:4] = 0xFFFFFFFF", strings.Join(addrs, " or "))
}

func main() {
	getLocalAddresses()
	log.Print(getFilterString())

	//if handle, err := pcap.OpenOffline("attack3.pcap"); err != nil {
	if handle, err := pcap.OpenLive("any", 512, false, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(getFilterString()); err != nil {
		panic(err)
	} else {
		//var offset time.Duration

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {

			/*
				// delay to simulate actual time span
				if offset == 0 {
					offset = time.Now().Sub(packet.Metadata().Timestamp)
				}

				sleep := packet.Metadata().Timestamp.Add(offset).Sub(time.Now())
				time.Sleep(sleep)
			*/

			handlePacket(packet)
		}
	}
}
