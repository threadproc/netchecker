package main

import (
	"github.com/showwin/speedtest-go/speedtest"
	"strings"
	"time"
)

func checkSpeed(dnsServer string, gw string) (int, error) {
	// get the dns for www.speedtest.net
	defer clearStaticRouteDNS("www.speedtest.net", dnsServer)
	if err := staticRouteDNS("www.speedtest.net", dnsServer, gw); err != nil {
		return 0, err
	}
	time.Sleep(100 * time.Millisecond)

	// get the server
	speedClient := speedtest.New()
	serverList, err := speedClient.FetchServers()
	if err != nil {
		return 0, err
	}
	targets, err := serverList.FindServer([]int{})
	if err != nil {
		return 0, err
	}

	for _, t := range targets {
		hostParts := strings.Split(t.Host, ":")

		// static route the test server
		defer clearStaticRouteDNS(hostParts[0], dnsServer)
		if err := staticRouteDNS(hostParts[0], dnsServer, gw); err != nil {
			return 0, err
		}
		time.Sleep(100 * time.Millisecond)

		// ensure we can actually connect to it
		if err := t.PingTest(nil); err != nil {
			// skip
			continue
		}

		// test!
		if err := t.DownloadTest(); err != nil {
			return 0, err
		}

		return int(t.DLSpeed), nil
	}

	return 0, nil
}
