package main

import (
	"github.com/pkg/errors"
	probing "github.com/prometheus-community/pro-bing"
	log "github.com/sirupsen/logrus"
	"os"
	"strconv"
	"strings"
	"time"
)

var api *mikrotikAPI
var externalCheckHosts = []string{"1.0.0.1", "8.8.4.4"}

func envOrDefault(key string, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

type ifStatus struct {
	ifName             string
	invalidConfig      bool
	gatewayPacketLoss  int
	externalPacketLoss int
	dnsOkay            bool
	msftConnTest       bool
	throughput         int
	routeDistance      int
	dhcpClientId       string
	gateway            string
}

func (ifs *ifStatus) isBad() bool {
	// it is bad if there is fundamental issues
	if ifs.invalidConfig || !ifs.dnsOkay || !ifs.msftConnTest {
		return true
	}

	// it is bad if there is any packet loss
	if ifs.gatewayPacketLoss > 0 || ifs.externalPacketLoss > 0 {
		return true
	}

	return false
}

func evaluateInterface(ifname string, speedTest bool) (*ifStatus, error) {
	log.Infof("evaluating interface %s", ifname)
	ifstats := &ifStatus{
		ifName:        ifname,
		invalidConfig: true,
	}

	dhcp, err := api.dhcpInfo(ifname)
	if err != nil {
		return ifstats, errors.Wrap(err, "could not get dhcp client info")
	}

	ifstats.dhcpClientId, _ = dhcp[".id"]
	ifstats.routeDistance, _ = strconv.Atoi(dhcp["default-route-distance"])
	var ok bool
	ifstats.gateway, ok = dhcp["gateway"]
	if !ok {
		// definitely don't want to monitor this one
		return ifstats, nil
	}

	// config is validated enough
	ifstats.invalidConfig = false

	// check that the gateway is up
	gwpinger, err := probing.NewPinger(ifstats.gateway)
	if err != nil {
		return nil, errors.Wrap(err, "could not create gateway pinger")
	}
	gwpinger.Interval = 500 * time.Millisecond
	gwpinger.Count = 3
	gwpinger.Timeout = 5 * time.Second
	if err := gwpinger.Run(); err != nil {
		return nil, errors.Wrap(err, "could not ping gateway")
	}

	stats := gwpinger.Statistics()
	ifstats.gatewayPacketLoss = int(stats.PacketLoss)

	// set static routes on mikrotik for the ips
	for _, extaddr := range externalCheckHosts {
		if err := api.clearStaticRoute(extaddr + "/32"); err != nil {
			return nil, errors.Wrap(err, "could not clear static route to dns server")
		}
		if err := api.setStaticRoute(extaddr+"/32", ifstats.gateway); err != nil {
			return nil, errors.Wrap(err, "could not set static route to dns server")
		}
		defer api.clearStaticRoute(extaddr + "/32")
	}

	// wait for routes to settle
	time.Sleep(100 * time.Millisecond)

	// there is no packet loss to the gateway, check another address
	for _, extaddr := range externalCheckHosts {
		extping, err := probing.NewPinger(extaddr)
		if err != nil {
			return nil, errors.Wrap(err, "could not create external pinger")
		}
		extping.Interval = 500 * time.Millisecond
		extping.Count = 3
		extping.Timeout = 5 * time.Second

		if err := extping.Run(); err != nil {
			return nil, errors.Wrap(err, "could not ping external address")
		}
		// add it
		extstats := extping.Statistics()
		ifstats.externalPacketLoss = max(ifstats.externalPacketLoss, int(extstats.PacketLoss))
	}

	// check dns with the external hosts
	workingDNS := ""
	for _, extDNS := range externalCheckHosts {
		if checkDNS(extDNS) {
			// we only need a single dns success
			ifstats.dnsOkay = true
			workingDNS = extDNS

			// we know this dns server works, so we will use it for the msft test
			ifstats.msftConnTest = msftConnCheck(extDNS, ifstats.gateway)
			break
		}
	}

	// check speed
	if speedTest && ifstats.dnsOkay {
		ifstats.throughput, err = checkSpeed(workingDNS, ifstats.gateway)
		if err != nil {
			return nil, errors.Wrap(err, "could not run speedtest")
		}
	}

	return ifstats, nil
}

func scoreInterfaces(ifs map[string]*ifStatus) map[string]int {
	scores := map[string]int{}
	maxThroughput := 0
	for _, i := range ifs {
		// starting score for all interfaces
		scores[i.ifName] = 16
		maxThroughput = max(maxThroughput, i.throughput)
	}

	for _, i := range ifs {
		// immediately disqualifying
		if i.invalidConfig {
			scores[i.ifName] = 256
			continue
		}

		// factor in packet loss, trending towards max points at 25% loss
		if i.gatewayPacketLoss > 0 || i.externalPacketLoss > 0 {
			// this will dramatically ruin the score, scale it and add it
			penalty := int(float64(max(i.gatewayPacketLoss, i.externalPacketLoss)/100) * 1024)
			scores[i.ifName] += penalty
		}

		// check if DNS is working, if not penalize it by 128 points
		if !i.dnsOkay {
			scores[i.ifName] += 128
		}

		// this test is slightly less weighted, we want it to balance out most of the throughput issues
		if !i.msftConnTest {
			scores[i.ifName] += 64
		}

		// get the max throughput of any interface, and then we want to take this throughput as a % of it
		// add points: 64 - (our percent * 64)
		// this will add between 0 (best conn) and 64 (worst conn) points
		if maxThroughput > 0 {
			speedScore := int(float64(i.throughput) / float64(maxThroughput) * 64)
			scores[i.ifName] += max(0, 64-speedScore)
		}

		// cap it to 255, so invalid configs are still worse
		scores[i.ifName] = min(255, scores[i.ifName])
	}

	return scores
}

func rerankInterfaces() (map[string]int, error) {
	// do the check
	wanIfaces, err := api.wanInterfaces()
	if err != nil {
		return nil, errors.Wrap(err, "could not get wan interfaces")
	}
	if len(wanIfaces) < 2 {
		return nil, errors.New("must have at least two wan interfaces")
	}

	// we are good
	interfaceStatus := map[string]*ifStatus{}
	defer func() {
		if err := api.cleanupRoutes(); err != nil {
			log.WithError(err).Error("failed to cleanup static routes")
		}
	}()

	for _, ifname := range wanIfaces {
		var err error
		interfaceStatus[ifname], err = evaluateInterface(ifname, true)
		if err != nil {
			return nil, errors.Wrapf(err, "could not evaluate interface %s", ifname)
		}
		if err := api.cleanupRoutes(); err != nil {
			return nil, errors.Wrap(err, "could not cleanup static routes")
		}
	}

	scores := scoreInterfaces(interfaceStatus)

	for iface, ifstats := range interfaceStatus {
		score := scores[iface]

		if score != ifstats.routeDistance {
			if err := api.setDHCPRouteDistance(ifstats.dhcpClientId, score); err != nil {
				return nil, errors.Wrapf(err, "could not set dhcp default route distance for %s to %d", iface, score)
			}
		}
	}

	return scores, nil
}

func main() {
	//log.SetLevel(log.DebugLevel)

	apiAddr := envOrDefault("API_ADDR", "192.168.0.1")
	apiUser := envOrDefault("API_USER", "admin")
	apiPass := envOrDefault("API_PASS", "")

	if len(apiPass) == 0 {
		log.Fatal("API_PASS environment variable not set")
	}

	if !strings.Contains(apiAddr, "://") {
		apiAddr = "http://" + apiAddr
	}
	apiAddr = apiAddr + "/rest"

	api = newMikrotikAPI(apiAddr, apiUser, apiPass)

	if err := api.test(); err != nil {
		log.WithError(err).Fatal("Failed to connect to Mikrotik API")
	}

	for {
		// we always want to evaluate this at least once
		log.Info("ranking WAN interfaces")
		scores, err := rerankInterfaces()
		if err != nil {
			log.WithError(err).Error("failed to rank interfaces!")
			log.Info("retrying in 10s...")
			time.Sleep(10 * time.Second)
			continue
		}

		lastRanking := time.Now()

		for {
			// check the lowest scored one
			lowestIfScore := 1024
			lowestIfName := ""
			for netIf, score := range scores {
				if score < lowestIfScore {
					lowestIfScore = score
					lowestIfName = netIf
				}
			}

			if lowestIfName == "" {
				panic("could not find the lowest interface")
			}

			// re-rank the interface without speed testing it
			ifs, err := evaluateInterface(lowestIfName, false)
			if err != nil {
				log.WithError(err).Error("failed to evaluate interface!")
				break
			}
			if ifs.isBad() {
				// it is bad! we should try to re-rank
				log.Info("network conditions are bad, re-ranking interfaces")
				break
			}

			if lastRanking.Add(30 * time.Minute).Before(time.Now()) {
				// expired!
				log.Info("rankings expired, forcing re-ranking")
				break
			}

			log.Info("network conditions seem okay, continuing")

			time.Sleep(1 * time.Minute)
		}
	}
}
