package main

import (
	"github.com/miekg/dns"
	"io"
	"net/http"
	"time"
)

var dnsClient = new(dns.Client)

func checkDNS(dnsServer string) bool {
	dnsServer += ":53"
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("www.msftconnecttest.com"), dns.TypeA)

	dnsClient.Timeout = 1 * time.Second
	in, _, err := dnsClient.Exchange(m, dnsServer)
	return err == nil && len(in.Answer) > 0
}

func staticRouteDNS(hostname string, dnsServer string, gw string) error {
	as, err := getARecords(hostname, dnsServer)
	if err != nil {
		return err
	}
	for _, a := range as {
		if err := api.clearStaticRoute(a + "/32"); err != nil {
			return err
		}
		if err := api.setStaticRoute(a+"/32", gw); err != nil {
			return err
		}
	}
	return nil
}
func clearStaticRouteDNS(hostname string, dnsServer string) error {
	as, err := getARecords(hostname, dnsServer)
	if err != nil {
		return err
	}
	for _, a := range as {
		if err := api.clearStaticRoute(a + "/32"); err != nil {
			return err
		}
	}
	return nil
}

func getARecords(hostname string, dnsServer string) ([]string, error) {
	dnsServer += ":53"
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeA)

	in, _, err := dnsClient.Exchange(m, dnsServer)
	if err != nil {
		return nil, err
	}

	addrs := []string{}
	for _, ans := range in.Answer {
		if ans.Header().Rrtype == dns.TypeA {
			ar := ans.(*dns.A)
			addrs = append(addrs, ar.A.String())
		}
	}

	return addrs, nil
}

func msftConnCheck(dnsServer string, gw string) bool {
	url := "http://www.msftconnecttest.com/connecttest.txt"

	addrs, err := getARecords("www.msftconnecttest.com", dnsServer)
	if err != nil || len(addrs) == 0 {
		return false
	}

	for _, addr := range addrs {
		if err := api.clearStaticRoute(addr + "/32"); err != nil {
			return false
		}
		if err := api.setStaticRoute(addr+"/32", gw); err != nil {
			return false
		}
		// we've set it
		defer api.clearStaticRoute(addr + "/32")
	}

	cl := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := cl.Get(url)
	if err != nil {
		return false
	}

	if resp.StatusCode != http.StatusOK {
		return false
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	return string(bs) == "Microsoft Connect Test"
}
