package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type mikrotikAPI struct {
	baseUrl string
	user    string
	pass    string
	client  *http.Client
}

func newMikrotikAPI(baseUrl string, user string, pass string) *mikrotikAPI {
	return &mikrotikAPI{
		baseUrl,
		user,
		pass,
		&http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (ma *mikrotikAPI) do(req *http.Request, payload any) error {
	resp, err := ma.client.Do(req)
	if err != nil {
		return err
	}

	// don't bother reading the response if we don't want it
	if payload == nil {
		if resp.StatusCode >= 400 {
			return errors.New(resp.Status)
		}
		return nil
	}

	bdbs, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	log.Debugf("%s %s (%d): %s", req.Method, req.URL.String(), resp.StatusCode, string(bdbs))

	if err := json.Unmarshal(bdbs, payload); err != nil {
		return err
	}

	// we want to return an error for bad status codes
	if resp.StatusCode >= 400 {
		return errors.New(resp.Status)
	}

	return nil
}
func (ma *mikrotikAPI) newRequest(method string, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("%s/%s", ma.baseUrl, url), body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(ma.user, ma.pass)
	return req, nil
}

func (ma *mikrotikAPI) get(endpoint string, data any) error {
	req, err := ma.newRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}

	if err := ma.do(req, data); err != nil {
		return err
	}

	return nil
}

func (ma *mikrotikAPI) delete(endpoint string) error {
	req, err := ma.newRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}

	return ma.do(req, nil)
}

func (ma *mikrotikAPI) put(endpoint string, data any) error {
	bs, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := ma.newRequest(http.MethodPut, endpoint, bytes.NewReader(bs))
	if err != nil {
		return err
	}

	return ma.do(req, nil)
}

func (ma *mikrotikAPI) patch(endpoint string, data any) error {
	bs, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := ma.newRequest(http.MethodPatch, endpoint, bytes.NewReader(bs))
	if err != nil {
		return err
	}

	return ma.do(req, nil)
}

func (ma *mikrotikAPI) test() error {
	ident := map[string]string{}
	if err := ma.get("system/identity", &ident); err != nil {
		return err
	}
	log.Infof("Connected to: %s", ident["name"])
	return nil
}

func (ma *mikrotikAPI) wanInterfaces() ([]string, error) {
	data := []map[string]string{}
	if err := ma.get("interface/list", &data); err != nil {
		return nil, err
	}

	listID := ""

	for _, iflist := range data {
		if strings.EqualFold(iflist["name"], "wan") {
			listID = iflist["name"]
			break
		}
	}

	if len(listID) == 0 {
		return nil, errors.New("no wan interface list found")
	}

	wanifs := []string{}
	ifaces := []map[string]any{}
	if err := ma.get("interface/list/member?list="+listID, &ifaces); err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface["disabled"] != "true" {
			wanifs = append(wanifs, iface["interface"].(string))
		}
	}
	return wanifs, nil
}

func (ma *mikrotikAPI) dhcpInfo(iface string) (map[string]string, error) {
	dhcpClients := []map[string]string{}
	if err := ma.get("ip/dhcp-client", &dhcpClients); err != nil {
		return nil, err
	}

	for _, client := range dhcpClients {
		if strings.EqualFold(client["interface"], iface) {
			return client, nil
		}
	}

	return nil, nil
}

func (ma *mikrotikAPI) setDHCPRouteDistance(dhcpClientId string, distance int) error {
	return ma.patch("ip/dhcp-client/"+dhcpClientId, map[string]string{
		"default-route-distance": strconv.Itoa(distance),
	})
}

func (ma *mikrotikAPI) setStaticRoute(ip string, gw string) error {
	return ma.put("ip/route", map[string]any{
		"dst-address": ip,
		"gateway":     gw,
		"distance":    "1",
		"comment":     "netchecker",
	})
}

func (ma *mikrotikAPI) cleanupRoutes() error {
	routes := []map[string]string{}
	if err := ma.get("ip/route", &routes); err != nil {
		return err
	}

	for _, route := range routes {
		if route["comment"] == "netchecker" {
			if err := ma.delete("ip/route/" + route[".id"]); err != nil {
				return err
			}
		}
	}

	return nil
}

func (ma *mikrotikAPI) clearStaticRoute(ip string) error {
	// get all the routes
	routes := []map[string]string{}
	if err := ma.get("ip/route", &routes); err != nil {
		return err
	}

	for _, route := range routes {
		if route["dst-address"] == ip {
			// clear the route
			//log.Infof("removing static route for %s", ip)
			if err := ma.delete("ip/route/" + route[".id"]); err != nil {
				return err
			}
		}
	}

	return nil
}
