package ip6monitor

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
)

type httpTest struct {
	url           string
	host          string
	ip            string
	token         string
	https         bool
	req           *http.Request
	hostformatted bool
}

func NewHttpTest(url string) *httpTest {
	httph := &httpTest{url: url}
	httph.testHttps()
	httph.req, _ = http.NewRequest("GET", httph.url, nil)
	httph.host = httph.req.Host
	httph.req.Header.Set("User-Agent", "Registry IPv6 Monitor")
	httph.req.Header.Set("Connection", "Close")
	httph.req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	httph.req.Header.Set("Accept-Encoding", "gzip,deflate")
	httph.req.Header.Set("Accept-Language", "en-US,en;q=0.8")
	return httph
}

func (h *httpTest) SetIP(ip string) error {
	if ip == "" {
		return nil
	}
	if !IsIPv6(ip) {
		return fmt.Errorf("Invalid IPv6 entered: %s", ip)
	}
	h.ip = ip
	return nil
}

func (h *httpTest) SetToken(token string) {
	h.token = token
}

func (h *httpTest) SetPostData(data string) {
	if data != "" {
		h.req, _ = http.NewRequest("POST", h.url, strings.NewReader(data))
		h.req.Header.Set("User-Agent", "Registry IPv6 Monitor")
		h.host = h.req.Host
		h.req.Header.Set("Connection", "Close")
	}	
}

func (h *httpTest) testHttps() {
	if strings.HasPrefix(strings.ToLower(h.url), "https") {
		h.https = true
	} else {
		h.https = false
	}

}

func (h *httpTest) formatHost() error {
	if h.ip != "" {
		h.host = h.ip
	}
	if IsIPv6(h.host) && !strings.HasPrefix(h.host, "[") {
		h.host = "[" + h.host + "]"
	}
	_, _, e := net.SplitHostPort(h.host)
	if e != nil {
		if strings.Contains(e.Error(), "missing port") {
			if IsIPv6(h.host) {
				h.host = "[" + h.host + "]"
			}
			if h.https {
				h.host += ":443"
			} else {
				h.host += ":80"
			}
		} else {
			return e
		}
	}
	h.hostformatted = true
	return nil
}

func (h *httpTest) GetHttp() ([]byte, error) {
	var errbyte []byte
	var conn net.Conn
	var err error
	if h.https {
		conn, err = tls.Dial("tcp6", h.host, nil)
	} else {
		conn, err = net.Dial("tcp6", h.host)
	}
	if err != nil {
		return errbyte, err
	}
	defer conn.Close()
	err = h.req.Write(conn)
	if err != nil {
		return errbyte, err
	}
	bufread := bufio.NewReader(conn)
	resp, err := http.ReadResponse(bufread, h.req)
	if err != nil {
		return errbyte, err
	}
	defer resp.Body.Close()
	loc, err := resp.Location()
	var ret []byte
	if err == nil && loc.String() != h.url {
		x := NewHttpTest(loc.String())
		ret, err = x.GetHttp()
	} else {
		ret, err = ioutil.ReadAll(resp.Body)
	}
	return ret, err
}

func (h *httpTest) Test() (bool, string, error) {
	retdata := ""
	if !h.hostformatted {
		err := h.formatHost()
		if err != nil {
			return false, retdata, err
		}
	}
	resp, err := h.GetHttp()
	if err != nil {
		return false, retdata, err
	}
	retdata = string(resp)
	if h.token != "" {
		if !strings.Contains(strings.ToLower(retdata), strings.ToLower(h.token)) {
			return false, retdata, fmt.Errorf("%s not found in body of webpage", h.token)
		}
	}
	return true, retdata, nil
}
