package ip6monitor

import (
	"fmt"
	"github.com/miekg/dns"
	"strings"
	"time"
)

type dnsTest struct {
	host          string
	question      string
	qtype         string
	answer        string
	port          string
	hostformatted bool
}

func NewDnsTest(question, qtype string) *dnsTest {
	return &dnsTest{question: question, qtype: qtype}
}

func (d *dnsTest) SetHost(host string) {
	d.host = host
}

func (d *dnsTest) SetAnswer(answer string) {
	d.answer = answer
}

func (d *dnsTest) formatHost() error {
	if d.port == "" {
		d.port = "53"
	}
	if d.host == "" {
		d.host = "2001:4860:4860::8888"
	}
	if IsIPv6(d.host) {
		d.host = fmt.Sprintf("[%s]:%s", d.host, d.port)
	} else if IsHostName(d.host) {
		d.host = fmt.Sprintf("%s:%s", d.host, d.port)
	} else {
		return fmt.Errorf("%s is not a valid IPv6 address or hostname", d.host)
	}
	if !strings.HasSuffix(d.question, ".") {
		d.question = d.question + "."
	}
	d.hostformatted = true
	return nil
}

func (d *dnsTest) GetDns() (*dns.Msg, time.Duration, error) {
	var err error
	c := new(dns.Client)
	m := new(dns.Msg)
	var ty uint16
	var r *dns.Msg
	var t time.Duration
	for k, v := range dns.TypeToString {
		if strings.ToLower(v) == strings.ToLower(d.qtype) {
			ty = k
		}
	}
	if ty == 0 {
		return r, t, fmt.Errorf("Invalid type specified: %s", ty)
	}
	m.SetQuestion(d.question, ty)
	m.RecursionDesired = true
	c.Net = "udp6"
	r, t, err = c.Exchange(m, d.host)
	if err != nil {
		return r, t, err
	}
	if r.Truncated {
		c.Net = "tcp6"
		rr, tt, err := c.Exchange(m, d.host)
		if err == nil {
			t = tt
			r = rr
		}
	}
	return r, t, err
}

func (d *dnsTest) Test() (bool, string, error) {
	retdata := ""
	if !d.hostformatted {
		err := d.formatHost()
		if err != nil {
			return false, retdata, err
		}
	}
	resp, _, err := d.GetDns()
	if err != nil {
		return false, retdata, err
	}
	if resp.Rcode != 0 {
		return false, retdata, fmt.Errorf("Nameserver returned %s", dns.RcodeToString[resp.Rcode])
	}
	ans := make([]string, len(resp.Answer))
	for i, v := range resp.Answer {
		ans[i] = v.String()
	}
	retdata = strings.Join(ans, ",")
	if d.answer != "" {
		for _, v := range ans {
			if strings.Contains(strings.ToLower(v), strings.ToLower(d.answer)) {
				return true, retdata, nil
			}
		}
		return false, retdata, fmt.Errorf("Answer %s not found in response.", d.answer)
	}
	return true, retdata, nil
}
