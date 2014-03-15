package ip6monitor

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type tcpTest struct {
	port          string
	host          string
	token         string
	sendData      string
	tls           bool
	hostformatted bool
	certfile      string
	keyfile       string
}

func NewTcpTest(host, port string) *tcpTest {
	return &tcpTest{host: host, port: port}
}

func (t *tcpTest) SetToken(token string) {
	t.token = token
}

func (t *tcpTest) SetSendData(data string) {
	t.sendData = data
}

func (t *tcpTest) SetTls(certfile, keyfile string) {
	t.tls = true
	t.certfile = certfile
	t.keyfile = keyfile
}

func (t *tcpTest) formatHost() error {
	if IsIPv6(t.host) {
		t.host = fmt.Sprintf("[%s]:%s", t.host, t.port)
	} else if IsHostName(t.host) {
		t.host = fmt.Sprintf("%s:%s", t.host, t.port)
	} else {
		return fmt.Errorf("%s is not a valid IPv6 address or hostname", t.host)
	}
	t.hostformatted = true
	return nil
}

func (t *tcpTest) GetTcp() ([]byte, error) {
	errbyte := make([]byte,0)
	var conn net.Conn
	var err error
	var n int
	var recv []byte
	if t.tls {
		//damn this nasty bug... redefined err and broke everything
		//rename to err2
		certs, err2 := tls.LoadX509KeyPair(t.certfile, t.keyfile)
		if err2 != nil {
			return errbyte, err
		}
		conf := tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{certs}}
		conn, err = tls.Dial("tcp6", t.host, &conf)
	} else {
		conn, err = net.Dial("tcp6", t.host)
	}
	if err != nil {
		return errbyte, err
	}
	defer conn.Close()
	if t.sendData != "" {
		_, err = conn.Write([]byte(t.sendData))
		if err != nil {
			return errbyte, err
		}
	}
	if t.token != "" {
		recv = make([]byte, 32000)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err = conn.Read(recv)
		recv = recv[0 : n+1]
	}
	return recv, err
}

func (t *tcpTest) Test() (bool, string, error) {
	retdata := ""
	if !t.hostformatted {
		err := t.formatHost()
		if err != nil {
			return false, retdata, err
		}
	}
	resp, err := t.GetTcp()
	if err != nil {
		return false, string(resp), err
	}
	retdata = string(resp)
	if t.token != "" {
		if !strings.Contains(strings.ToLower(retdata), strings.ToLower(t.token)) {
			return false, retdata, fmt.Errorf("%s not found in result text.", t.token)
		}
	}
	return true, retdata, nil
}
