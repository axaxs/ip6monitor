package ip6monitor

import (
	"fmt"
	"os/exec"
	"strings"
)

type pingTest struct {
	host string
}

func NewPingTest(host string) *pingTest {
	return &pingTest{host}
}

func (p *pingTest) TestPing() (bool, string, error) {
	out, err := exec.Command("ping6", p.host, "-c", "1", "-w", "5").Output()
	if err != nil {
		return false, "", err
	}
	sout := string(out)
	slin := strings.Split(sout, "\n")
	for _, v := range slin {
		if strings.Contains(v, "packet loss") {
			if strings.Contains(v, " 0% packet loss") {
				return true, sout, nil
			} else {
				return false, sout, fmt.Errorf(v)
			}
		}
	}
	return false, sout, fmt.Errorf("Test did not find string, test is broken?")
}

func (p *pingTest) Test() (bool, string, error) {
	return p.TestPing()
}
