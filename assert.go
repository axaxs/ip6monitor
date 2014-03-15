package ip6monitor

import("strings";"net";"strconv")

const(
	IPv4 = 0
	IPv6 = 1
	HOSTNAME = 2
	UNKNOWN = 3
)

func IsIPv6(address string) bool {
	addy := net.ParseIP(address)
	if addy == nil {
		return false
	}
	if addy.To4() == nil{
		return true
	}
	return false
}

func IsHostName(host string) bool {
	if IsIPv6(host) || strings.Count(host, ":") > 0 {
		return false
	}
	for _,v := range strings.Split(host, ".") {
		_, err := strconv.Atoi(v)
		if err != nil {
			return true
		}
	}
	return false
}


func IsIPv4(address string) bool {
        addy := net.ParseIP(address)
        if addy == nil {
                return false
        }
        if addy.To4 != nil{
                return true
        }
        return false
}

func DetermineType(host string) int {
	switch {
	case IsIPv4(host):
		return 0
	case IsIPv6(host):
		return 1
	case IsHostName(host):
		return 2
	default:
		return 3
	}
}
