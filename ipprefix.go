/* Copyright (c) 2025 Waldemar Augustyn */

package common

import (
	"errors"
	"net/netip"
)

type IPPrefix netip.Prefix // .Addr().Zone() must be "", and must be .Masked()

func (p IPPrefix) Addr() IP {
	return IP(netip.Prefix(p).Addr())
}

func (p IPPrefix) Bits() int {
	return netip.Prefix(p).Bits()
}

func IPPrefixFrom(ip IP, bits int) IPPrefix {
	return IPPrefix(netip.PrefixFrom(netip.Addr(ip), bits).Masked())
}

func (p IPPrefix) String() string {
	return netip.Prefix(p).String()
}

func ParseIPPrefix(s string) (IPPrefix, error) {

	p, err := netip.ParsePrefix(s)
	if err != nil {
		return IPPrefix{}, err
	}
	if p.Addr().Zone() != "" {
		return IPPrefix{}, errors.New("IP address prefix may not have zone")
	}
	return IPPrefix(p.Masked()), nil
}

func MustParseIPPrefix(s string) IPPrefix {

	p, err := ParseIPPrefix(s)
	if err != nil {
		panic("invalid IP address prefix")
	}
	return p
}

func IPPrefixSingle(ip IP) IPPrefix {
	return IPPrefixFrom(ip, ip.Len() * 8)
}

func IPPrefixComplete(ipver int) IPPrefix {
	return IPPrefixFrom(IPZero(IPVerToLen(ipver)), 0)
}

func (p IPPrefix) Contains(ip IP) bool {
	return netip.Prefix(p).Contains(netip.Addr(ip))
}
