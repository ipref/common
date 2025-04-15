package common

import (
	rff "github.com/ipref/ref"
)

const ( // v1 constants

	V1_SIG      = 0x11 // v1 signature
	V1_HDR_LEN  = 8
	V1_MARK_LEN = 4 + 4 // oid + mark
	// v1 header offsets
	V1_VER      = 0 // must be 0x11
	V1_CMD      = 1
	V1_PKTID    = 2
	V1_IPVER    = 4 // high nibble is the ea IP ver, low nibble is gw IP ver
	V1_RESERVED = 5
	V1_PKTLEN   = 6
	// v1 mark offsets
	V1_OID  = 0
	V1_MARK = 4
	// v1 host data offsets
	V1_HOST_DATA_BATCHID = 0
	V1_HOST_DATA_COUNT   = 0
	V1_HOST_DATA_HASH    = 4
	V1_HOST_DATA_SOURCE  = 12
	// v1 save dnssource offsets
	V1_DNSSOURCE_MARK   = 4
	V1_DNSSOURCE_XMARK  = 4
	V1_DNSSOURCE_HASH   = 8
	V1_DNSSOURCE_SOURCE = 16
)

const ( // v1 item types

	//V1_TYPE_NONE   = 0
	//V1_TYPE_AREC   = 1
	//V1_TYPE_IPV4   = 3
	V1_TYPE_STRING = 4
)

const ( // v1 commands

	V1_NOOP           = 0
	V1_SET_AREC       = 1
	V1_SET_MARK       = 2
	V1_GET_REF        = 4
	V1_GET_EA         = 6
	V1_MC_GET_EA      = 7
	V1_SAVE_OID       = 8
	V1_SAVE_TIME_BASE = 9
	V1_RECOVER_EA     = 10
	V1_RECOVER_REF    = 11

	V1_MC_HOST_DATA      = 14
	V1_MC_HOST_DATA_HASH = 15
	V1_SAVE_DNSSOURCE    = 16
)

const ( // v1 command mode, top two bits

	V1_DATA = 0x00
	V1_REQ  = 0x40
	V1_ACK  = 0x80
	V1_NACK = 0xC0
)

type IpRef struct {
	IP  IP
	Ref rff.Ref
}

func (ipref IpRef) String() string {
	return ipref.IP.String() + " + " + ipref.Ref.String()
}

type AddrRec struct {
	EA  IP
	IP  IP
	GW  IP
	Ref rff.Ref
}

func AddrRecEncodedLen(ea_iplen, gw_iplen int) int {
	return ea_iplen * 2 + gw_iplen + 16 // ea + ip + gw + ref.h + ref.l
}

func AddrRecSlices(ea_iplen, gw_iplen int, arec []byte) (ea, ip, gw, refh, refl []byte) {
	i := 0
	ea = arec[i : i + ea_iplen]
	i += ea_iplen
	ip = arec[i : i + ea_iplen]
	i += ea_iplen
	gw = arec[i : i + gw_iplen]
	i += gw_iplen
	refh = arec[i : i + 8]
	i += 8
	refl = arec[i : i + 8]
	return
}

func (arec AddrRec) Encode(arecb []byte) {
	if arec.EA.Len() != arec.IP.Len() {
		panic("unexpected")
	}
	eab, ipb, gwb, refhb, reflb := AddrRecSlices(arec.EA.Len(), arec.GW.Len(), arecb)
	copy(eab, arec.EA.AsSlice())
	copy(ipb, arec.IP.AsSlice())
	copy(gwb, arec.GW.AsSlice())
	be.PutUint64(refhb, arec.Ref.H)
	be.PutUint64(reflb, arec.Ref.L)
}

func (arec AddrRec) EncodedLen() int {
	if arec.EA.Len() != arec.IP.Len() {
		panic("unexpected")
	}
	return AddrRecEncodedLen(arec.EA.Len(), arec.GW.Len())
}

func AddrRecDecode(ea_iplen, gw_iplen int, arecb []byte) (arec AddrRec) {
	eab, ipb, gwb, refhb, reflb := AddrRecSlices(ea_iplen, gw_iplen, arecb)
	arec.EA = IPFromSlice(eab)
	arec.IP = IPFromSlice(ipb)
	arec.GW = IPFromSlice(gwb)
	arec.Ref.H = be.Uint64(refhb)
	arec.Ref.L = be.Uint64(reflb)
	return
}
