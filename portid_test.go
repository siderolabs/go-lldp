package lldp_test

import (
	"testing"

	"github.com/siderolabs/go-lldp"
)

func TestPortIDMarshalBinary(t *testing.T) {
	testIDMarshalBinary(t, newPortID, byte(lldp.PortIDSubtypeMACAddress))
}

func TestPortIDUnmarshalBinary(t *testing.T) {
	testIDUnmarshalBinary(t, newPortID, byte(lldp.PortIDSubtypeMACAddress))
}

func newPortID(subtype byte, id []byte) binaryID {
	return &lldp.PortID{Subtype: lldp.PortIDSubtype(subtype), ID: id}
}
