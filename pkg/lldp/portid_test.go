// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package lldp_test

import (
	"testing"

	"github.com/siderolabs/go-lldp/pkg/lldp"
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
