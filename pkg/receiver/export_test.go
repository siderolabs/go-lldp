// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package receiver

import "net"

// SetMulticastAddressForTest allows a kernel-rejected address to exercise partial
// membership cleanup without replacing any socket operations. Tests using it
// must not run concurrently with Listen and must call the returned restore.
func SetMulticastAddressForTest(index int, address net.HardwareAddr) func() {
	original := multicastAddresses[index]
	multicastAddresses[index] = address

	return func() { multicastAddresses[index] = original }
}
