// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package receiver_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/packet"
	"github.com/stretchr/testify/suite"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/siderolabs/go-lldp/pkg/lldp"
	"github.com/siderolabs/go-lldp/pkg/receiver"
)

func TestInvalidInterface(t *testing.T) {
	for _, iface := range []*net.Interface{nil, {Index: -1}, {Index: 0}, {Index: 1<<31 - 1}} {
		conn, err := receiver.Listen(iface)
		if conn != nil {
			conn.Close() //nolint:errcheck
			t.Fatal("invalid interface returned a receiver")
		}

		if err == nil {
			t.Fatal("invalid interface accepted")
		}
	}
}

type receiverSuite struct {
	suite.Suite

	iface *net.Interface
	peer  *net.Interface
}

func TestReceiver(t *testing.T) {
	suite.Run(t, new(receiverSuite))
}

func (suite *receiverSuite) SetupTest() {
	suite.iface, suite.peer = vethPair(suite.T())
}

func vethPair(t *testing.T) (*net.Interface, *net.Interface) {
	t.Helper()

	suffix := rand.Text()[:8]

	pair := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "lldpr" + suffix},
		PeerName:  "lldpt" + suffix,
	}
	if err := netlink.LinkAdd(pair); err != nil {
		if errors.Is(err, unix.EPERM) && os.Geteuid() != 0 {
			t.Skip("veth tests require CAP_NET_ADMIN and CAP_NET_RAW")
		}

		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := netlink.LinkDel(pair); err != nil {
			t.Errorf("delete test veth pair: %v", err)
		}
	})

	var ifaces [2]*net.Interface

	for i, name := range []string{pair.Name, pair.PeerName} {
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}

		if err = netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}

		ifaces[i], err = net.InterfaceByIndex(link.Attrs().Index)
		if err != nil {
			t.Fatal(err)
		}
	}

	pair.Index = ifaces[0].Index

	return ifaces[0], ifaces[1]
}

func (suite *receiverSuite) TestMemberships() {
	// Another interface's memberships must not affect these assertions.
	listen(suite.T(), suite.peer)

	before := memberships(suite.T(), suite.iface)
	if before != "" {
		suite.T().Fatalf("membership lookup included another interface or protocol: %s", before)
	}

	conn := listen(suite.T(), suite.iface)

	joined := memberships(suite.T(), suite.iface)
	for _, address := range []string{"0180c200000e", "0180c2000003", "0180c2000000"} {
		if !strings.Contains(joined, address) {
			suite.T().Errorf("missing membership %s: %s", address, joined)
		}
	}

	if err := conn.Close(); err != nil {
		suite.T().Fatal(err)
	}

	if after := memberships(suite.T(), suite.iface); after != before {
		suite.T().Fatalf("Close left memberships behind: before=%q after=%q", before, after)
	}
}

func (suite *receiverSuite) TestPartialJoinFailure() {
	before := memberships(suite.T(), suite.iface)
	sockets := receiverSockets(suite.T(), suite.iface)

	// Opening a receiver on another interface must not look like a leaked socket.
	listen(suite.T(), suite.peer)

	// A seven-byte address fails in the kernel after the first valid join.
	suite.T().Cleanup(receiver.SetMulticastAddressForTest(1, net.HardwareAddr{1, 0x80, 0xc2, 0, 0, 3, 0}))

	conn, err := receiver.Listen(suite.iface)
	if conn != nil {
		conn.Close() //nolint:errcheck
		suite.T().Fatal("partial join returned a receiver")
	}

	if !errors.Is(err, unix.EINVAL) {
		suite.T().Fatalf("expected kernel membership EINVAL, got %v", err)
	}

	if after := memberships(suite.T(), suite.iface); after != before {
		suite.T().Errorf("partial join leaked membership: %q", after)
	}

	if remaining := receiverSockets(suite.T(), suite.iface); remaining != sockets {
		suite.T().Errorf("partial join leaked a receiver socket on %s: before=%d after=%d", suite.iface.Name, sockets, remaining)
	}
}

func (suite *receiverSuite) TestFramesAndFilter() {
	conn := listen(suite.T(), suite.iface)

	sender, err := packet.Listen(suite.peer, packet.Raw, unix.ETH_P_ALL, nil)
	if err != nil {
		suite.T().Fatal(err)
	}
	defer sender.Close() //nolint:errcheck

	var previous []byte

	for _, suffix := range []byte{0x0e, 0x03, 0x00} {
		frame := ethernet.Frame{
			Destination: net.HardwareAddr{1, 0x80, 0xc2, 0, 0, suffix},
			Source:      net.HardwareAddr{2, 0, 0, 0, 0, 1},
			EtherType:   lldp.EtherType,
			// Mandatory chassis MAC, port name, TTL, end TLVs.
			Payload: []byte{2, 7, 4, 2, 0, 0, 0, 0, 1, 4, 3, 5, 'e', suffix, 6, 2, 0, 120, 0, 0},
		}
		wrong := frame
		wrong.EtherType = 0x88b5
		send(suite.T(), sender, &wrong)

		want := send(suite.T(), sender, &frame)
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			suite.T().Fatal(err)
		}

		got, err := conn.ReadFrame()
		if err != nil {
			suite.T().Fatal(err)
		}

		if !bytes.Equal(got, want) {
			suite.T().Fatalf("raw frame/filter mismatch: got %x want %x", got, want)
		}

		var eth ethernet.Frame
		if err := eth.UnmarshalBinary(got); err != nil {
			suite.T().Fatal(err)
		}

		var decoded lldp.Frame
		if err := decoded.UnmarshalBinary(eth.Payload); err != nil || decoded.TTL != 120*time.Second {
			suite.T().Fatalf("LLDP decode: %v, %+v", err, decoded)
		}

		if previous != nil && (&previous[0] != &got[0] || !bytes.Equal(previous, got)) {
			suite.T().Fatal("ReadFrame did not reuse its borrowed buffer")
		}

		previous = got
	}
}

func (suite *receiverSuite) TestDeadlineAndClose() {
	conn := listen(suite.T(), suite.iface)
	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		suite.T().Fatal(err)
	}

	if _, err := conn.ReadFrame(); !errors.Is(err, os.ErrDeadlineExceeded) {
		suite.T().Fatalf("expired deadline: %v", err)
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		suite.T().Fatal(err)
	}

	sender, err := packet.Listen(suite.peer, packet.Raw, unix.ETH_P_ALL, nil)
	if err != nil {
		suite.T().Fatal(err)
	}
	defer sender.Close() //nolint:errcheck

	want := send(suite.T(), sender, &ethernet.Frame{
		Destination: net.HardwareAddr{1, 0x80, 0xc2, 0, 0, 0x0e},
		Source:      net.HardwareAddr{2, 0, 0, 0, 0, 1},
		EtherType:   lldp.EtherType,
		Payload:     []byte{2, 7, 4, 2, 0, 0, 0, 0, 1, 4, 3, 5, 'e', '0', 6, 2, 0, 120, 0, 0},
	})
	if got, err := conn.ReadFrame(); err != nil || !bytes.Equal(got, want) {
		suite.T().Fatalf("read after deadline clear: %x, %v", got, err)
	}

	started := make(chan struct{})
	result := make(chan error, 1)

	go func() {
		close(started)

		_, err := conn.ReadFrame()
		result <- err
	}()

	<-started
	// The public API cannot acknowledge entry into the kernel read. This
	// covers both an already blocked read and a read racing with Close.
	if err := conn.Close(); err != nil {
		suite.T().Fatal(err)
	}

	select {
	case err := <-result:
		var opErr *net.OpError

		if !errors.As(err, &opErr) || opErr.Op != "read" || opErr.Timeout() {
			suite.T().Fatalf("read after deadline clear and Close: expected a non-timeout read error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		suite.T().Fatal("Close did not unblock ReadFrame")
	}
}

func listen(t *testing.T, iface *net.Interface) *receiver.Receiver {
	t.Helper()

	conn, err := receiver.Listen(iface)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := conn.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Errorf("cleanup receiver: %v", err)
		}
	})

	return conn
}

func memberships(t *testing.T, iface *net.Interface) string {
	t.Helper()

	data, err := os.ReadFile("/proc/net/dev_mcast")
	if err != nil {
		t.Fatal(err)
	}

	var rows []string

	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != strconv.Itoa(iface.Index) {
			continue
		}

		// IPv6 may join its own groups asynchronously when the veth comes up.
		switch fields[4] {
		case "0180c200000e", "0180c2000003", "0180c2000000":
			rows = append(rows, line)
		}
	}

	return strings.Join(rows, "\n")
}

func receiverSockets(t *testing.T, iface *net.Interface) int {
	t.Helper()

	data, err := os.ReadFile("/proc/net/packet")
	if err != nil {
		t.Fatal(err)
	}

	var count int

	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		// Columns are socket, references, type, protocol, interface, ...
		if len(fields) > 4 && fields[3] == "88cc" && fields[4] == strconv.Itoa(iface.Index) {
			count++
		}
	}

	return count
}

func send(t *testing.T, sender *packet.Conn, frame *ethernet.Frame) []byte {
	t.Helper()

	data, err := frame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sender.WriteTo(data, &packet.Addr{HardwareAddr: frame.Destination}); err != nil {
		t.Fatal(err)
	}

	return data
}
