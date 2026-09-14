// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package receiver provides a receive-only Linux LLDP Ethernet transport.
package receiver

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/packet"
	"golang.org/x/sys/unix"

	"github.com/siderolabs/go-lldp/pkg/lldp"
)

var multicastAddresses = [...]net.HardwareAddr{
	{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e},
	{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03},
	{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00},
}

// Receiver reads raw LLDP Ethernet frames from one interface.
// ReadFrame must not be called concurrently. Close and SetReadDeadline may
// be called concurrently with ReadFrame.
type Receiver struct {
	conn   *packet.Conn
	buffer []byte
}

// Listen opens a raw ETH_P_LLDP socket and joins all three LLDP multicast
// groups on iface. It requires CAP_NET_RAW. The interface must have a positive
// kernel index; a nil interface is rejected.
func Listen(iface *net.Interface) (*Receiver, error) {
	if iface == nil || iface.Index <= 0 {
		return nil, errors.New("invalid LLDP interface")
	}

	conn, err := packet.Listen(iface, packet.Raw, int(lldp.EtherType), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open LLDP packet socket: %w", err)
	}

	if err = joinMulticastGroups(conn, iface.Index); err != nil {
		conn.Close() //nolint:errcheck

		return nil, err
	}

	return &Receiver{conn: conn, buffer: make([]byte, 65536)}, nil
}

func joinMulticastGroups(conn *packet.Conn, ifIndex int) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to access LLDP packet socket: %w", err)
	}

	var membershipErr error

	if err = rawConn.Control(func(fd uintptr) {
		for _, address := range multicastAddresses {
			request := unix.PacketMreq{
				Ifindex: int32(ifIndex),
				Type:    unix.PACKET_MR_MULTICAST,
				Alen:    uint16(len(address)),
			}
			copy(request.Address[:], address)

			if membershipErr = unix.SetsockoptPacketMreq(int(fd), unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &request); membershipErr != nil {
				return
			}
		}
	}); err != nil {
		return fmt.Errorf("failed to control LLDP packet socket: %w", err)
	}

	if membershipErr != nil {
		return fmt.Errorf("failed to join LLDP multicast group: %w", membershipErr)
	}

	return nil
}

// SetReadDeadline sets the read deadline. A zero value clears the deadline.
func (receiver *Receiver) SetReadDeadline(deadline time.Time) error {
	return receiver.conn.SetReadDeadline(deadline)
}

// ReadFrame returns a complete raw Ethernet frame, including its header.
// The returned slice is borrowed and valid only until the next ReadFrame call;
// callers retaining a frame must copy it. It is not safe for concurrent reads.
func (receiver *Receiver) ReadFrame() ([]byte, error) {
	n, _, err := receiver.conn.ReadFrom(receiver.buffer)
	if err != nil {
		return nil, err
	}

	return receiver.buffer[:n], nil
}

// Close closes the socket, releases multicast memberships and unblocks reads.
// It returns the underlying socket's error, including on repeated calls.
func (receiver *Receiver) Close() error {
	return receiver.conn.Close()
}
