// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package lldp_test

import (
	"bytes"
	"encoding"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/siderolabs/go-lldp/pkg/lldp"
)

func TestChassisIDMarshalBinary(t *testing.T) {
	testIDMarshalBinary(t, newChassisID, byte(lldp.ChassisIDSubtypeMACAddress))
}

func TestChassisIDUnmarshalBinary(t *testing.T) {
	testIDUnmarshalBinary(t, newChassisID, byte(lldp.ChassisIDSubtypeMACAddress))
}

func newChassisID(subtype byte, id []byte) binaryID {
	return &lldp.ChassisID{Subtype: lldp.ChassisIDSubtype(subtype), ID: id}
}

type binaryID interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

func testIDMarshalBinary(t *testing.T, newID func(byte, []byte) binaryID, macSubtype byte) {
	t.Helper()

	tests := []struct {
		desc string
		id   binaryID
		b    []byte
	}{
		{desc: "empty ID", id: newID(0, nil), b: []byte{0}},
		{desc: "reserved, no ID", id: newID(0, []byte{}), b: []byte{0}},
		{
			desc: "MAC address",
			id:   newID(macSubtype, []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad}),
			b:    []byte{macSubtype, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			b, err := tt.id.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(tt.b, b) {
				t.Fatalf("unexpected ID bytes:\n- want: %v\n-  got: %v", tt.b, b)
			}
		})
	}
}

func testIDUnmarshalBinary(t *testing.T, newID func(byte, []byte) binaryID, macSubtype byte) {
	t.Helper()

	tests := []struct {
		id   binaryID
		err  error
		desc string
		b    []byte
	}{
		{desc: "nil buffer", err: io.ErrUnexpectedEOF},
		{desc: "reserved, no ID", b: []byte{0}, id: newID(0, []byte{})},
		{
			desc: "MAC address",
			b:    []byte{macSubtype, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
			id:   newID(macSubtype, []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			id := newID(0, nil)

			err := id.UnmarshalBinary(tt.b)
			if !errors.Is(err, tt.err) {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", tt.err, err)
			}

			if err != nil {
				return
			}

			if !reflect.DeepEqual(tt.id, id) {
				t.Fatalf("unexpected ID:\n- want: %v\n-  got: %v", tt.id, id)
			}

			b, err := id.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(tt.b, b) {
				t.Fatalf("unexpected round-trip bytes:\n- want: %v\n-  got: %v", tt.b, b)
			}
		})
	}
}
