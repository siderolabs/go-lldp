// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package lldp_test

import (
	"bytes"
	"errors"
	"io"
	"math"
	"testing"
	"time"

	"github.com/siderolabs/go-lldp/pkg/lldp"
)

func TestFrameUnmarshalBinaryPadding(t *testing.T) {
	// A minimum Ethernet frame is 60 bytes without the FCS: a 14-byte
	// Ethernet header followed by a 46-byte payload (LLDPDU plus padding).
	mandatory := []byte{
		0x02, 0x07, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // Chassis ID
		0x04, 0x05, 0x05, 'e', 't', 'h', '0', // Port ID
		0x06, 0x02, 0x00, 0x78, // TTL
	}

	for _, tt := range []struct {
		name     string
		optional []byte
		padding  []byte
	}{
		{name: "even zero padding", padding: make([]byte, 24)},
		{name: "odd zero padding", optional: []byte{0x0a, 0x01, 'x'}, padding: make([]byte, 21)},
		{name: "nonzero padding", padding: bytes.Repeat([]byte{0xff}, 24)},
		// Padding that looks like an optional TLV and another End must also
		// be ignored: the first End terminates the LLDPDU.
		{name: "parseable padding", padding: append([]byte{0x0a, 0x02, 'n', 'o'}, make([]byte, 20)...)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			payload := append([]byte(nil), mandatory...)
			payload = append(payload, tt.optional...)
			payload = append(payload, 0, 0)
			payload = append(payload, tt.padding...)

			if len(payload) != 46 {
				t.Fatalf("invalid Ethernet payload size: %d", len(payload))
			}

			var f lldp.Frame
			if err := f.UnmarshalBinary(payload); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(f.ChassisID.ID, mandatory[3:9]) || !bytes.Equal(f.PortID.ID, []byte("eth0")) || f.TTL != 120*time.Second {
				t.Fatalf("unexpected mandatory TLVs: %+v", f)
			}

			wantOptional := 0
			if len(tt.optional) != 0 {
				wantOptional = 1
			}

			if len(f.Optional) != wantOptional {
				t.Fatalf("optional TLVs: got %d, want %d (End and padding must be excluded)", len(f.Optional), wantOptional)
			}

			if wantOptional == 1 && (f.Optional[0].Type != lldp.TLVTypeSystemName || f.Optional[0].Length != 1 || !bytes.Equal(f.Optional[0].Value, []byte("x"))) {
				t.Fatalf("unexpected optional TLV: %+v", f.Optional[0])
			}
		})
	}

	for _, tt := range []struct {
		name   string
		suffix []byte
	}{
		{name: "missing End"},
		{name: "nonempty End", suffix: []byte{0x00, 0x01, 0xff}},
		{name: "nonempty End before valid End", suffix: []byte{0x00, 0x01, 0xff, 0x00, 0x00}},
		{name: "truncated header before End", suffix: []byte{0x0a}},
		{name: "truncated value before End", suffix: []byte{0x0a, 0x04, 'x', 0x00, 0x00}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			payload := append([]byte(nil), mandatory...)
			payload = append(payload, tt.suffix...)

			var f lldp.Frame
			if err := f.UnmarshalBinary(payload); err == nil {
				t.Fatal("expected malformed LLDPDU to be rejected")
			}
		})
	}
}

func TestFrameMarshalBinary(t *testing.T) {
	tests := []struct {
		err  error
		f    *lldp.Frame
		desc string
		b    []byte
	}{
		{
			desc: "ChassisID nil",
			f:    &lldp.Frame{},
			err:  lldp.ErrInvalidFrame,
		},
		{
			desc: "PortID nil",
			f: &lldp.Frame{
				ChassisID: &lldp.ChassisID{},
			},
			err: lldp.ErrInvalidFrame,
		},
		{
			desc: "TTL too large",
			f: &lldp.Frame{
				ChassisID: &lldp.ChassisID{},
				PortID:    &lldp.PortID{},
				TTL:       (math.MaxUint16 + 1) * time.Second,
			},
			err: lldp.ErrInvalidFrame,
		},
		{
			desc: "too much data in ChassisID",
			f: &lldp.Frame{
				ChassisID: &lldp.ChassisID{
					ID: make([]byte, lldp.TLVLengthMax+1),
				},
				PortID: &lldp.PortID{},
			},
			err: lldp.ErrInvalidTLV,
		},
		{
			desc: "too much data in PortID",
			f: &lldp.Frame{
				ChassisID: &lldp.ChassisID{},
				PortID: &lldp.PortID{
					ID: make([]byte, lldp.TLVLengthMax+1),
				},
			},
			err: lldp.ErrInvalidTLV,
		},
		{
			desc: "length mismatch in optional TLV",
			f: &lldp.Frame{
				ChassisID: &lldp.ChassisID{},
				PortID:    &lldp.PortID{},
				Optional: []*lldp.TLV{
					{
						Type:   0,
						Length: 2,
						Value:  []byte{1},
					},
				},
			},
			err: lldp.ErrInvalidTLV,
		},
		{
			desc: "OK",
			f: &lldp.Frame{
				ChassisID: &lldp.ChassisID{
					Subtype: 1,
					ID:      []byte("foo"),
				},
				PortID: &lldp.PortID{
					Subtype: 1,
					ID:      []byte("bar"),
				},
				TTL: 255 * time.Second,
			},
			b: []byte{
				0x02, 0x04, 1, 'f', 'o', 'o',
				0x04, 0x04, 1, 'b', 'a', 'r',
				0x06, 0x02, 0, 255,
				0, 0,
			},
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		b, err := tt.f.MarshalBinary()
		if err != nil {
			if want, got := tt.err, err; !errors.Is(got, want) {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
			}

			continue
		}

		if want, got := tt.b, b; !bytes.Equal(want, got) {
			t.Fatalf("unexpected Frame bytes:\n- want: %v\n-  got: %v", want, got)
		}
	}
}

func TestFrameUnmarshalBinary(t *testing.T) {
	tests := []struct {
		err  error
		f    *lldp.Frame
		desc string
		b    []byte
	}{
		{
			desc: "nil buffer",
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "short buffer",
			b:    []byte{0},
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "first TLV with incorrect length field",
			b:    []byte{0x02, 0xff},
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "second TLV with incorrect length field",
			b: []byte{
				0x02, 0x00,
				0x02, 0xff,
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			desc: "first TLV not chassis ID type",
			b: []byte{
				0x04, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
			},
			err: lldp.ErrInvalidFrame,
		},
		{
			desc: "second TLV not port ID type",
			b: []byte{
				0x02, 0x01, 0x00,
				0x02, 0x00,
				0x00, 0x00,
				0x00, 0x00,
			},
			err: lldp.ErrInvalidFrame,
		},
		{
			desc: "third TLV not TTL type",
			b: []byte{
				0x02, 0x01, 0x00,
				0x04, 0x01, 0x00,
				0x04, 0x00,
				0x00, 0x00,
			},
			err: lldp.ErrInvalidFrame,
		},
		{
			desc: "third TLV is TTL type but not uint16",
			b: []byte{
				0x02, 0x01, 0x00,
				0x04, 0x01, 0x00,
				0x06, 0x01, 0x00,
				0x00, 0x00,
			},
			err: lldp.ErrInvalidFrame,
		},
		{
			desc: "fourth TLV is not end of LLDPDU type",
			b: []byte{
				0x02, 0x01, 0x00,
				0x04, 0x01, 0x00,
				0x06, 0x02, 0x00, 0x00,
				0x02, 0x00,
			},
			err: lldp.ErrInvalidFrame,
		},
		{
			desc: "fourth TLV is end of LLDPDU type, but not length zero",
			b: []byte{
				0x02, 0x01, 0x00,
				0x04, 0x01, 0x00,
				0x06, 0x02, 0x00, 0x00,
				0x00, 0x01, 0x00,
			},
			err: lldp.ErrInvalidFrame,
		},
		{
			desc: "OK Frame, no optional TLVs",
			b: []byte{
				0x02, 0x05, 6, 'e', 't', 'h', '0',
				0x04, 0x05, 4, 'e', 't', 'h', '1',
				0x06, 0x02, 0x00, 0xff,
				0x00, 0x00,
			},
			f: &lldp.Frame{
				ChassisID: &lldp.ChassisID{
					Subtype: 6,
					ID:      []byte("eth0"),
				},
				PortID: &lldp.PortID{
					Subtype: 4,
					ID:      []byte("eth1"),
				},
				TTL: 255 * time.Second,
			},
		},
		{
			desc: "OK Frame, two optional TLVs",
			b: []byte{
				0x02, 0x05, 6, 'e', 't', 'h', '0',
				0x04, 0x05, 4, 'e', 't', 'h', '1',
				0x06, 0x02, 0x00, 0xff,
				0x08, 0x01, 1,
				0x0a, 0x02, 1, 2,
				0x00, 0x00,
			},
			f: &lldp.Frame{
				ChassisID: &lldp.ChassisID{
					Subtype: 6,
					ID:      []byte("eth0"),
				},
				PortID: &lldp.PortID{
					Subtype: 4,
					ID:      []byte("eth1"),
				},
				TTL: 255 * time.Second,
			},
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		f := new(lldp.Frame)
		if err := f.UnmarshalBinary(tt.b); err != nil {
			if want, got := tt.err, err; !errors.Is(got, want) {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
			}

			continue
		}

		fb, err := f.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		if want, got := tt.b, fb; !bytes.Equal(want, got) {
			t.Fatalf("unexpected Frame bytes:\n- want: %v\n-  got: %v", want, got)
		}
	}
}
