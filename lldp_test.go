package lldp_test

import (
	"bytes"
	"errors"
	"io"
	"math"
	"testing"
	"time"

	"github.com/siderolabs/go-lldp"
)

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
