// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package lldp_test

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/siderolabs/go-lldp/pkg/lldp"
)

func TestTLVMarshalBinary(t *testing.T) {
	tests := []struct {
		err  error
		tlv  *lldp.TLV
		desc string
		b    []byte
	}{
		{
			desc: "type too large",
			tlv: &lldp.TLV{
				Type: lldp.TLVTypeMax + 1,
			},
			err: lldp.ErrInvalidTLV,
		},
		{
			desc: "length too large",
			tlv: &lldp.TLV{
				Length: lldp.TLVLengthMax + 1,
			},
			err: lldp.ErrInvalidTLV,
		},
		{
			desc: "length and value length mismatch",
			tlv: &lldp.TLV{
				Length: 1,
				Value:  []byte{1, 2},
			},
			err: lldp.ErrInvalidTLV,
		},
		{
			desc: "TLV type 1, length 1, value 255",
			tlv: &lldp.TLV{
				Type:   1,
				Length: 1,
				Value:  []byte{0xff},
			},
			b: []byte{0x02, 0x01, 0xff},
		},
		{
			desc: "TLV type 127, length 511, all zero value",
			tlv: &lldp.TLV{
				Type:   lldp.TLVTypeMax,
				Length: lldp.TLVLengthMax,
				Value:  make([]byte, lldp.TLVLengthMax),
			},
			b: append([]byte{0xff, 0xff}, make([]byte, lldp.TLVLengthMax)...),
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		b, err := tt.tlv.MarshalBinary()
		if err != nil {
			if want, got := tt.err, err; !errors.Is(got, want) {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
			}

			continue
		}

		if want, got := tt.b, b; !bytes.Equal(want, got) {
			t.Fatalf("unexpected TLV bytes:\n- want: %v\n-  got: %v", want, got)
		}
	}
}

func TestTLVUnmarshalBinary(t *testing.T) {
	tests := []struct {
		err  error
		tlv  *lldp.TLV
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
			desc: "TLV with incorrect length field",
			b:    []byte{0x02, 0xff},
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "TLV type 1, length 1, value 255",
			b:    []byte{0x02, 0x01, 0xff},
			tlv: &lldp.TLV{
				Type:   1,
				Length: 1,
				Value:  []byte{0xff},
			},
		},
		{
			desc: "TLV type 0, length 0, trailing bytes",
			b:    []byte{0x00, 0x00, 0xff},
			tlv: &lldp.TLV{
				Type:   0,
				Length: 0,
				Value:  []byte{},
			},
		},
		{
			desc: "TLV type 127, length 511, all zero value",
			b:    append([]byte{0xff, 0xff}, make([]byte, lldp.TLVLengthMax)...),
			tlv: &lldp.TLV{
				Type:   lldp.TLVTypeMax,
				Length: lldp.TLVLengthMax,
				Value:  make([]byte, lldp.TLVLengthMax),
			},
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		tlv := new(lldp.TLV)
		if err := tlv.UnmarshalBinary(tt.b); err != nil {
			if want, got := tt.err, err; !errors.Is(got, want) {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
			}

			continue
		}

		if want, got := tt.tlv, tlv; !reflect.DeepEqual(want, got) {
			t.Fatalf("unexpected TLV:\n- want: %v\n-  got: %v", want, got)
		}
	}
}
