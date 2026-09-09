// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package lldp

import (
	"io"
)

// A ChassisIDSubtype is a value used to indicate the type of content
// carried in a ChassisID.
type ChassisIDSubtype uint8

// List of valid ChassisIDSubtype values.
const (
	ChassisIDSubtypeReserved         ChassisIDSubtype = 0
	ChassisIDSubtypeChassisComponent ChassisIDSubtype = 1
	ChassisIDSubtypeInterfaceAlias   ChassisIDSubtype = 2
	ChassisIDSubtypePortComponent    ChassisIDSubtype = 3
	ChassisIDSubtypeMACAddress       ChassisIDSubtype = 4
	ChassisIDSubtypeNetworkAddress   ChassisIDSubtype = 5
	ChassisIDSubtypeInterfaceName    ChassisIDSubtype = 6
	ChassisIDSubtypeLocallyAssigned  ChassisIDSubtype = 7
)

// A ChassisID is a structure parsed from a chassis ID TLV.  It contains
// information which identifies a particular chassis on a given network.
//
//nolint:govet // Preserve exported field order for unkeyed composite literals.
type ChassisID struct {
	// Subtype specifies the type of identification carried in this ChassisID.
	Subtype ChassisIDSubtype

	// ID specifies raw bytes containing identification information for
	// this ChassisID.
	//
	// ID may carry alphanumeric data or binary data, depending upon the
	// value of Subtype.
	ID []byte
}

// MarshalBinary allocates a byte slice and marshals a ChassisID into binary
// form.
//
// MarshalBinary never returns an error.
func (c *ChassisID) MarshalBinary() ([]byte, error) {
	return marshalID(byte(c.Subtype), c.ID), nil
}

// UnmarshalBinary unmarshals a byte slice into a ChassisID.
//
// If the byte slice does not contain enough data to unmarshal a valid
// ChassisID, io.ErrUnexpectedEOF is returned.
func (c *ChassisID) UnmarshalBinary(b []byte) error {
	subtype, id, err := unmarshalID(b)
	if err != nil {
		return err
	}

	c.Subtype = ChassisIDSubtype(subtype)
	c.ID = id

	return nil
}

// marshalID encodes the subtype byte and ID shared by chassis and port ID TLVs.
func marshalID(subtype byte, id []byte) []byte {
	b := make([]byte, 1+len(id))
	b[0] = subtype
	copy(b[1:], id)

	return b
}

// unmarshalID decodes a subtype byte and copies the remaining ID bytes.
func unmarshalID(b []byte) (byte, []byte, error) {
	if len(b) < 1 {
		return 0, nil, io.ErrUnexpectedEOF
	}

	id := make([]byte, len(b[1:]))
	copy(id, b[1:])

	return b[0], id, nil
}
