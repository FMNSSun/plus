package packet

import "errors"
import "fmt"
import "encoding/binary"

// Utility functions to read/create/write PLUS
// packets.

// A PLUSPacket
//
// Basically just a wrapper around a []byte
//
// See the plus-spec draft for more. Or ask brian :D.
type PLUSPacket struct {
	header  []byte
	payload []byte
}

// BASIC_HEADER_LEN is the length of the basic header.
// If a packet is not at least BASIC_HEADER_LEN bytes long
// it doesn't even have a complete basic header
const BASIC_HEADER_LEN uint16 = 20

// IT's MAGIC!
const MAGIC uint32 = 0xd8007ff

const PCF_INTEGRITY_ZERO uint8 = 0
const PCF_INTEGRITY_QUARTER uint8 = 1
const PCF_INTEGRITY_HALF uint8 = 2
const PCF_INTEGRITY_FULL uint8 = 3

const PCF_TYPE_HOP_COUNT uint16 = 0x0001

// Returns value of the L flag
func (plusPacket *PLUSPacket) LFlag() bool {
	return toBool((plusPacket.header[3] >> 3) & 0x01)
}

// Returns value of the R flag
func (plusPacket *PLUSPacket) RFlag() bool {
	return toBool((plusPacket.header[3] >> 2) & 0x01)
}

// Returns value of the S flag
func (plusPacket *PLUSPacket) SFlag() bool {
	return toBool((plusPacket.header[3] >> 1) & 0x01)
}

// Returns value of the X flag
func (plusPacket *PLUSPacket) XFlag() bool {
	return toBool((plusPacket.header[3] >> 0) & 0x01)
}

// Sets the L flag to v
func (plusPacket *PLUSPacket) SetLFlag(v bool) {
	plusPacket.header[3] |= toByte(v) << 3
}

// Sets the R flag to v
func (plusPacket *PLUSPacket) SetRFlag(v bool) {
	plusPacket.header[3] |= toByte(v) << 2
}

// Sets the S flag to v
func (plusPacket *PLUSPacket) SetSFlag(v bool) {
	plusPacket.header[3] |= toByte(v) << 1
}

// Sets the X flag to v
func (plusPacket *PLUSPacket) setXFlag(v bool) {
	plusPacket.header[3] |= toByte(v)
}

// Returns the CAT
func (plusPacket *PLUSPacket) CAT() uint64 {
	return binary.BigEndian.Uint64(plusPacket.header[4:])
}

// Returns the PSN
func (plusPacket *PLUSPacket) PSN() uint32 {
	return binary.BigEndian.Uint32(plusPacket.header[12:])
}

// Returns the PSE
func (plusPacket *PLUSPacket) PSE() uint32 {
	return binary.BigEndian.Uint32(plusPacket.header[16:])
}

// Sets the CAT
func (plusPacket *PLUSPacket) SetCAT(cat uint64) {
	binary.BigEndian.PutUint64(plusPacket.header[4:], cat)
}

// Sets the PSN
func (plusPacket *PLUSPacket) SetPSN(psn uint32) {
	binary.BigEndian.PutUint32(plusPacket.header[12:], psn)
}

// Sets the PSE
func (plusPacket *PLUSPacket) SetPSE(pse uint32) {
	binary.BigEndian.PutUint32(plusPacket.header[16:], pse)
}

// Returns the payload
func (plusPacket *PLUSPacket) Payload() []byte {
	return plusPacket.payload
}

// Sets the payload
func (plusPacket *PLUSPacket) SetPayload(payload []byte) {
	plusPacket.payload = payload
}

// Returns the PCF Type. If there's an additional PCF Type byte
// present (due to PCF type being 0x00) then that value is
// shifted right by 8 bits. Thus PCF Type 0x0012 is returned
// as 0x1200 and PCF Type 0x12 is returned as 0x12.
func (plusPacket *PLUSPacket) PCFType() (uint16, error) {
	// If it's not an extended header then
	// we have no PCF Type
	if !plusPacket.XFlag() {
		return 0, errors.New("No PCF Type present in basic header.")
	}

	// PCF Type = 0x00 means additional byte
	if plusPacket.header[20] == 0x00 {
		return uint16(plusPacket.header[21]) << 8, nil
	}

	return uint16(plusPacket.header[20]), nil
}

func (plusPacket *PLUSPacket) PCFTypeUnsafe() uint16 {
	t, _ := plusPacket.PCFType()
	return t
}

func (plusPacket *PLUSPacket) PCFIntegrityUnsafe() uint8 {
	t, _ := plusPacket.PCFIntegrity()
	return t
}

func (plusPacket *PLUSPacket) PCFValueUnsafe() []byte {
	t, _ := plusPacket.PCFValue()
	return t
}

func (plusPacket *PLUSPacket) PCFLenUnsafe() uint8 {
	t, _ := plusPacket.PCFLen()
	return t
}



// Returns the position of the PCF Len/PCF I byte in the
// packet buffer.
func (plusPacket *PLUSPacket) GetPCFLenIntegrityPos() (int, error) {
	// Basic header? No PCF Len/PCF I
	if !plusPacket.XFlag() {
		return 0, errors.New("No PCF Len/PCF Integrity present in basic header.")
	}

	// PCF type 0x00 -> additional PCF type byte causing PCF len to be at byte
	// 22
	if plusPacket.header[20] == 0x00 {
		return 22, nil
	}

	// PCF type 0xFF -> no PCF Len/PCF I
	if plusPacket.header[20] == 0xFF {
		return 0, errors.New("No PCF Len/PCF Integrity present due to PCF Type = 0xFF.")
	}

	// Regular position is 21 1 byte after PCF type
	return 21, nil
}

// Returns the PCF Len (6 bits)
func (plusPacket *PLUSPacket) PCFLen() (uint8, error) {
	// Basic header? Then no PCFLen
	if !plusPacket.XFlag() {
		return 0, errors.New("No PCF Len present in basic header.")
	}

	var value byte

	if plusPacket.header[20] == 0x00 { //2 byte PCF type

		value = plusPacket.header[22]

	} else if plusPacket.header[20] == 0xFF { //no PCF Len/PCF I

		return 0, errors.New("No PCF Len present due to PCF Type = 0xFF.")

	} else {

		value = plusPacket.header[21]

	}

	return uint8(value >> 2), nil //PCF Len is upper 6 bits
}

// Returns the PCF Integrity (2 bits)
func (plusPacket *PLUSPacket) PCFIntegrity() (uint8, error) {
	// Basic header? Then no PCFLen
	if !plusPacket.XFlag() {
		return 0, errors.New("No PCF Integrity present in basic header.")
	}

	var value byte

	if plusPacket.header[20] == 0x00 { //2 byte PCF type

		value = plusPacket.header[22]

	} else if plusPacket.header[20] == 0xFF { //no PCF Len/PCF I

		return 0, errors.New("No PCF Integrity present due to PCF Type = 0xFF")

	} else {

		value = plusPacket.header[21]

	}

	return uint8(value & 0x03), nil //PCF I is lower 2 bits
}

// Returns the PCF value. Should be used read-only, can be used
// write, but be cautious (PCF Len etc.)
func (plusPacket *PLUSPacket) PCFValue() ([]byte, error) {
	if !plusPacket.XFlag() {
		return nil, errors.New("No PCF Value present in basic header.")
	}

	pcfILenIndex := -1

	if plusPacket.header[20] == 0x00 { //2 byte PCF type as usual
		pcfILenIndex = 22
	} else if plusPacket.header[20] == 0xFF { //no PCF Len/PCF I as usual
		return nil, errors.New("No PCF Value due to PCF Type = 0xFF")
	} else {
		pcfILenIndex = 21
	}

	pcfLen := uint8(plusPacket.header[pcfILenIndex] >> 2)
	//pcfIntegrity := uint8(plusPacket.header[pcfILenIndex] & 0x03)

	return plusPacket.header[pcfILenIndex+1 : pcfILenIndex+1+int(pcfLen)], nil
}

// Returns the unprotected part of the PCF value. Should be used read-only, can be used
// write, but be cautious (PCF Len etc.)
func (plusPacket *PLUSPacket) PCFValueUnprotected() ([]byte, error) {
	if !plusPacket.XFlag() {
		return nil, errors.New("No PCF Value present in basic header.")
	}

	pcfILenIndex := -1

	if plusPacket.header[20] == 0x00 { //2 byte PCF type as usual
		pcfILenIndex = 22
	} else if plusPacket.header[20] == 0xFF { //no PCF Len/PCF I as usual
		return nil, errors.New("No PCF Value due to PCF Type = 0xFF")
	} else {
		pcfILenIndex = 21
	}

	pcfLen := uint8(plusPacket.header[pcfILenIndex] >> 2)
	pcfIntegrity := uint8(plusPacket.header[pcfILenIndex] & 0x03)

	offset := 0

	if pcfIntegrity == PCF_INTEGRITY_FULL {
		return nil, nil
	} else if pcfIntegrity == PCF_INTEGRITY_ZERO {
		offset = 0
	} else if pcfIntegrity == PCF_INTEGRITY_HALF {
		offset = int(pcfLen / 2)
	} else if pcfIntegrity == PCF_INTEGRITY_QUARTER {
		offset = int(pcfLen / 4)
	}

	return plusPacket.header[pcfILenIndex+1+offset : pcfILenIndex+1+int(pcfLen)], nil
}

// Returns the Header with unprotected fields zeroed out.
// Safe to modfify as it is a copy.
func (plusPacket *PLUSPacket) HeaderWithZeroes() []byte {
	headerCopy := make([]byte, len(plusPacket.header))
	copy(headerCopy, plusPacket.header)

	if !plusPacket.XFlag() {
		return headerCopy
	}

	pcfILenIndex := -1

	if plusPacket.header[20] == 0x00 { //2 byte PCF type as usual
		pcfILenIndex = 22
	} else if plusPacket.header[20] == 0xFF { //no PCF Len/PCF I as usual
		return headerCopy
	} else {
		pcfILenIndex = 21
	}

	pcfLen := uint8(plusPacket.header[pcfILenIndex] >> 2)
	pcfIntegrity := uint8(plusPacket.header[pcfILenIndex] & 0x03)

	pcfValueIndex := pcfILenIndex + 1

	pcfUnprotectedStartIndex := 0
	if pcfIntegrity == PCF_INTEGRITY_FULL {
		pcfUnprotectedStartIndex = 0
	} else if pcfIntegrity == PCF_INTEGRITY_ZERO {
		pcfUnprotectedStartIndex = int(pcfLen)
	} else if pcfIntegrity == PCF_INTEGRITY_HALF {
		pcfUnprotectedStartIndex = pcfValueIndex + int(pcfLen/2)
	} else if pcfIntegrity == PCF_INTEGRITY_QUARTER {
		pcfUnprotectedStartIndex = pcfValueIndex + int(pcfLen/4)
	}

	for i := pcfUnprotectedStartIndex; i < pcfValueIndex+int(pcfLen); i++ {
		headerCopy[i] = 0x00
	}

	return headerCopy
}

// Returns the size of the header
func (plusPacket *PLUSPacket) HeaderLen() uint16 {
	return ulen(plusPacket.header)
}

// Utility function for bool -> 0/1
func toByte(v bool) byte {
	if v {
		return 1
	} else {
		return 0
	}
}

// Utility function for 0/1 -> bool
func toBool(v byte) bool {
	if v == 0 {
		return false
	} else {
		return true
	}
}

// Utility function for len as uint16
func ulen(buffer []byte) uint16 {
	return uint16(len(buffer))
}

// Returns the header as raw bytes.
// Should be used read-only as it is not a copy.
func (plusPacket *PLUSPacket) Header() []byte {
	return plusPacket.header
}

// Returns the packet as raw bytes.
// You can modify it as it is a copy.
func (plusPacket *PLUSPacket) Buffer() []byte {
	buffer := make([]byte, len(plusPacket.payload)+len(plusPacket.header))
	copy(buffer, plusPacket.header)
	copy(buffer[len(plusPacket.header):], plusPacket.payload)
	return buffer
}

// Sets the buffer of this packet while performing a
// check whether the buffer contains a valid PLUS packet. You
// might prefer using the NewPLUSPacket function. Please be aware that
// this function will set PCF Integrity to zero if PCF Len is zero.
func (plusPacket *PLUSPacket) SetBuffer(buffer_ []byte) error {
	buffer := make([]byte, len(buffer_))
	copy(buffer, buffer_)

	if ulen(buffer) < BASIC_HEADER_LEN {
		return errors.New("buffer is too small")
	}

	xFlag := buffer[3] & 0x01

	magic := binary.BigEndian.Uint32(buffer)
	magic >>= 4

	if magic != MAGIC {
		return errors.New("The wizard is not happy with the magic.")
	}

	// If it's a basic header we're done
	if xFlag == 0 {
		plusPacket.header = buffer[:BASIC_HEADER_LEN]
		plusPacket.payload = buffer[BASIC_HEADER_LEN:]
		return nil
	}

	expectedLength := BASIC_HEADER_LEN

	// PCF type has to be present in all extended headers
	expectedLength += 1
	if ulen(buffer) < expectedLength {
		return errors.New("Buffer is too small. PCF Type missing.")
	}

	// If the PCF type is 0xFF there's another PCF type byte
	if buffer[20] == 0x00 {
		expectedLength += 1
	}

	if ulen(buffer) < expectedLength {
		return errors.New("Buffer is too small. Missing second byte for PCF type.")
	}

	// If PCF type is 0xFF it means no PCF Len and no PCF I
	if buffer[20] != 0xFF {
		// PCF type isn't 0xFF so there's one additional byte for PCF Len/PCF I
		expectedLength += 1

		if ulen(buffer) < expectedLength {
			return errors.New("Buffer is too small. Missing PCF Len/PCF I.")
		}

		// Position of the PCF Len/PCF I in the buffer
		pcfLenIPos := expectedLength - 1

		pcfLen := buffer[pcfLenIPos] >> 2
		pcfI := buffer[pcfLenIPos] & 0x03

		expectedLength += uint16(pcfLen)

		if ulen(buffer) < expectedLength {
			return errors.New("Buffer is too small. Missing or incomplete PCF Value.")
		}

		//If PCF Len is zero then the receiver must set PCF I to zero.
		if pcfLen == 0 {
			pcfI = 0
		}

		buffer[pcfLenIPos] = pcfLen<<2 | pcfI
	}

	plusPacket.header = buffer[:expectedLength]
	plusPacket.payload = buffer[expectedLength:]

	return nil
}

// Construct a plus packet from buffer.
// This will perform a check if this is a valid
// PLUS packet (in the correct wire format).
// The buffer will be copied.
func NewPLUSPacket(buffer []byte) (*PLUSPacket, error) {
	var plusPacket PLUSPacket
	err := plusPacket.SetBuffer(buffer)

	return &plusPacket, err
}

// Construct a new basic plus packet
//  (with basic header)
func NewBasicPLUSPacket(
	lFlag bool,
	rFlag bool,
	sFlag bool,
	cat uint64,
	psn uint32,
	pse uint32,
	payload []byte) *PLUSPacket {

	var plusPacket PLUSPacket

	plusPacket.header = make([]byte, BASIC_HEADER_LEN)

	binary.BigEndian.PutUint32(plusPacket.header, MAGIC<<4)

	plusPacket.SetLFlag(lFlag)
	plusPacket.SetRFlag(rFlag)
	plusPacket.SetSFlag(sFlag)
	plusPacket.SetCAT(cat)
	plusPacket.SetPSN(psn)
	plusPacket.SetPSE(pse)

	plusPacket.SetPayload(payload)

	return &plusPacket
}

// Construct a new extended plus packet
//  (with extended header)
func NewExtendedPLUSPacket(
	lFlag bool,
	rFlag bool,
	sFlag bool,
	cat uint64,
	psn uint32,
	pse uint32,
	pcfType uint16,
	pcfIntegrity uint8,
	pcfValue []byte,
	payload []byte) (*PLUSPacket, error) {

	var plusPacket PLUSPacket

	length := BASIC_HEADER_LEN + 1

	if len(pcfValue) >= 64 {
		return nil, errors.New("PCF Value is restricted to 63 bytes maximum.")
	}

	if pcfType == 0xFF {
		if pcfValue != nil {
			return nil, errors.New("PCF Value does not exist if PCF Type is 0xFF")
		}
	}

	//Need one more byte for PCF Type 0x00
	if (pcfType & 0x00FF) == 0 {
		length += 1
	}

	if pcfIntegrity > PCF_INTEGRITY_FULL {
		return nil, errors.New("PCF Integrity is a two bit value. Can't be larger than 0x03.")
	}

	if pcfType == 0xFF {
		//no PCF Len/PCF I and no PCF Value
	} else {
		length += 1 //need one byte for PCF Len/PCF I
		length += ulen(pcfValue)
	}

	plusPacket.header = make([]byte, length)

	binary.BigEndian.PutUint32(plusPacket.header, (MAGIC<<4)|1)

	plusPacket.SetLFlag(lFlag)
	plusPacket.SetRFlag(rFlag)
	plusPacket.SetSFlag(sFlag)
	plusPacket.SetCAT(cat)
	plusPacket.SetPSN(psn)
	plusPacket.SetPSE(pse)

	ofs := uint16(0)

	if (pcfType & 0x00FF) == 0 {
		plusPacket.header[BASIC_HEADER_LEN+ofs] = 0x00
		ofs++
		plusPacket.header[BASIC_HEADER_LEN+ofs] = uint8(pcfType >> 8)
		ofs++
		plusPacket.header[BASIC_HEADER_LEN+ofs] = (uint8(ulen(pcfValue)) << 2) | pcfIntegrity
	} else if pcfType != 0xFF {
		plusPacket.header[BASIC_HEADER_LEN+ofs] = uint8(pcfType & 0xFF)
		ofs++
		if ulen(pcfValue) == 0 {
			pcfIntegrity = 0 //spec says if len is 0 integrity is unspecified and must be set to zero
		}

		plusPacket.header[BASIC_HEADER_LEN+ofs] = (uint8(ulen(pcfValue)) << 2) | pcfIntegrity
	} else {
		plusPacket.header[BASIC_HEADER_LEN+ofs] = 0xFF
	}

	ofs++

	copy(plusPacket.header[(BASIC_HEADER_LEN+ofs):], pcfValue)

	ofs += ulen(pcfValue)

	if BASIC_HEADER_LEN+ofs != length {
		return nil, fmt.Errorf("BUG %d, %d", BASIC_HEADER_LEN+ofs, length)
	}

	plusPacket.SetPayload(payload)

	return &plusPacket, nil
}
