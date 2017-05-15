package packet

import "testing"
import "encoding/binary"
import "bytes"
import "fmt"

// Dummy test
func TestByteOrder(t *testing.T) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, 197344687)
	ret := binary.BigEndian.Uint32(buf)

	if ret != 197344687 {
		t.Errorf("Expected %d but got %d", 197344687, ret)
	}
}

func TestHeader(t *testing.T) {
	packet := []byte{
		0xD8, 0x00, 0x7F, 0xFF, // the usual, magic + flags (all set) [0-3]
		0x12, 0x34, 0x56, 0x78, // cat								  [4-7]
		0x12, 0x12, 0x12, 0x12, // also cat                           [8-11]
		0x13, 0x11, 0x11, 0x11, // psn                                [12-15]
		0x11, 0x11, 0x11, 0x13, // pse                                [15-19]
		0x13, //PCF Type := 0x13                                      [20]
		(0x06 << 2) | (PCF_INTEGRITY_QUARTER), //PCF Len = 6, PCF I   [21]
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, //PCF Value bytes
		0x00, 0x00, 0x00, 0x00} // 4 bytes payload

	plusPacket, err := NewPLUSPacket(packet)
	
	if err != nil {
		t.Errorf("Error but expected none: %s", err.Error())
		return
	}

	if !bytes.Equal(plusPacket.Buffer(), packet) {
		fmt.Println(plusPacket.Buffer())
		fmt.Println(packet)
		t.Errorf("Buffers don't match!")
		return
	}

	header := []byte {
		0xD8, 0x00, 0x7F, 0xFF, // the usual, magic + flags (all set) [0-3]
		0x12, 0x34, 0x56, 0x78, // cat								  [4-7]
		0x12, 0x12, 0x12, 0x12, // also cat                           [8-11]
		0x13, 0x11, 0x11, 0x11, // psn                                [12-15]
		0x11, 0x11, 0x11, 0x13, // pse                                [15-19]
		0x13, //PCF Type := 0x13                                      [20]
		(0x06 << 2) | (PCF_INTEGRITY_QUARTER), //PCF Len = 6, PCF I   [21]
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06} // PCF value bytes (6)

	if !bytes.Equal(plusPacket.Header(), header) {
		fmt.Println(plusPacket.Header())
		fmt.Println(header)
		t.Errorf("Header is broken!")
		return
	}
}

func TestHeaderWithZeroes(t *testing.T) {
	packet := []byte{
		0xD8, 0x00, 0x7F, 0xFF, // the usual, magic + flags (all set) [0-3]
		0x12, 0x34, 0x56, 0x78, // cat								  [4-7]
		0x12, 0x12, 0x12, 0x12, // also cat                           [8-11]
		0x13, 0x11, 0x11, 0x11, // psn                                [12-15]
		0x11, 0x11, 0x11, 0x13, // pse                                [15-19]
		0x13, //PCF Type := 0x13                                      [20]
		(0x06 << 2) | (PCF_INTEGRITY_QUARTER), //PCF Len = 6, PCF I   [21]
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, //PCF Value bytes
		0x00, 0x00, 0x00, 0x00} // 4 bytes payload

	plusPacket, err := NewPLUSPacket(packet)
	
	if err != nil {
		t.Errorf("Error but expected none: %s", err.Error())
		return
	}

	if !bytes.Equal(plusPacket.Buffer(), packet) {
		fmt.Println(plusPacket.Buffer())
		fmt.Println(packet)
		t.Errorf("Buffers don't match!")
		return
	}

	headerWithZeroes := []byte {
		0xD8, 0x00, 0x7F, 0xFF, // the usual, magic + flags (all set) [0-3]
		0x12, 0x34, 0x56, 0x78, // cat								  [4-7]
		0x12, 0x12, 0x12, 0x12, // also cat                           [8-11]
		0x13, 0x11, 0x11, 0x11, // psn                                [12-15]
		0x11, 0x11, 0x11, 0x13, // pse                                [15-19]
		0x13, //PCF Type := 0x13                                      [20]
		(0x06 << 2) | (PCF_INTEGRITY_QUARTER), //PCF Len = 6, PCF I   [21]
		0x01, 0x02, 0x00, 0x00, 0x00, 0x00} //PCF Value bytes (6/4=1.5~=2 first two are protected, rest isn't)

	if !bytes.Equal(plusPacket.HeaderWithZeroes(), headerWithZeroes) {
		fmt.Println(plusPacket.HeaderWithZeroes())
		fmt.Println(headerWithZeroes)
		t.Errorf("HeaderWithZeroes is broken!")
		return
	}
}

func TestPacketPCFValue(t *testing.T) {
	packet := []byte{
		0xD8, 0x00, 0x7F, 0xFF, // the usual, magic + flags (all set) [0-3]
		0x12, 0x34, 0x56, 0x78, // cat								  [4-7]
		0x12, 0x12, 0x12, 0x12, // also cat                           [8-11]
		0x13, 0x11, 0x11, 0x11, // psn                                [12-15]
		0x11, 0x11, 0x11, 0x13, // pse                                [15-19]
		0x13, //PCF Type := 0x13                                      [20]
		(0x06 << 2) | (0x00), //PCF Len = 6, PCF I = 0x00 = (unprotected) [21]
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, //PCF Value bytes
		0x00, 0x00, 0x00, 0x00} // 4 bytes payload

	plusPacket, err := NewPLUSPacket(packet)
	
	if err != nil {
		t.Errorf("Error but expected none: %s", err.Error())
		return
	}

	if !bytes.Equal(plusPacket.Buffer(), packet) {
		fmt.Println(plusPacket.Buffer())
		fmt.Println(packet)
		t.Errorf("Buffers don't match!")
		return
	}

	pcfValue := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	res, err := plusPacket.PCFValue()

	if err != nil {
		t.Errorf("Error but expected none: %s", err.Error())
		return
	}

	if !bytes.Equal(res, pcfValue) {
		fmt.Println(res)
		fmt.Println(pcfValue)
		t.Errorf("PCFValue does not match!")
		return
	}

	// unprotected part
	pcfValueUnprotected := []byte{0x01, 0x02, 0x03,
	                              0x04, 0x05, 0x06}

	res, err = plusPacket.PCFValueUnprotected()

	if err != nil {
		t.Errorf("Error but expected none: %s", err.Error())
		return
	}

	if !bytes.Equal(res, pcfValueUnprotected) {
		fmt.Println(res)
		fmt.Println(pcfValueUnprotected)
		t.Errorf("PCFValueUnprotected is broken!")
		return
	}

	// Set PCF Integrity to quarter
	packet[21] = (0x06 << 2) | PCF_INTEGRITY_QUARTER
	
	plusPacket, err = NewPLUSPacket(packet)
	
	if err != nil {
		t.Errorf("Error but expected none: %s", err.Error())
		return
	}

	// First two bytes should be protected now 
	pcfValueUnprotected= []byte{0x03, 0x04, 0x05, 0x06}

	res, err = plusPacket.PCFValueUnprotected()

	if err != nil {
		t.Errorf("Error but expected none: %s", err.Error())
		return
	}

	if !bytes.Equal(res, pcfValueUnprotected) {
		fmt.Println(res)
		fmt.Println(pcfValueUnprotected)
		t.Errorf("PCFValueUnprotected is broken!")
		return
	}
}

// Create a packet through the New... and compare
// the result with a handcrafted buffer
func TestSerializePacket2(t *testing.T) {
	packet := []byte{
		0xD8, 0x00, 0x7F, 0xFF, //magic + flags (x bit set)
		0x12, 0x34, 0x56, 0x78, // cat
		0x12, 0x34, 0x56, 0x78, // cat..
		0x13, 0x11, 0x11, 0x11, // psn
		0x23, 0x22, 0x22, 0x22, // pse
		0x01, 0x1B, // PCF Type := 0x01,
		// PCF Len 6, PCF I = 11b,
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, // 6 bytes PCF value
		0x99, 0x98, 0x97, 0x96} // 4 bytes payload

	lFlag := true
	rFlag := true
	sFlag := true
	cat := uint64(0x1234567812345678)
	psn := uint32(0x13111111)
	pse := uint32(0x23222222)
	pcfType := uint16(0x01)
	//pcfLen := uint8(0x06)
	pcfIntegrity := uint8(0x03)
	pcfValue := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	payload := []byte{0x99, 0x98, 0x97, 0x96}

	plusPacket, err := NewExtendedPLUSPacket(lFlag, rFlag, sFlag, cat, psn, pse,
		pcfType, pcfIntegrity, pcfValue, payload)

	if err != nil {
		t.Errorf("Error but expected none: %s", err.Error())
		return
	}

	if !bytes.Equal(plusPacket.Buffer(), packet) {
		fmt.Println(plusPacket.Buffer())
		fmt.Println(packet)
		t.Errorf("Buffers don't match!")
		return
	}
}

// Create a packet through the New... and compare
// the result with a handcrafted buffer
func TestSerializePacket1(t *testing.T) {
	packet := []byte{
		0xD8, 0x00, 0x7F, 0xFA, //magic + flags
		0x12, 0x34, 0x56, 0x78, //cat
		0x21, 0x43, 0x65, 0x87,
		0x87, 0x65, 0x43, 0x21, //psn
		0x11, 0x22, 0x33, 0x44, //pse
		0x01, 0x02, 0x03, 0x04, //payload
		0x10, 0x20, 0x30, 0x40, //payload
		0x99, 0x90, 0x99, 0x90}

	lFlag := true
	rFlag := false
	sFlag := true

	cat := uint64(0x1234567821436587)
	psn := uint32(0x87654321)
	pse := uint32(0x11223344)

	payload := []byte{
		0x01, 0x02, 0x03, 0x04,
		0x10, 0x20, 0x30, 0x40,
		0x99, 0x90, 0x99, 0x90}

	plusPacket := NewBasicPLUSPacket(lFlag, rFlag, sFlag, cat, psn, pse, payload)

	if !bytes.Equal(plusPacket.Buffer(), packet) {
		fmt.Println(plusPacket.Buffer())
		fmt.Println(packet)
		t.Errorf("Buffers don't match!")
		return
	}
}

// Trying to read PCF flags in an extended packet
func TestReadPCF(t *testing.T) {
	packet := []byte{
		0xD8, 0x00, 0x7F, 0xFF, //magic + flags (x bit set)
		0x12, 0x34, 0x56, 0x78, // cat
		0x12, 0x34, 0x56, 0x78, // cat..
		0x13, 0x11, 0x11, 0x11, // psn
		0x23, 0x22, 0x22, 0x22, // pse
		0x01, 0x1B, // PCF Type := 0x01,
		// PCF Len 6, PCF I = 11b,
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, // 6 bytes PCF value
		0x99, 0x98, 0x97, 0x96} // 4 bytes payload

	lFlag := true
	rFlag := true
	sFlag := true
	cat := uint64(0x1234567812345678)
	psn := uint32(0x13111111)
	pse := uint32(0x23222222)
	pcfType := uint16(0x01)
	pcfLen := uint8(0x06)
	pcfIntegrity := uint8(0x03)
	//pcfValue := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	//payload := []byte{0x99, 0x98, 0x97, 0x96}

	var plusPacket PLUSPacket
	plusPacket.SetBuffer(packet)

	if plusPacket.LFlag() != lFlag {
		t.Errorf("Wrong lFlag")
		return
	}

	if plusPacket.RFlag() != rFlag {
		t.Errorf("Wrong RFlag")
		return
	}

	if plusPacket.SFlag() != sFlag {
		t.Errorf("Wrong SFlag")
		return
	}

	if plusPacket.CAT() != cat {
		t.Errorf("Wrong CAT")
		return
	}

	if plusPacket.PSN() != psn {
		t.Errorf("Wrong PSN")
		return
	}

	if plusPacket.PSE() != pse {
		t.Errorf("Wrong PSE")
		return
	}

	pcfType_, err := plusPacket.PCFType()

	if err != nil {
		t.Errorf("Error: %s", err.Error())
		return
	}

	if pcfType_ != pcfType {
		t.Errorf("Wrong PCF Type")
		return
	}

	pcfLen_, err := plusPacket.PCFLen()

	if err != nil {
		t.Errorf("Error: %s", err.Error())
		return
	}

	if pcfLen_ != pcfLen {
		t.Errorf("Wrong PCF Len. Got %d but expected %d", pcfLen_, pcfLen)
		return
	}

	pcfIntegrity_, err := plusPacket.PCFIntegrity()

	if err != nil {
		t.Errorf("Error: %s", err.Error())
		return
	}

	if pcfIntegrity_ != pcfIntegrity {
		t.Errorf("Wrong PCF Integrity")
		return
	}
}

// Trying to read PCF flags in a basic packet should return
// an error.
func TestReadPCFInBasicPacket(t *testing.T) {
	plusPacket := NewBasicPLUSPacket(true, true, true, 99, 99, 99, []byte{})

	_, err := plusPacket.PCFType()

	if err == nil {
		t.Errorf("Expected error but got none.")
		return
	}

	_, err = plusPacket.PCFLen()

	if err == nil {
		t.Errorf("Expected error but got none.")
		return
	}

	_, err = plusPacket.PCFIntegrity()

	if err == nil {
		t.Errorf("Expected error but got none.")
		return
	}

	_, err = plusPacket.GetPCFLenIntegrityPos()

	if err == nil {
		t.Errorf("Expected error but got none.")
	}
}

// Create a too small buffer and try to read it as
// a PLUS packet.
func TestReadPacketInvalidTooSmall(t *testing.T) {
	buf := make([]byte, 16)

	_, err := NewPLUSPacket(buf)

	if err == nil {
		t.Errorf("Expected error but got none.")
		return
	}
}

// Creates a packet with a 1 byte (0xB1) payload
// with a basic header with L and S flag set and R unset.
func TestReadPacket1(t *testing.T) {
	buf := make([]byte, 21)

	const expectedLFlag byte = 1
	const expectedRFlag byte = 0
	const expectedSFlag byte = 1

	flags := expectedLFlag<<3 | expectedRFlag<<2 | expectedSFlag<<1

	binary.BigEndian.PutUint32(buf,
		(MAGIC<<4)|uint32(flags))

	const expectedCat uint64 = 0x3F2FFFFF1FFFFFFF
	const expectedPsn uint32 = 0x12345678
	const expectedPse uint32 = 0x87654321

	binary.BigEndian.PutUint64(buf[4:], expectedCat)
	binary.BigEndian.PutUint32(buf[12:], expectedPsn)
	binary.BigEndian.PutUint32(buf[16:], expectedPse)
	buf[20] = 0xB1

	var plusPacket PLUSPacket
	err := plusPacket.SetBuffer(buf)

	if err != nil {
		t.Errorf(err.Error())
	}

	if plusPacket.CAT() != expectedCat {
		t.Errorf("Expected %x but got %x", expectedCat, plusPacket.CAT())
		return
	}

	if plusPacket.PSN() != expectedPsn {
		t.Errorf("Expected %x but got %x", expectedPsn, plusPacket.PSN())
		return
	}

	if plusPacket.PSE() != expectedPse {
		t.Errorf("Expected %x but got %x", expectedPse, plusPacket.PSE())
		return
	}

	if plusPacket.Payload()[0] != 0xB1 {
		t.Errorf("Expected %x but got %x", 0xB1, plusPacket.Payload()[0])
		return
	}

	if plusPacket.LFlag() != toBool(expectedLFlag) {
		t.Errorf("Expected %x but got %x", expectedLFlag, plusPacket.LFlag())
		return
	}

	if plusPacket.RFlag() != toBool(expectedRFlag) {
		t.Errorf("Expected %x but got %x", expectedRFlag, plusPacket.RFlag())
		return
	}

	if plusPacket.SFlag() != toBool(expectedSFlag) {
		t.Errorf("Expected %x but got %x", expectedSFlag, plusPacket.SFlag())
		return
	}
}
