package PLUS

import "plus/packet"
import "fmt"
import "sync"
import "net"

/* type PLUS */

type PLUS struct {
	connectionStates map[uint64]*PLUSConnState
	mutex            *sync.Mutex
	packetConn       net.PacketConn
	maxPacketSize    int
}

// Processes a PLUS packet. Returns unprotected part of PCF data that
// needs to be sent back through an encrypted feedback channel or
// nil when nothing is to send back.
func (plus *PLUS) ProcessPacket(plusPacket *packet.PLUSPacket) ([]byte, error) {
	plus.mutex.Lock()

	cat := plusPacket.CAT()

	connectionState, ok := plus.connectionStates[cat]

	if !ok {
		// New connection
		connectionState := NewPLUSConnState(cat)
		plus.connectionStates[cat] = connectionState
	}
	plus.mutex.Unlock()

	connectionState.mutex.Lock()
	defer connectionState.mutex.Unlock()

	connectionState.pse = plusPacket.PSN()

	if plusPacket.XFlag() { //extended header? need additional handling here
		return plus.handleExtendedPacket(plusPacket)
	}

	return nil, nil
}

// Updates the CAT of a connection (for connections with changing CATs)
func (plus *PLUS) UpdateCAT(oldCat uint64, newCat uint64) error {
	plus.mutex.Lock()
	defer plus.mutex.Unlock()

	oldConnectionState, ok := plus.connectionStates[oldCat]
	if !ok {
		return fmt.Errorf("Unknown CAT %d!", oldCat)
	}

	oldConnectionState.SetCAT(newCat)
	delete(plus.connectionStates, oldCat)
	plus.connectionStates[newCat] = oldConnectionState

	return nil
}

// Returns the connection state assigned to the specified cat.
func (plus *PLUS) GetPLUSConnState(cat uint64) (*PLUSConnState, error) {
	plus.mutex.Lock()
	defer plus.mutex.Unlock()

	plusConnState, ok := plus.connectionStates[cat]
	if !ok {
		return nil, fmt.Errorf("Unknown CAT %d!", cat)
	}
	return plusConnState, nil
}

// [internal] handles packets with extended header
func (plus *PLUS) handleExtendedPacket(plusPacket *packet.PLUSPacket) ([]byte, error) {
	unprotected, err := plusPacket.PCFValueUnprotected()
	if err != nil {
		return nil, nil
	}

	return unprotected, nil
}

// Reads a PLUS packet from the underlying PacketConn.
func (plus *PLUS) ReadPacket() (*packet.PLUSPacket, net.Addr, error) {
	buffer := make([]byte, plus.maxPacketSize)

	_, addr, err := plus.packetConn.ReadFrom(buffer)

	if err != nil {
		return nil, addr, err
	}

	plusPacket, err := packet.NewPLUSPacket(buffer)

	if err != nil {
		return nil, addr, err
	}

	return plusPacket, addr, nil
}

// ReadAndProcessPacket. See `ReadPacket` and `ProcessPacket`.
func (plus *PLUS) ReadAndProcessPacket() (*packet.PLUSPacket, net.Addr, []byte, error) {
	plusPacket, addr, err := plus.ReadPacket()

	if err != nil {
		return nil, nil, nil, err
	}

	feedbackData, err := plus.ProcessPacket(plusPacket)

	if err != nil {
		return nil, nil, nil, err
	}

	return plusPacket, addr, feedbackData, nil
}

// Writes a PLUS packet to the underlying PacketConn.
func (plus *PLUS) WritePacket(plusPacket *packet.PLUSPacket, addr net.Addr) error {
	buffer := plusPacket.Buffer()
	n, err := plus.packetConn.WriteTo(buffer, addr)

	if err != nil {
		return err
	}

	if n != len(buffer) {
		return fmt.Errorf("Expected to send %d bytes but could only send %d bytes!", len(buffer), n)
	}

	return nil
}

/* /type PLUS */

/* type PLUSConnState */

type PLUSConnState struct {
	cat            uint64
	psn            uint32
	pse            uint32
	defaultLFlag   bool
	defaultRFlag   bool
	defaultSFlag   bool
	pcfRequests    []pcfRequest
	pcfInsertIndex int
	pcfReadIndex   int
	pcfElements    int
	mutex          *sync.RWMutex
}

type pcfRequest struct {
	pcfType      uint16
	pcfValue     []byte
	pcfIntegrity uint8
}

const kMaxQueuedPCFRequests int = 10

// Creates a new connection state.
func NewPLUSConnState(cat uint64) *PLUSConnState {
	var plusConnState PLUSConnState
	plusConnState.cat = cat
	plusConnState.psn = 0
	plusConnState.pse = 0
	plusConnState.mutex = &sync.RWMutex{}
	plusConnState.pcfInsertIndex = 0
	plusConnState.pcfReadIndex = 0
	plusConnState.pcfElements = 0
	plusConnState.pcfRequests = make([]pcfRequest, kMaxQueuedPCFRequests)
	return &plusConnState
}

// Changes the CAt
func (plusConnState *PLUSConnState) SetCAT(newCat uint64) {
	plusConnState.mutex.Lock()
	defer plusConnState.mutex.Unlock()

	plusConnState.cat = newCat
}

// Adds received PCF feedback data
func (plusConnState *PLUSConnState) AddPCFFeedback(feedbackData []byte) error {
	//TODO
	return nil
}

// Prepares the next packet to be sent by creating an empty (no set payload) PLUS packet
// and returns this. The upper layer should then set the payload of the packet and hand it over
// to `WritePacket`.
func (plusConnState *PLUSConnState) PrepareNextPacket() (*packet.PLUSPacket, error) {
	plusConnState.mutex.Lock()
	defer plusConnState.mutex.Unlock()

	// Advance PSN (initialized to zero)
	plusConnState.psn += 1

	var plusPacket *packet.PLUSPacket
	var err error

	pcfType, pcfIntegrity, pcfValue, ok := plusConnState.GetPCFRequest()

	if ok {
		// Pending PCF, send extended packet
		plusPacket, err = packet.NewExtendedPLUSPacket(
			plusConnState.defaultLFlag,
			plusConnState.defaultRFlag,
			plusConnState.defaultSFlag,
			plusConnState.cat,
			plusConnState.psn,
			plusConnState.pse,
			pcfType,
			pcfIntegrity,
			pcfValue,
			nil)

		if err != nil {
			return nil, err
		}
	} else {
		// No pending PCF, send basic packet
		plusPacket = packet.NewBasicPLUSPacket(
			plusConnState.defaultLFlag,
			plusConnState.defaultRFlag,
			plusConnState.defaultSFlag,
			plusConnState.cat,
			plusConnState.psn,
			plusConnState.pse,
			nil)
	}

	return plusPacket, nil
}

// Queues a PCF request.
func (plusConnState *PLUSConnState) QueuePCFRequest(pcfType uint16, pcfIntegrity uint8, pcfValue []byte) error {
	plusConnState.mutex.Lock()
	defer plusConnState.mutex.Unlock()

	if plusConnState.pcfElements >= len(plusConnState.pcfRequests) {
		return fmt.Errorf("Buffer is full!")
	}

	plusConnState.pcfRequests[plusConnState.pcfInsertIndex] = pcfRequest{pcfType: pcfType, pcfValue: pcfValue, pcfIntegrity: pcfIntegrity}
	plusConnState.pcfInsertIndex = (plusConnState.pcfInsertIndex + 1) % kMaxQueuedPCFRequests
	plusConnState.pcfElements++

	return nil
}

// Returns and unqueues a PCF request.
func (plusConnState *PLUSConnState) GetPCFRequest() (uint16, uint8, []byte, bool) {
	plusConnState.mutex.Lock()
	defer plusConnState.mutex.Unlock()

	if plusConnState.pcfElements == 0 {
		return 0xDEAD, 0x00, nil, false
	}

	req := plusConnState.pcfRequests[plusConnState.pcfReadIndex]
	plusConnState.pcfReadIndex = (plusConnState.pcfReadIndex + 1) % kMaxQueuedPCFRequests
	plusConnState.pcfElements--

	return req.pcfType, req.pcfIntegrity, req.pcfValue, true
}

/* /type PLUSConnState */
