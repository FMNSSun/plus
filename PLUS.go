package PLUS

import "plus/packet"
import "fmt"
import "sync"
import "net"

/* type PLUSConnManager */

type PLUSConnManager struct {
	connectionStates map[uint64]*PLUSConnState
	mutex            *sync.Mutex
	packetConn       net.PacketConn
	maxPacketSize    int
}

func NewPLUSConnManager(packetConn net.PacketConn) *PLUSConnManager {
    plusConnManager := &PLUSConnManager {
        connectionStates : make(map[uint64]*PLUSConnState),
        mutex: &sync.Mutex{},
        packetConn: packetConn,
        maxPacketSize: 8192,
    }
    
    return plusConnManager
}

// Processes a PLUS packet. Returns unprotected part of PCF data that
// needs to be sent back through an encrypted feedback channel or
// nil when nothing is to send back.
func (plus *PLUSConnManager) ProcessPacket(plusPacket *packet.PLUSPacket, remoteAddr net.Addr) (*PLUSConnState, []byte, error) {
	plus.mutex.Lock()

	cat := plusPacket.CAT()

	connectionState, ok := plus.connectionStates[cat]

	if !ok {
		// New connection
		connectionState := NewPLUSConnState(cat, plus.packetConn, remoteAddr)
		plus.connectionStates[cat] = connectionState
	}
	plus.mutex.Unlock()

	connectionState.mutex.Lock()
	defer connectionState.mutex.Unlock()

	connectionState.pse = plusPacket.PSN()

	if plusPacket.XFlag() { //extended header? need additional handling here
        data, err := plus.handleExtendedPacket(plusPacket)
		return connectionState, data, err
	}

	return connectionState, nil, nil
}

// Updates the CAT of a connection (for connections with changing CATs)
func (plus *PLUSConnManager) UpdateCAT(oldCat uint64, newCat uint64) error {
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
func (plus *PLUSConnManager) GetPLUSConnState(cat uint64) (*PLUSConnState, error) {
	plus.mutex.Lock()
	defer plus.mutex.Unlock()

	plusConnState, ok := plus.connectionStates[cat]
	if !ok {
		return nil, fmt.Errorf("Unknown CAT %d!", cat)
	}
	return plusConnState, nil
}

// [internal] handles packets with extended header
func (plus *PLUSConnManager) handleExtendedPacket(plusPacket *packet.PLUSPacket) ([]byte, error) {
	unprotected, err := plusPacket.PCFValueUnprotected()
	if err != nil {
		return nil, nil
	}

	return unprotected, nil
}

// Reads a PLUS packet from the underlying PacketConn.
func (plus *PLUSConnManager) ReadPacket() (*packet.PLUSPacket, net.Addr, error) {
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
func (plus *PLUSConnManager) ReadAndProcessPacket() (*PLUSConnState, *packet.PLUSPacket, net.Addr, []byte, error) {
	plusPacket, addr, err := plus.ReadPacket()

	if err != nil {
		return nil, nil, nil, nil, err
	}

	plusConnState, feedbackData, err := plus.ProcessPacket(plusPacket, addr)

	if err != nil {
		return plusConnState, nil, nil, nil, err
	}

	return plusConnState, plusPacket, addr, feedbackData, nil
}

// Writes a PLUS packet to the underlying PacketConn.
func (plus *PLUSConnManager) WritePacket(plusPacket *packet.PLUSPacket, addr net.Addr) error {
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

func (plus *PLUSConnManager) Close() error {
    return plus.packetConn.Close()
}

func (plus *PLUSConnManager) LocalAddr() net.Addr {
    return plus.packetConn.LocalAddr()
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
    packetConn     net.PacketConn
    currentRemoteAddr net.Addr
}

type pcfRequest struct {
	pcfType      uint16
	pcfValue     []byte
	pcfIntegrity uint8
}

const kMaxQueuedPCFRequests int = 10

// Creates a new connection state.
func NewPLUSConnState(cat uint64, packetConn net.PacketConn, remoteAddr net.Addr) *PLUSConnState {
	var plusConnState PLUSConnState
	plusConnState.cat = cat
	plusConnState.psn = 0
	plusConnState.pse = 0
    plusConnState.packetConn = packetConn
	plusConnState.mutex = &sync.RWMutex{}
	plusConnState.pcfInsertIndex = 0
	plusConnState.pcfReadIndex = 0
	plusConnState.pcfElements = 0
	plusConnState.pcfRequests = make([]pcfRequest, kMaxQueuedPCFRequests)
    plusConnState.currentRemoteAddr = remoteAddr
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

// Wrapper. Writes an unprotected/unencrypted basic packet!
func (plusConnState *PLUSConnState) Write(data []byte) error {
    plusConnState.mutex.Lock()
	defer plusConnState.mutex.Unlock()

    // Advance PSN (initialized to zero)
	plusConnState.psn += 1

    plusPacket := packet.NewBasicPLUSPacket(
			plusConnState.defaultLFlag,
			plusConnState.defaultRFlag,
			plusConnState.defaultSFlag,
			plusConnState.cat,
			plusConnState.psn,
			plusConnState.pse,
			data)
            
    _, err := plusConnState.packetConn.WriteTo(plusPacket.Buffer(), plusConnState.currentRemoteAddr)
    
    return err
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

func (plusConnState *PLUSConnState) Close() error {
    return nil
}

func (plusConnState *PLUSConnState) LocalAddr() net.Addr {
    return plusConnState.packetConn.LocalAddr()
}

func (plusConnState *PLUSConnState) RemoteAddr() net.Addr {
    plusConnState.mutex.Lock()
    defer plusConnState.mutex.Unlock()
    
    return plusConnState.currentRemoteAddr
}

func (plusConnState *PLUSConnState) SetRemoteAddr(remoteAddr net.Addr) {
    plusConnState.mutex.Lock()
    defer plusConnState.mutex.Unlock()
    
    plusConnState.currentRemoteAddr = remoteAddr
}

/* /type PLUSConnState */
