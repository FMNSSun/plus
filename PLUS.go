package PLUS

import "plus/packet"
import "fmt"
import "sync"

/* type PLUS */

type PLUS struct {
	connectionStates map[uint64]*PLUSConnState
	mutex *sync.Mutex
}

// Process a PLUS packet. Returns unprotected part of PCF data that
// needs to be sent back through an encrypted feedback channel or 
// nil when nothing is to send back.
func (plus *PLUS) ProcessPacket(plusPacket *packet.PLUSPacket, feedbackData []byte) ([]byte, error) {
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

    if feedbackData != nil {
		connectionState.addPCFFeedback(feedbackData)
	}

	if plusPacket.XFlag() { //extended header? need additional handling here
		return plus.handleExtendedPacket(plusPacket)
	}

	return nil, nil
}

func (plus *PLUS) UpdateCAT(oldCat uint64, newCat uint64) error {
	oldConnectionState, ok := plus.connectionStates[oldCat]
	if !ok {
		return fmt.Errorf("Unknown CAT %d!", oldCat)
	}

	oldConnectionState.SetCAT(newCat)
	delete(plus.connectionStates, oldCat)
	plus.connectionStates[newCat] = oldConnectionState

	return nil
}

func (plus *PLUS) GetPLUSConnState(cat uint64) (*PLUSConnState, error) {
	plusConnState, ok := plus.connectionStates[cat]
	if !ok {
		return nil, fmt.Errorf("Unknown CAT %d!", cat)
	}
	return plusConnState, nil
}

func (plus *PLUS) handleExtendedPacket(plusPacket *packet.PLUSPacket) ([]byte, error) {
	unprotected, err := plusPacket.PCFValueUnprotected()
	if err != nil {
		return nil, nil
	}

	return unprotected, nil
}

/* /type PLUS */

/* type PLUSConnState */

type PLUSConnState struct {
	cat	uint64
	psn uint32
	pse uint32
	defaultLFlag bool
	defaultRFlag bool
	defaultSFlag bool
	pcfRequests []pcfRequest
	pcfInsertIndex int
	pcfReadIndex int
	pcfElements int
	mutex *sync.RWMutex
}

type pcfRequest struct {
	pcfType uint16
	pcfValue []byte
	pcfIntegrity uint8
}

const kMaxQueuedPCFRequests int = 10

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

func (plusConnState *PLUSConnState) SetCAT(newCat uint64) {
	plusConnState.mutex.Lock()
	defer plusConnState.mutex.Unlock()

	plusConnState.cat = newCat
}

func (plusConnState *PLUSConnState) addPCFFeedback(feedbackData []byte) error {
	//TODO
	return nil
}

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

func (plusConnState *PLUSConnState) QueuePCFRequest(pcfType uint16, pcfIntegrity uint8, pcfValue []byte) error {
	plusConnState.mutex.Lock()
	defer plusConnState.mutex.Unlock()

	if plusConnState.pcfElements >= len(plusConnState.pcfRequests) {
		return fmt.Errorf("Buffer is full!")
	}

	plusConnState.pcfRequests[plusConnState.pcfInsertIndex] = pcfRequest { pcfType : pcfType, pcfValue : pcfValue, pcfIntegrity : pcfIntegrity }
	plusConnState.pcfInsertIndex = (plusConnState.pcfInsertIndex + 1 ) % kMaxQueuedPCFRequests
	plusConnState.pcfElements++

	return nil
}

func (plusConnState *PLUSConnState) GetPCFRequest() (uint16, uint8,  []byte, bool) {
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


