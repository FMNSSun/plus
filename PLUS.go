package PLUS

import "plus/packet"
import "fmt"
import "sync"
import "net"

/* iface CryptoContext */

type CryptoContext interface {
	EncryptAndProtect(plusHeader []byte, payload []byte) ([]byte, error)
	DecryptAndValidate(plusHeader []byte, payload []byte) ([]byte, error)
}

/* type ConnectionManager */

type ConnectionManager struct {
	connections map[uint64]*Connection
	mutex            *sync.Mutex
	packetConn       net.PacketConn
	maxPacketSize    int
    clientMode       bool
    clientCAT        uint64
}

func NewConnectionManager(packetConn net.PacketConn) *ConnectionManager {
    connectionManager := &ConnectionManager {
        connections : make(map[uint64]*Connection),
        mutex: &sync.Mutex{},
        packetConn: packetConn,
        maxPacketSize: 8192,
    }
    
    return connectionManager
}

func NewConnectionManagerClient(packetConn net.PacketConn, connection *Connection) *ConnectionManager {
    connectionManager := &ConnectionManager {
        connections : make(map[uint64]*Connection),
        mutex: &sync.Mutex{},
        packetConn: packetConn,
        maxPacketSize: 8192,
        clientMode: true,
        clientCAT: connection.cat,
    }
    
    return connectionManager
}


func (plus *ConnectionManager) LocalAddr() net.Addr {
	return plus.packetConn.LocalAddr()
}

// Processes a PLUS packet. Returns unprotected part of PCF data that
// needs to be sent back through an encrypted feedback channel or
// nil when nothing is to send back.
func (plus *ConnectionManager) ProcessPacket(plusPacket *packet.PLUSPacket, remoteAddr net.Addr) (*Connection, []byte, error) {
	plus.mutex.Lock()

	cat := plusPacket.CAT()
    
    if plus.clientMode {
        if cat != plus.clientCAT {
            return nil, nil, fmt.Errorf("Expected CAT := %d but got %d", plus.clientCAT, cat)
        }
    }

	connection, ok := plus.connections[cat]

	if !ok {
		// New connection
        fmt.Println("New connection", plus.clientMode)
		connection = NewConnection(cat, plus.packetConn, remoteAddr)
		plus.connections[cat] = connection
	}
	plus.mutex.Unlock()

	connection.mutex.Lock()
	defer connection.mutex.Unlock()

	connection.pse = plusPacket.PSN()

	if plusPacket.XFlag() { //extended header? need additional handling here
        data, err := plus.handleExtendedPacket(plusPacket)
		return connection, data, err
	}

	return connection, nil, nil
}


// Updates the CAT of a connection (for connections with changing CATs)
func (plus *ConnectionManager) UpdateCAT(oldCat uint64, newCat uint64) error {
	plus.mutex.Lock()
	defer plus.mutex.Unlock()

	oldconnection, ok := plus.connections[oldCat]
	if !ok {
		return fmt.Errorf("Unknown CAT %d!", oldCat)
	}

	oldconnection.SetCAT(newCat)
	delete(plus.connections, oldCat)
	plus.connections[newCat] = oldconnection

	return nil
}

// Returns the connection assigned to the specified cat.
func (plus *ConnectionManager) GetConnection(cat uint64) (*Connection, error) {
	plus.mutex.Lock()
	defer plus.mutex.Unlock()

	connection, ok := plus.connections[cat]
	if !ok {
		return nil, fmt.Errorf("Unknown CAT %d!", cat)
	}
	return connection, nil
}

// [internal] handles packets with extended header
func (plus *ConnectionManager) handleExtendedPacket(plusPacket *packet.PLUSPacket) ([]byte, error) {
	unprotected, err := plusPacket.PCFValueUnprotected()
	if err != nil {
		return nil, nil
	}

	return unprotected, nil
}

// Reads a PLUS packet from the underlying PacketConn.
func (plus *ConnectionManager) ReadPacket() (*packet.PLUSPacket, net.Addr, error) {
	buffer := make([]byte, plus.maxPacketSize)

	n, addr, err := plus.packetConn.ReadFrom(buffer)

	if err != nil {
		return nil, addr, err
	}

	plusPacket, err := packet.NewPLUSPacket(buffer[:n])

	if err != nil {
		return nil, addr, err
	}

	return plusPacket, addr, nil
}

// ReadAndProcessPacket. See `ReadPacket` and `ProcessPacket`.
func (plus *ConnectionManager) ReadAndProcessPacket() (*Connection, *packet.PLUSPacket, net.Addr, []byte, error) {
	plusPacket, addr, err := plus.ReadPacket()

	if err != nil {
		return nil, nil, nil, nil, err
	}

	connection, feedbackData, err := plus.ProcessPacket(plusPacket, addr)

	if err != nil {
		return connection, nil, nil, nil, err
	}

	return connection, plusPacket, addr, feedbackData, nil
}

// Writes a PLUS packet to the underlying PacketConn.
func (plus *ConnectionManager) WritePacket(plusPacket *packet.PLUSPacket, addr net.Addr) error {
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

func (plus *ConnectionManager) Close() error {
    return plus.packetConn.Close()
}


/* /type PLUS */

/* type Connection */

type Connection struct {
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
	cryptoContext  CryptoContext
}

type pcfRequest struct {
	pcfType      uint16
	pcfValue     []byte
	pcfIntegrity uint8
}

const kMaxQueuedPCFRequests int = 10

// Creates a new connection state.
func NewConnection(cat uint64, packetConn net.PacketConn, remoteAddr net.Addr) *Connection {
	var connection Connection
	connection.cat = cat
	connection.psn = 0
	connection.pse = 0
    connection.packetConn = packetConn
	connection.mutex = &sync.RWMutex{}
	connection.pcfInsertIndex = 0
	connection.pcfReadIndex = 0
	connection.pcfElements = 0
	connection.pcfRequests = make([]pcfRequest, kMaxQueuedPCFRequests)
    connection.currentRemoteAddr = remoteAddr
	return &connection
}

// Changes the CAt
func (connection *Connection) SetCAT(newCat uint64) {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()

	connection.cat = newCat
}

// Adds received PCF feedback data
func (connection *Connection) AddPCFFeedback(feedbackData []byte) error {
	//TODO
	return nil
}

// Wrapper. Writes an unprotected/unencrypted basic packet!
func (connection *Connection) Write(data []byte) error {
    plusPacket, err := connection.PrepareNextPacket()
	plusPacket.SetPayload(data)

	connection.mutex.Lock()
	defer connection.mutex.Unlock()
           
	if err != nil {
		return err
	}

	if connection.cryptoContext != nil {
		_Payload, err := connection.cryptoContext.EncryptAndProtect(
				plusPacket.HeaderWithZeroes(), data)

		if err != nil {
			return err
		}

		plusPacket.SetPayload(_Payload)
	}

    _, err = connection.packetConn.WriteTo(plusPacket.Buffer(), connection.currentRemoteAddr)
    
    return err
}

// Prepares the next packet to be sent by creating an empty (no set payload) PLUS packet
// and returns this. The upper layer should then set the payload of the packet and hand it over
// to `WritePacket`.
func (connection *Connection) PrepareNextPacket() (*packet.PLUSPacket, error) {
	connection.mutex.Lock()
	defer func(){ 
		connection.mutex.Unlock()
	}()

	// Advance PSN (initialized to zero)
	connection.psn += 1

	var plusPacket *packet.PLUSPacket
	var err error

	pcfType, pcfIntegrity, pcfValue, ok := connection.getPCFRequest()

	if ok {
		// Pending PCF, send extended packet
		plusPacket, err = packet.NewExtendedPLUSPacket(
			connection.defaultLFlag,
			connection.defaultRFlag,
			connection.defaultSFlag,
			connection.cat,
			connection.psn,
			connection.pse,
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
			connection.defaultLFlag,
			connection.defaultRFlag,
			connection.defaultSFlag,
			connection.cat,
			connection.psn,
			connection.pse,
			nil)
	}

	return plusPacket, nil
}

// Queues a PCF request.
func (connection *Connection) QueuePCFRequest(pcfType uint16, pcfIntegrity uint8, pcfValue []byte) error {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()

	if connection.pcfElements >= len(connection.pcfRequests) {
		return fmt.Errorf("Buffer is full!")
	}

	connection.pcfRequests[connection.pcfInsertIndex] = pcfRequest{pcfType: pcfType, pcfValue: pcfValue, pcfIntegrity: pcfIntegrity}
	connection.pcfInsertIndex = (connection.pcfInsertIndex + 1) % kMaxQueuedPCFRequests
	connection.pcfElements++

	return nil
}

// Returns and unqueues a PCF request.
func (connection *Connection) getPCFRequest() (uint16, uint8, []byte, bool) {
	if connection.pcfElements == 0 {
		return 0xDEAD, 0x00, nil, false
	}

	req := connection.pcfRequests[connection.pcfReadIndex]
	connection.pcfReadIndex = (connection.pcfReadIndex + 1) % kMaxQueuedPCFRequests
	connection.pcfElements--

	return req.pcfType, req.pcfIntegrity, req.pcfValue, true
}

func (connection *Connection) Close() error {
    return nil
}

func (connection *Connection) LocalAddr() net.Addr {
    return connection.packetConn.LocalAddr()
}

func (connection *Connection) RemoteAddr() net.Addr {
    connection.mutex.Lock()
    defer connection.mutex.Unlock()
    
    return connection.currentRemoteAddr
}

func (connection *Connection) SetRemoteAddr(remoteAddr net.Addr) {
    connection.mutex.Lock()
    defer connection.mutex.Unlock()
    
    connection.currentRemoteAddr = remoteAddr
}

/* /type Connection */
