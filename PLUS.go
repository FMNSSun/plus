package PLUS

import "plus/packet"
import "fmt"
import "sync"
import "net"
import "io"
import "errors"
import "time"
import crand "crypto/rand"
import "math/rand"
import "math/big"
import m "math"

// Returns a cryptographically strong random PSN value
// if possible, otherwise it will fallback to a regular
// PRNG.
func RandomPSN() uint32 {
	bigNum, err := crand.Int(crand.Reader, big.NewInt(m.MaxUint32))

	if err != nil {
		return rand.Uint32()
	}

	return uint32(bigNum.Uint64())
}

// Returns a cryptographically strong random CAT value
// if possible, otherwise it will fallback to a regular
// PRNG.
func RandomCAT() uint64 {
	return uint64(RandomPSN())<<32 | uint64(RandomPSN())
}

var LoggerDestination io.Writer = nil
var LoggerMutex *sync.Mutex = &sync.Mutex{}

func Log(msg string, a ...interface{}) {
	log(99, msg, a...)
}

func log(lvl int, msg string, a ...interface{}) {
	if LoggerDestination == nil {
		return
	}

	LoggerMutex.Lock()
	defer LoggerMutex.Unlock()

	fmt.Fprintf(LoggerDestination, msg, a...)
	fmt.Fprintf(LoggerDestination, "\n")
}

/* iface CryptoContext */

// Provides callbacks to encrypt and protect or
// decrypt and validate packets. You must not read or write to the
// connection during these callbacks.
type CryptoContext interface {
	// Encrypts and protects a packet. plusHeader is PLUS header with
	// necessary fields zeroed out and payload is the actual payload.
	// This method needs to return the encrypted and protected payload (incl.
	// integrity protection mechanism).
	EncryptAndProtect(plusHeader []byte, payload []byte) ([]byte, error)

	// Decrypts and validates a packet. plusHeader is the PLUS header with
	// necessary fields zeroed out and payload is the encrypted and protected
	// payload of a packet. Needs to return the decrypted pure payload and indicate
	// through a bool whether validation was successful or not.
	DecryptAndValidate(plusHeader []byte, payload []byte) ([]byte, bool, error)
}

/* /iface CryptoContext */

/* iface FeedbackChannel */

// Provides PLUS with methods to send feedback back.
// Relevant for PCF capabilities. You must not read or write to the
// connection or change the connection's state during these callbacks.
type FeedbackChannel interface {
	// Send feedback back through.
	SendFeedback([]byte) error
}

/* /iface FeedbackChannel */

/* type ConnectionManager */

// Manages connections. You must not change attributes of the connection
// manager during the InitConn callback. The connection manager will create new connections
// as necessary invoking the InitConn callback during connection creation.
type ConnectionManager struct {
	// map of connections
	connections map[uint64]*Connection

	// new connections
	newConnections chan *Connection

	// used to sync access to fields
	mutex *sync.Mutex

	// underlying packet connection
	packetConn net.PacketConn

	// maximum packet size in bytes
	maxPacketSize int

	// true if client mode, false otherwise
	clientMode bool

	// if in client mode this holds the expected CAT
	clientCAT uint64

	// callback to be called when a new connection was established.
	// (Mostly only relevant in server mode)
	initConn func(connection *Connection) error

	// drop undecryptable packets or forward decryption errors to Read()
	dropUndecryptablePackets bool

	// listen mode?
	listenMode bool

	// closed?
	closed bool

	// useNGoRoutines
	useNGoRoutines uint8

	bufPool sync.Pool
	packetPool sync.Pool
}

// Creates a new connection manager (server) using packetConn as the underlying
// packet connection.
func NewConnectionManager(packetConn net.PacketConn) *ConnectionManager {
	var connectionManager *ConnectionManager
	connectionManager = &ConnectionManager{
		connections:              make(map[uint64]*Connection),
		mutex:                    &sync.Mutex{},
		packetConn:               packetConn,
		maxPacketSize:            8192,
		dropUndecryptablePackets: true,
		newConnections:           make(chan *Connection, 16),
		bufPool:                  sync.Pool { New : func() interface{} { return allocBuf(connectionManager) } },
		packetPool:               sync.Pool { New : func() interface{} { return &packet.PLUSPacket{} } }, 
	}

	return connectionManager
}

// Creates a new connection manager for a client using packetConn as the underlying packet connection
// and the specified connectionId will be used when sending packets. remoteAddr specifies the
// target.
func NewConnectionManagerClient(packetConn net.PacketConn, connectionId uint64, remoteAddr net.Addr) (*ConnectionManager, *Connection) {
	var connectionManager *ConnectionManager
	connectionManager = &ConnectionManager{
		connections:              make(map[uint64]*Connection),
		mutex:                    &sync.Mutex{},
		packetConn:               packetConn,
		maxPacketSize:            8192,
		clientMode:               true,
		clientCAT:                connectionId,
		dropUndecryptablePackets: true,
		newConnections:           make(chan *Connection, 16),
		bufPool:                  sync.Pool { New : func() interface{} { return allocBuf(connectionManager) } },
		packetPool:               sync.Pool { New : func() interface{} { return &packet.PLUSPacket{} } }, 
	}

	connection := NewConnection(connectionId, packetConn, remoteAddr, connectionManager)
	connectionManager.connections[connection.cat] = connection

	return connectionManager, connection
}

// Obtain a W lock to the connection manager. You shouldn't have to call this.
func (plus *ConnectionManager) Lock() {
	log(0, "cm: LOCK")
	plus.mutex.Lock()
}

// Release a W lock to the connection manager. Neither should you have to call this.
func (plus *ConnectionManager) Unlock() {
	log(0, "cm: UNLOCK")
	plus.mutex.Unlock()
}

// Tells the connection manager how many go routines to use for listening and
// decryption of packets.
func (plus *ConnectionManager) SetUseNGoRoutines(n uint8) {
	plus.Lock()
	defer plus.Unlock()

	plus.useNGoRoutines = n
}

// Sets the InitConn callback. This is invoked during creation of a new connection by
// the connection manager.
func (plus *ConnectionManager) SetInitConn(initConn func(*Connection) error) {
	plus.Lock()
	defer plus.Unlock()

	plus.initConn = initConn
}

// Waits and returns a new connection. nil if the ConnectionManager
// was closed.
func (plus *ConnectionManager) Accept() *Connection {
	log(1, "cm: Accepting")
	conn, ok := <-plus.newConnections

	if !ok {
		return nil
	}

	log(1, "cm: Accepted")
	return conn
}

// This is the loop that handles incoming packets.
// It is spawned by the Listen() function.
func (plus *ConnectionManager) listenLoop() error {
	for {
		connection, plusPacket, addr, feedbackData, err := plus.ReadAndProcessPacket()

		if err != nil {
			log(1, "cm: Error: %s", err.Error())
			if plusPacket == InvalidPacket || connection == InvalidConnection { // don't stop listening on invalid packets or invalid connections.
				continue
			} else {
				plus.Close()
				return err
			}
		}

		log(0, "cm: Inpacket")

		connection.Lock()
		connection.currentRemoteAddr = addr
		connection.Unlock()

		connection.RLock()

		if feedbackData != nil && connection.feedbackChannel != nil {
			log(0, "cm: Feedback data available!")

			// TODO: What do we do with errors here?
			err = connection.feedbackChannel.SendFeedback(feedbackData)

			if err != nil {
				log(2, "cm: SendFeedback failed for connection %d", connection.cat)
			} else {
				log(0, "cm: Notified feedback channel!")
			}
		}

		packetValid := false

		if connection.cryptoContext != nil {
			log(1, "cm: Decrypting packet %d/%d", plusPacket.PSN(), plusPacket.PSE())
			_Payload, ok, err := connection.cryptoContext.DecryptAndValidate(
				plusPacket.HeaderWithZeroes(),
				plusPacket.Payload())

			packetValid = ok

			if err != nil && plus.dropUndecryptablePackets { //drop undecryptable packets?
				log(1, "cm: Undecryptable packet dropped")
			} else {

				if !ok {
					log(1, "cm: Invalid packet skipped")
				} else {
					plusPacket.SetPayload(_Payload)

					log(0, "cm: Forwarding packet...")

					select {
					case connection.inChannel <- &packetReceived{packet: plusPacket, err: err}:
						log(0, "cm: Packet forwarded...")

					default:
						log(0, "cm: Consumer too slow!")
						// drop packet if consumer is too slow
					}
				}
			}
		} else {
			log(0, "cm: Forwarding packet...")

			select {
			case connection.inChannel <- &packetReceived{packet: plusPacket, err: err}:
				log(0, "cm: Packet forwarded...")
			default:
				log(0, "cm: Consumer too slow!")
				// drop packet if consumer is too slow
			}
		}

		connection.RUnlock()

		connection.Lock()

		if connection.closeSent && plusPacket.SFlag() { // we sent a close and received a close
			if connection.closeSentPSN == plusPacket.PSE() {
				// Only close it if PSE matches.
				// But as a safety mechanism also only do so if the packet is actually valid? Otherwise we ignore it.
				// We should be able to drive the flow state back into associated.
				if packetValid {
					connection.close()
				}

				// Set closeReceivedPSN to zero again. If the packet was forged
				// and we thus don't close the connection and it will be driven into associated again
				// then the nodes on the path will also reset this.
				connection.closeReceivedPSN = 0
			}
		} else if plusPacket.SFlag() {
			connection.closeReceived = true

			// Only keep the PSN of the first S flag received
			if connection.closeReceivedPSN == 0 {
				connection.closeReceivedPSN = plusPacket.PSN()
			}
		}

		connection.Unlock()
	}
}

// Listens on the underlying connection for packets and
// distributes them to the Connections. This therefore does
// connection multiplexing. If you do this please DO NOT
// manually call ReadPacket/ProcessPacket/ReadAndProcessPacket
// anymore as this is handled by this Listen().
// If useNGoRoutines is zero this will block, otherwise it will
// always immediately return nil.
func (plus *ConnectionManager) Listen() error {
	log(1, "cm: Listen()")

	plus.Lock()
	plus.listenMode = true
	plus.Unlock()

	if plus.useNGoRoutines == 0 {
		return plus.listenLoop()
	} else {
		for i := uint8(0); i < plus.useNGoRoutines; i++ {
			go plus.listenLoop()
		}
	}

	return nil
}

// Returns the local address of the underlying packet connection.
func (plus *ConnectionManager) LocalAddr() net.Addr {
	return plus.packetConn.LocalAddr()
}

// Processes a PLUS packet. Returns data that
// needs to be sent back through an encrypted feedback channel or
// nil when nothing is to send back.
func (plus *ConnectionManager) ProcessPacket(plusPacket *packet.PLUSPacket, remoteAddr net.Addr) (*Connection, []byte, error) {
	log(0, "%s\t\t\tProcessing packet [%d/%d]: %x", plus.packetConn.LocalAddr().String(),
		plusPacket.PSN(), plusPacket.PSE(),
		plusPacket.Header())

	plus.Lock()

	cat := plusPacket.CAT()

	if plus.clientMode {
		if cat != plus.clientCAT {
			plus.Unlock()
			return InvalidConnection, nil, fmt.Errorf("Expected CAT := %d but got %d", plus.clientCAT, cat)
		}

	}

	connection, ok := plus.connections[cat]

	if !ok {
		// New connection
		log(2, "cm: New connection: %d (%t)", cat, plus.clientMode)
		connection = NewConnection(cat, plus.packetConn, remoteAddr, plus)
		plus.connections[cat] = connection

		if plus.initConn != nil {
			err := plus.initConn(connection)

			if err != nil {
				return nil, nil, err
			}
		}

		if plus.listenMode {
			log(0, "New connection forwarded")
			plus.newConnections <- connection
		}
	}
	plus.Unlock()

	connection.Lock()
	defer connection.Unlock()

	if plusPacket.PSN() == 1 && plus.clientMode {
		connection.queuePCFRequest(packet.PCF_TYPE_HOP_COUNT, packet.PCF_INTEGRITY_ZERO, []byte{0x00}) // send a HOP_COUNT request
	}

	connection.pse = plusPacket.PSN()

	if plusPacket.XFlag() { //extended header? need additional handling here
		data, err := plus.handleExtendedPacket(plusPacket)
		log(0, "Unprotected part: %x", data)
		return connection, data, err
	}

	return connection, nil, nil
}

// Updates the CAT of a connection (for connections with changing CATs)
func (plus *ConnectionManager) UpdateCAT(oldCat uint64, newCat uint64) error {
	plus.Lock()
	defer plus.Unlock()

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
	plus.Lock()
	defer plus.Unlock()

	connection, ok := plus.connections[cat]
	if !ok {
		return nil, fmt.Errorf("Unknown CAT %d!", cat)
	}
	return connection, nil
}

// [internal] handles packets with extended header
func (plus *ConnectionManager) handleExtendedPacket(plusPacket *packet.PLUSPacket) ([]byte, error) {
	log(0, "handleExtendedPacket")

	i, err := plusPacket.PCFIntegrity()

	if err != nil {
		return nil, nil // ignore error. This shouldn't happen and if it does, ignore it.
	}

	if i == packet.PCF_INTEGRITY_FULL {
		return nil, nil // don't send back if everything is integrity protected.
	}

	return plusPacket.Header(), nil
}

// This will be returned (in addition to error) by ReadPacket in case of a NON-CRITICAL error
// to distinguish between an error where the connection is broken or an error where a
// packet was invalid.
var InvalidPacket *packet.PLUSPacket = &packet.PLUSPacket{}

// This will be returned (in addition to error) by ProcessPacket in case of a NON-CRITICAL error
// to distinguish between an error where the connection is broken or an error where a packet
// was invalid.
var InvalidConnection *Connection = &Connection{}

// Reads a PLUS packet from the underlying PacketConn using the supplied buffer
func (plus *ConnectionManager) ReadPacketUsing(buffer []byte) (*packet.PLUSPacket, net.Addr, error) {
	n, addr, err := plus.packetConn.ReadFrom(buffer)

	if err != nil {
		return nil, addr, err
	}

	plusPacket, err := packet.NewPLUSPacketNoCopy(buffer[:n])

	if err != nil {
		return InvalidPacket, addr, err
	}

	return plusPacket, addr, nil
}

func allocBuf(plus *ConnectionManager) interface{} {
	return make([]byte, plus.maxPacketSize)
}

// Reads a PLUS packet from the underlying PacketConn.
func (plus *ConnectionManager) ReadPacket() (*packet.PLUSPacket, net.Addr, error) {
	buffer := plus.bufPool.Get().([]byte)

	n, addr, err := plus.packetConn.ReadFrom(buffer)

	if err != nil {
		return nil, addr, err
	}

	plusPacket := plus.packetPool.Get().(*packet.PLUSPacket)

	err = plusPacket.SetBufferNoCopy(buffer[:n])

	if err != nil {
		return InvalidPacket, addr, err
	}

	//log(1, "cm: ReadPacket received packet %d/%d", plusPacket.PSN(), plusPacket.PSE())

	return plusPacket, addr, nil
}

// ReadAndProcessPacket. See `ReadPacket` and `ProcessPacket`.
func (plus *ConnectionManager) ReadAndProcessPacket() (*Connection, *packet.PLUSPacket, net.Addr, []byte, error) {
	plusPacket, addr, err := plus.ReadPacket()

	if err != nil {
		return nil, plusPacket, addr, nil, err // make sure we pass plusPacket because it might be InvalidPacket
	}

	connection, feedbackData, err := plus.ProcessPacket(plusPacket, addr)

	if err != nil {
		return connection, nil, nil, nil, err // make sure we pass connection because it might be InvalidConnection
	}

	return connection, plusPacket, addr, feedbackData, nil
}

// ReadAndProcessPacketUsing. See `ReadAndProcessPacket`. Uses the supplied buffer.
func (plus *ConnectionManager) ReadAndProcessPacketUsing(buffer []byte) (*Connection, *packet.PLUSPacket, net.Addr, []byte, error) {
	plusPacket, addr, err := plus.ReadPacketUsing(buffer)

	if err != nil {
		return nil, plusPacket, addr, nil, err // make sure we pass plusPacket because it might be InvalidPacket
	}

	connection, feedbackData, err := plus.ProcessPacket(plusPacket, addr)

	if err != nil {
		return connection, nil, nil, nil, err // make sure we pass connection because it might be InvalidConnection
	}

	return connection, plusPacket, addr, feedbackData, nil
}

func (plus *ConnectionManager) ReturnBuffer(buffer []byte) {
	if cap(buffer) != plus.maxPacketSize {
		panic(fmt.Sprintf("Returned buffer of incorrect size! Wanted %d, got %d.", plus.maxPacketSize, cap(buffer)))
	}

	buffer = buffer[:plus.maxPacketSize]
	plus.bufPool.Put(buffer)
}

func (plus *ConnectionManager) ReturnPacketAndBuffer(plusPacket *packet.PLUSPacket) {
	plus.ReturnBuffer(plusPacket.BufferNoCopy())
	plus.ReturnPacket(plusPacket)
}

func (plus *ConnectionManager) ReturnPacket(plusPacket *packet.PLUSPacket) {
	plus.packetPool.Put(plusPacket)
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

	log(1, "cm: WritePacket sent packet %d/%d", plusPacket.PSN(), plusPacket.PSE())

	return nil
}

// Returns true if the connection manager is closed.
func (plus *ConnectionManager) Closed() bool {
	plus.Lock()
	defer plus.Unlock()

	// Technically this is set before all connections have been closed
	// but the above lock blocks until the lock is released in Close()
	return plus.closed
}

// closes the connection manager
func (plus *ConnectionManager) close() error {
	log(1, "cm: Close()")

	// Make double closing harmless.
	// If the CM is in clientMode the close call on the connection.
	// will also close the CM thus this a nested call to this close function.
	// This check also makes this harmless.
	if plus.closed {
		log(1, "cm: Already closed")
		return nil
	}

	plus.closed = true

	// Close all connections.
	for k, v := range plus.connections {
		log(1, "cm: Close(): Attempting to close CAT := ", k)
		v.Lock()
		v.close()
		v.Unlock()
	}

	// Close the packet connection
	return plus.packetConn.Close()
}

// Closes the connection manager.
func (plus *ConnectionManager) Close() error {
	plus.Lock()
	defer plus.Unlock()

	return plus.close()
}

/* /type PLUS */

/* type Connection */

// A Connection implementing net.Conn
// Currently Set*Deadline functions are NOT supported.
// If both an S flag was sent and received the connection will
// automatically be closed. On creation the InitConn callback
// of the ConnectionManager is invoked. During closing the CloseConn
// callback is invoked.
type Connection struct {
	cat          uint64
	psn          uint32
	pse          uint32
	defaultLFlag bool
	defaultRFlag bool
	defaultSFlag bool

	// pending pcf requests
	pcfRequests    []pcfRequest
	pcfInsertIndex int
	pcfReadIndex   int
	pcfElements    int

	// used to synchronize field access.
	mutex *sync.RWMutex

	packetConn        net.PacketConn
	currentRemoteAddr net.Addr

	cryptoContext   CryptoContext
	feedbackChannel FeedbackChannel

	// only relevant in Listen() mode.
	// Read of Connection will read from this chan.
	inChannel chan *packetReceived

	// back ref to the connection manager
	connManager *ConnectionManager

	closeSent        bool
	closeReceived    bool
	closeSentPSN     uint32
	closeReceivedPSN uint32
	closed           bool
	closeConn        func(connection *Connection) error

	pcfFeedback map[uint16][]byte

	sendBuffer []byte
	headerBuffer []byte
}

type pcfRequest struct {
	pcfType      uint16
	pcfValue     []byte
	pcfIntegrity uint8
}

// pair of (packet, error)
type packetReceived struct {
	packet *packet.PLUSPacket
	err    error
}

// How many PCF requests in the queue.
const kMaxQueuedPCFRequests int = 10

// Creates a new connection state.
func NewConnection(cat uint64, packetConn net.PacketConn, remoteAddr net.Addr, connManager *ConnectionManager) *Connection {
	var connection Connection
	connection.cat = cat
	connection.psn = RandomPSN()
	connection.pse = 0
	connection.packetConn = packetConn
	connection.mutex = &sync.RWMutex{}
	connection.pcfInsertIndex = 0
	connection.pcfReadIndex = 0
	connection.pcfElements = 0
	connection.pcfRequests = make([]pcfRequest, kMaxQueuedPCFRequests)
	connection.currentRemoteAddr = remoteAddr
	connection.connManager = connManager
	connection.inChannel = make(chan *packetReceived, 16)
	connection.pcfFeedback = make(map[uint16][]byte)
	connection.sendBuffer = make([]byte, connManager.maxPacketSize)
	connection.headerBuffer = make([]byte, 256)

	return &connection
}

// Changes the CAT
func (connection *Connection) SetCAT(newCat uint64) {
	connection.Lock()
	defer connection.Unlock()

	connection.cat = newCat
}

// Returns the CAT.
func (connection *Connection) CAT() uint64 {
	connection.RLock()
	defer connection.RUnlock()

	return connection.cat
}

// Returns the PSE.
func (connection *Connection) PSE() uint32 {
	connection.RLock()
	defer connection.RUnlock()

	return connection.pse
}

// Returns the PSN.
func (connection *Connection) PSN() uint32 {
	connection.RLock()
	defer connection.RUnlock()

	return connection.psn
}

// Adds received PCF feedback data
func (connection *Connection) AddPCFFeedback(feedbackData []byte) error {
	connection.Lock()
	defer connection.Unlock()

	log(1, "%s\t\t\tReceived PCF feedback: %x", connection.packetConn.LocalAddr().String(), feedbackData)

	return nil
}

var ErrConnClosed error = errors.New("Connection was closed!")

// Read data from this connection
func (connection *Connection) Read(data []byte) (int, error) {
	packetReceived, ok := <-connection.inChannel //validation/decription happens in the feeder

	if !ok {
		return 0, ErrConnClosed
	}

	plusPacket, err := packetReceived.packet, packetReceived.err

	if err != nil {
		return 0, err
	}

	n := copy(data, plusPacket.Payload())

	return n, nil
}

// Write data to this connection.
func (connection *Connection) Write(data []byte) (int, error) {
	connection.Lock()
	defer connection.Unlock()

	var payload []byte

	if connection.closed {
		return 0, ErrConnClosed
	}
	
	psn, headerLen, err := connection.prepareNextRaw(connection.sendBuffer)

	if err != nil {
		return 0, err
	}

	if connection.cryptoContext != nil {
		targetBuffer := connection.headerBuffer[:headerLen]
		packet.HeaderWithZeroesRaw(connection.sendBuffer[:headerLen], targetBuffer)
		_Payload, err := connection.cryptoContext.EncryptAndProtect(
			targetBuffer, data)

		if err != nil {
			return 0, err
		}

		payload = _Payload
	} else {
		payload = data
	}

	//fmt.Printf("headerLen := %d, len(payload) := %d, cap(sendBuffer) := %d, s := %d\n",
	//	headerLen, len(payload), cap(connection.sendBuffer), headerLen + len(payload))
	sendbuffer := connection.sendBuffer[:(headerLen + len(payload))] // resize
	copy(sendbuffer[headerLen:], payload) // copy payload into it

	n, err := connection.packetConn.WriteTo(sendbuffer, connection.currentRemoteAddr)

	if connection.closeReceived && connection.defaultSFlag {
		connection.close() //received and sending an SFlag?
	} else if connection.defaultSFlag { // ... just sending an SFlag?
		connection.closeSent = true
		if connection.closeSentPSN == 0 {
			connection.closeSentPSN = psn
		}
	}

	return n, err
}

// Send feedback data. Don't call this if you use the Listen() method
// of the ConnectionManager or if you don't use a FeedbackChannel
func (connection *Connection) SendFeedback(data []byte) error {
	connection.RLock()
	defer connection.RUnlock()

	return connection.feedbackChannel.SendFeedback(data)
}

// Encrypt and protect a packet. Don't call this if you use the Listen() method
// of the ConnectionManager or if you don't use a CryptoContext.
func (connection *Connection) EncryptAndProtect(plusPacket *packet.PLUSPacket) ([]byte, error) {
	connection.RLock()
	defer connection.RUnlock()

	return connection.cryptoContext.EncryptAndProtect(plusPacket.HeaderWithZeroes(), plusPacket.Payload())
}

// Decrypt and validate a packet. Don't call this if you use the Listen() method
// of the ConnectionManager or if you don't use a CryptoContext.
func (connection *Connection) DecryptAndValidate(plusPacket *packet.PLUSPacket) ([]byte, bool, error) {
	connection.RLock()
	defer connection.RUnlock()

	return connection.cryptoContext.DecryptAndValidate(plusPacket.HeaderWithZeroes(), plusPacket.Payload())
}

func (connection *Connection) prepareNextRaw(buffer []byte) (uint32, int, error) {
	// we assume we're already holding the lock.
	connection.psn += 1

	if connection.psn == 0 {
		connection.psn = 1
	}

	pcfType, pcfIntegrity, pcfValue, ok := connection.getPCFRequest()

	var pse uint32
	var n int
	var err error

	if connection.closeReceived && connection.defaultSFlag { // if we are sending a stop confirm
		pse = connection.closeReceivedPSN // we need to set pse to the PSN of the received stop
	} else {
		pse = connection.pse
	}

	if ok {
		log(2, "Pending PCF(%d,%d,%x)", pcfType, pcfIntegrity, pcfValue)
		// Pending PCF, send extended packet
		n, _, err = packet.WriteExtendedPacket(
			buffer, 
			connection.defaultLFlag,
			connection.defaultRFlag,
			connection.defaultSFlag,
			connection.cat,
			connection.psn,
			pse,
			pcfType,
			pcfIntegrity,
			pcfValue,
			nil)

		if err != nil {
			return 0, -1, err
		}

		// Set value to nil in pcfFeedback map to indicate
		// that this request was sent
		connection.pcfFeedback[pcfType] = nil
	} else {
		// No pending PCF, send basic packet
		n, _, err = packet.WriteBasicPacket(
			buffer, 
			connection.defaultLFlag,
			connection.defaultRFlag,
			connection.defaultSFlag,
			connection.cat,
			connection.psn,
			pse,
			nil)

		if err != nil {
			return 0, -1, err
		}
	}

	return connection.psn, n, nil
}

// Prepares the next packet to be sent by creating an empty (no set payload) PLUS packet
// and returns this. The upper layer should then set the payload of the packet and hand it over
// to `WritePacket`.
func (connection *Connection) PrepareNextPacket() (*packet.PLUSPacket, error) {
	connection.Lock()
	defer func() {
		connection.Unlock()
	}()

	// Advance PSN (initialized to zero)
	connection.psn += 1

	if connection.psn == 0 {
		connection.psn = 1
	}

	var plusPacket *packet.PLUSPacket
	var pse uint32
	var err error

	pcfType, pcfIntegrity, pcfValue, ok := connection.getPCFRequest()

	if connection.closeReceived && connection.defaultSFlag { // if we are sending a stop confirm
		pse = connection.closeReceivedPSN // we need to set pse to the PSN of the received stop
	} else {
		pse = connection.pse
	}

	if ok {
		log(2, "Pending PCF(%d,%d,%x)", pcfType, pcfIntegrity, pcfValue)
		// Pending PCF, send extended packet
		plusPacket, err = packet.NewExtendedPLUSPacket(
			connection.defaultLFlag,
			connection.defaultRFlag,
			connection.defaultSFlag,
			connection.cat,
			connection.psn,
			pse,
			pcfType,
			pcfIntegrity,
			pcfValue,
			nil)

		if err != nil {
			return nil, err
		}

		// Set value to nil in pcfFeedback map to indicate
		// that this request was sent
		connection.pcfFeedback[pcfType] = nil
	} else {
		// No pending PCF, send basic packet
		plusPacket = packet.NewBasicPLUSPacket(
			connection.defaultLFlag,
			connection.defaultRFlag,
			connection.defaultSFlag,
			connection.cat,
			connection.psn,
			pse,
			nil)
	}

	return plusPacket, nil
}

// Retreives feedback that was received and added by the outer layer.
// Returns an error if no data present. If the returned bool is false
// then no PCF request for this pcfType was ever sent. If the returned
// data is nil then the request was sent but no feedback yet arrived.
func (connection *Connection) GetFeedbackData(pcfType uint16) ([]byte, bool) {
	connection.Lock()
	defer connection.Unlock()

	data, ok := connection.pcfFeedback[pcfType]

	return data, ok
}

// This function needs to be called by the outer layer when it received
// data on a feedback channel
func (connection *Connection) AddFeedbackData(feedbackData []byte) error {
	connection.Lock()
	defer connection.Unlock()

	plusPacket, err := packet.NewPLUSPacket(feedbackData)

	if err != nil {
		return err
	}

	unprotected, err := plusPacket.PCFValueUnprotected()

	if err != nil {
		return err
	}

	pcfType, err := plusPacket.PCFType()

	if err != nil {
		return err
	}

	_, ok := connection.pcfFeedback[pcfType]

	if !ok {
		log(0, "c: Received unrequested PCF feedback!")
		return nil // wasn't requested so ignore it.
	} else {
		connection.pcfFeedback[pcfType] = unprotected
	}

	return nil
}

func (connection *Connection) queuePCFRequest(pcfType uint16, pcfIntegrity uint8, pcfValue []byte) error {
	log(0, "c: QueuePCFRequest(%d,%d,%x)", pcfType, pcfIntegrity, pcfValue)

	if connection.pcfElements >= len(connection.pcfRequests) {
		return fmt.Errorf("Buffer is full!")
	}

	connection.pcfRequests[connection.pcfInsertIndex] = pcfRequest{pcfType: pcfType, pcfValue: pcfValue, pcfIntegrity: pcfIntegrity}
	connection.pcfInsertIndex = (connection.pcfInsertIndex + 1) % kMaxQueuedPCFRequests
	connection.pcfElements++

	return nil
}

// Queues a PCF request.
func (connection *Connection) QueuePCFRequest(pcfType uint16, pcfIntegrity uint8, pcfValue []byte) error {
	connection.Lock()
	defer connection.Unlock()

	return connection.queuePCFRequest(pcfType, pcfIntegrity, pcfValue)
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

// Returns true if a packet with a set S flag was received
func (connection *Connection) CloseReceived() bool {
	connection.RLock()
	defer connection.RUnlock()

	return connection.closeReceived
}

// Returns true if a packet with a set S flag was sent
func (connection *Connection) CloseSent() bool {
	connection.RLock()
	defer connection.RUnlock()

	return connection.closeSent
}

// Returns true if the connection is closed
func (connection *Connection) Closed() bool {
	connection.RLock()
	defer connection.RUnlock()

	// technically this is set before the connection is COMPLETELY
	// closed but due to the lock synchronisation the above lock blocks
	// until the lock that's held during Close() is released.
	return connection.closed
}

// closes this connection.
func (connection *Connection) close() error {
	log(1, "c: Close()")

	// Make double closing harmless.
	if connection.closed {
		log(1, "c: Close(): Already closed")
		return nil
	}

	connection.closed = true

	// Close the inChannel. Necessary to unblock readers that are blocked on
	// reading from this channel. Otherwise the Read on a connection will block
	// forever.
	close(connection.inChannel)

	if connection.connManager.clientMode {
		var closeConnErr error

		if connection.closeConn != nil {
			closeConnErr = connection.closeConn(connection)
		}

		connection.connManager.Lock()
		delete(connection.connManager.connections, connection.cat)
		connection.connManager.Unlock()

		var cmCloseErr error = connection.connManager.Close()

		if cmCloseErr != nil {
			return cmCloseErr
		}

		return closeConnErr
	} else {
		connection.connManager.Lock()
		delete(connection.connManager.connections, connection.cat)
		connection.connManager.Unlock()
	}

	if connection.closeConn != nil {
		err := connection.closeConn(connection)
		if err != nil {
			return err
		}
	}

	return nil
}

// Closes this connection.
func (connection *Connection) Close() error {
	connection.Lock()
	defer connection.Unlock()

	return connection.close()
}

// Returns the local address.
func (connection *Connection) LocalAddr() net.Addr {
	return connection.packetConn.LocalAddr()
}

// Returns the remote address.
func (connection *Connection) RemoteAddr() net.Addr {
	connection.RLock()
	defer connection.RUnlock()

	return connection.currentRemoteAddr
}

// Changes the remote address.
func (connection *Connection) SetRemoteAddr(remoteAddr net.Addr) {
	connection.Lock()
	defer connection.Unlock()

	connection.currentRemoteAddr = remoteAddr
}

// Sets the CloseConn callback
func (connection *Connection) SetCloseConn(closeConn func(connection *Connection) error) {
	connection.Lock()
	defer connection.Unlock()

	connection.closeConn = closeConn
}

// Sets the crypto context.
func (connection *Connection) SetCryptoContext(cryptoContext CryptoContext) {
	connection.Lock()
	defer connection.Unlock()

	connection.cryptoContext = cryptoContext
}

// Returns the crypto context.
func (connection *Connection) CryptoContext() CryptoContext {
	connection.RLock()
	defer connection.RUnlock()

	return connection.cryptoContext
}

// Sets the feedback channel.
func (connection *Connection) SetFeedbackChannel(feedbackChannel FeedbackChannel) {
	connection.Lock()
	defer connection.Unlock()

	connection.feedbackChannel = feedbackChannel
}

// Returns the feedback channel.
func (connection *Connection) FeedbackChannel() FeedbackChannel {
	connection.RLock()
	defer connection.RUnlock()

	return connection.feedbackChannel
}

// Returns the default L flag.
func (connection *Connection) LFlag() bool {
	connection.RLock()
	defer connection.RUnlock()

	return connection.defaultLFlag
}

// Returns the default R flag.
func (connection *Connection) RFlag() bool {
	connection.RLock()
	defer connection.RUnlock()

	return connection.defaultRFlag
}

// Returns the default S flag
func (connection *Connection) SFlag() bool {
	connection.RLock()
	defer connection.RUnlock()

	return connection.defaultSFlag
}

// Sets the default L flag
func (connection *Connection) SetLFlag(value bool) {
	connection.Lock()
	defer connection.Unlock()

	connection.defaultLFlag = value
}

// Sets the default R flag
func (connection *Connection) SetRFlag(value bool) {
	connection.Lock()
	defer connection.Unlock()

	connection.defaultRFlag = value
}

// Sets the default S flag
func (connection *Connection) SetSFlag(value bool) {
	connection.Lock()
	defer connection.Unlock()

	connection.defaultSFlag = value
}

// Obtains a W lock. You should not have to call this.
func (connection *Connection) Lock() {
	log(-1, "c: LOCK")
	connection.mutex.Lock()
}

// Releases a W lock. You should not have to call this.
func (connection *Connection) Unlock() {
	log(-1, "c: UNLOCK")
	connection.mutex.Unlock()
}

// Obtains an R lock. You should not have to call this.
func (connection *Connection) RLock() {
	log(-1, "c: RLOCK")
	connection.mutex.RLock()
}

// Releases an R lock. You should not have to call this.
func (connection *Connection) RUnlock() {
	log(-1, "c: RUNLOCK")
	connection.mutex.RUnlock()
}

// TODO
func (*Connection) SetDeadline(t time.Time) error {
	return nil
}

// TODO
func (*Connection) SetReadDeadline(t time.Time) error {
	return nil
}

// TODO
func (*Connection) SetWriteDeadline(t time.Time) error {
	return nil
}

/* /type Connection */
