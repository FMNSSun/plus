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

func Log( msg string, a ...interface{}) {
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
// decrypt and validate packets.
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
// Relevant for PCF capabilities.
type FeedbackChannel interface {
	// Send feedback back through. 
	SendFeedback([]byte) error
}

/* /iface FeedbackChannel */

/* type ConnectionManager */

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
}

// Creates a new connection manager (server) using packetConn as the underlying
// packet connection.
func NewConnectionManager(packetConn net.PacketConn) *ConnectionManager {
	connectionManager := &ConnectionManager{
		connections:              make(map[uint64]*Connection),
		mutex:                    &sync.Mutex{},
		packetConn:               packetConn,
		maxPacketSize:            8192,
		dropUndecryptablePackets: true,
		newConnections:           make(chan *Connection, 16),
	}

	return connectionManager
}

// Creates a new connection manager for a client using packetConn as the underlying packet connection
// and the specified connectionId will be used when sending packets. remoteAddr specifies the
// target.
func NewConnectionManagerClient(packetConn net.PacketConn, connectionId uint64, remoteAddr net.Addr) (*ConnectionManager, *Connection) {
	connectionManager := &ConnectionManager{
		connections:              make(map[uint64]*Connection),
		mutex:                    &sync.Mutex{},
		packetConn:               packetConn,
		maxPacketSize:            8192,
		clientMode:               true,
		clientCAT:                connectionId,
		dropUndecryptablePackets: true,
		newConnections:           make(chan *Connection, 16),
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

// Tells the connection manager how many go routines to use.
func (plus *ConnectionManager) SetUseNGoRoutines(n uint8) {
	plus.Lock()
	defer plus.Unlock()

	plus.useNGoRoutines = n
}

// Sets the InitConn callback.
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

// 
func (plus *ConnectionManager) listenLoop() error {
	for {
		connection, plusPacket, addr, feedbackData, err := plus.ReadAndProcessPacket()

		if err != nil {
			log(1, "cm: Error: %s", err.Error())
			if plusPacket != InvalidPacket { // don't stop listening on invalid packets.
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

		if packetValid { // ignore S flag on invalid packets
			if connection.closeSent && plusPacket.SFlag() {
				connection.close() //we sent a close and received a close
			} else if plusPacket.SFlag() {
				connection.closeReceived = true
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
			return nil, nil, fmt.Errorf("Expected CAT := %d but got %d", plus.clientCAT, cat)
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
	

	return plusPacket.Header(), nil
}

var InvalidPacket *packet.PLUSPacket = &packet.PLUSPacket{}

// Reads a PLUS packet from the underlying PacketConn.
func (plus *ConnectionManager) ReadPacket() (*packet.PLUSPacket, net.Addr, error) {
	buffer := make([]byte, plus.maxPacketSize)

	n, addr, err := plus.packetConn.ReadFrom(buffer)

	if err != nil {
		return nil, addr, err
	}

	plusPacket, err := packet.NewPLUSPacket(buffer[:n])

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

	log(1, "cm: WritePacket sent packet %d/%d", plusPacket.PSN(), plusPacket.PSE())

	return nil
}

// closes the connection manager
func (plus *ConnectionManager) close() error {
	log(1, "cm: Close()")
	plus.closed = true
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

	closeSent     bool
	closeReceived bool
	closed        bool
	closeConn     func(connection *Connection) error

	pcfFeedback map[uint16][]byte
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
	plusPacket, err := connection.PrepareNextPacket()
	plusPacket.SetPayload(data)

	connection.Lock()
	defer connection.Unlock()

	if connection.closed {
		return 0, ErrConnClosed
	}

	if err != nil {
		return 0, err
	}

	if connection.cryptoContext != nil {
		_Payload, err := connection.cryptoContext.EncryptAndProtect(
			plusPacket.HeaderWithZeroes(), data)

		if err != nil {
			return 0, err
		}

		plusPacket.SetPayload(_Payload)
	}

	log(0, "%s\t\t\tSending [%d,%d]: %x", connection.packetConn.LocalAddr().String(),
		plusPacket.PSN(), plusPacket.PSE(),
		plusPacket.Header())

	n, err := connection.packetConn.WriteTo(plusPacket.Buffer(), connection.currentRemoteAddr)

	if connection.closeReceived && plusPacket.SFlag() {
		connection.close() //received and sent an SFlag?
	} else if plusPacket.SFlag() {
		connection.closeSent = true
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
	var err error

	pcfType, pcfIntegrity, pcfValue, ok := connection.getPCFRequest()

	if ok {
		log(2, "Pending PCF(%d,%d,%x)", pcfType, pcfIntegrity, pcfValue)
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
			connection.pse,
			nil)
	}

	return plusPacket, nil
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

// closes this connection.
func (connection *Connection) close() error {
	log(1, "c: Close()")

	if connection.connManager.clientMode {
		if connection.closeConn != nil {
		err := connection.closeConn(connection)
			if err != nil {
				return err
			}
		}

		return connection.connManager.close()
	} else {
		connection.connManager.Lock()
		delete(connection.connManager.connections, connection.cat)
		connection.connManager.Unlock()
	}

	close(connection.inChannel)
	connection.closed = true

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

func (connection *Connection) Lock() {
	log(-1, "c: LOCK")
	connection.mutex.Lock()
}

func (connection *Connection) Unlock() {
	log(-1, "c: UNLOCK")
	connection.mutex.Unlock()
}

func (connection *Connection) RLock() {
	log(-1, "c: RLOCK")
	connection.mutex.RLock()
}

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
