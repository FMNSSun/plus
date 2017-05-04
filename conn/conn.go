package conn

import "net"
import "time"
import "plus/packet"
import "fmt"
import "log"
import "os"
import "sync"

// Implements the net.PacketConn interface but also
// allows raw access and allows to register an observer
// to be notified about state changes and receiving
// of packets.
type PLUSConn struct {
	inChannel          chan inPacket
	outChannel         chan *packet.PLUSPacket
	packetConn         net.PacketConn
	state              uint16
	cat                uint64
	defaultLFlag       bool
	defaultRFlag       bool
	pse                uint32
	psn                uint32
	remoteAddr         net.Addr
	logger             *log.Logger
	mutex              *sync.RWMutex
	observer           PLUSObserver
	cryptoContext      PLUSCryptoContext
	dropInvalidPackets bool
}

type PLUSObserver interface {
	OnStateChanged(*PLUSConn, uint16)
	OnBasicPacketReceived(*PLUSConn, *packet.PLUSPacket, error)
	OnExtendedPacketReceived(*PLUSConn, *packet.PLUSPacket, error)
}

type PLUSCryptoContext interface {
	SignAndEncrypt(*PLUSConn, []byte, []byte) ([]byte, error)
	ValidateAndDecrypt(*PLUSConn, []byte, []byte) ([]byte, error)
}

// Connect to a PLUS server. laddr is the local address and remoteAddr is the
// remote address.
func DialPLUSAware(laddr string, remoteAddr net.Addr, initConn func(*PLUSConn) error) (*PLUSConn, error) {
	packetConn, err := net.ListenPacket("udp", laddr)

	if err != nil {
		return nil, err
	}

	return DialPLUSWithPacketConn(packetConn, remoteAddr, initConn)
}

// Connect to a PLUS server. laddr is the local address and remoteAddr is the
// remote address.
func DialPLUS(laddr string, remoteAddr net.Addr) (*PLUSConn, error) {
	return DialPLUSAware(laddr, remoteAddr, nil)
}

func DialPLUSWithPacketConn(packetConn net.PacketConn, remoteAddr net.Addr, initConn func(*PLUSConn) error) (*PLUSConn, error) {
	var plusListener PLUSListener
	plusListener.logger = log.New(os.Stdout, "Listener (false): ", log.Lshortfile)
	plusListener.packetConn = packetConn
	plusListener.serverMode = false
	plusListener.connections = make(map[uint64]*PLUSConn)
	plusListener.initConn = initConn

	// FIXME: Make this random.
	randomCAT := uint64(4) //totally random for now
	plusListener.addConnection(randomCAT)

	plusConnection, ok := plusListener.connections[randomCAT]

	if !ok {
		return nil, fmt.Errorf("Connection with CAT %d does not exist. BUG!", randomCAT)
	}

	if plusListener.initConn != nil {
		plusListener.initConn(plusConnection)
	}
	plusConnection.updateRemoteAddr(remoteAddr)

	go plusListener.listen()

	return plusConnection, nil
}

// Returns this connection's current remote address.
func (conn *PLUSConn) RemoteAddr() net.Addr {
	conn.mutex.RLock()
	addr := conn.remoteAddr
	conn.mutex.RUnlock()
	return addr
}

// Set the state and call on*State functions
func (conn *PLUSConn) setState(newState uint16) {
	conn.logger.Print(fmt.Sprintf("Old state: %s, New State: %s", StateToString(conn.state), StateToString(newState)))
	conn.state = newState
	switch newState {
	case STATE_ZERO:
		conn.onStateZero()
		break
	case STATE_UNIFLOW_RECV:
		conn.onStateUniflowRecv()
		break
	case STATE_UNIFLOW_SENT:
		conn.onStateUniflowSent()
		break
	case STATE_STOP_SENT:
		conn.onStateStopSent()
		break
	case STATE_STOP_RECV:
		conn.onStateStopRecv()
		break
	case STATE_CLOSED:
		conn.onStateClosed()
		break
	}

	// Notify observer, if any
	if conn.observer != nil {
		if conn.observer.OnStateChanged != nil {
			conn.observer.OnStateChanged(conn, conn.state)
		}
	}
}

func (conn *PLUSConn) onStateZero() {
}

func (conn *PLUSConn) onStateUniflowRecv() {
}

func (conn *PLUSConn) onStateUniflowSent() {
}

func (conn *PLUSConn) onStateStopSent() {
}

func (conn *PLUSConn) onStateStopRecv() {
}

func (conn *PLUSConn) onStateClosed() {
}

// Called to update the state on receiving a packet
func (conn *PLUSConn) updateStateReceive(plusPacket *packet.PLUSPacket) {
	switch conn.state {
	case STATE_ZERO:
		conn.setState(STATE_UNIFLOW_RECV)
		break
	case STATE_UNIFLOW_RECV:
		break
	case STATE_UNIFLOW_SENT:
		// Up to this point we only received stuff
		conn.setState(STATE_ASSOCIATED)
		break
	case STATE_STOP_SENT:
		// We sent a stop and received a stop?
		if plusPacket.SFlag() {
			conn.setState(STATE_CLOSED)
		}
		break
	case STATE_STOP_RECV:
		break
	case STATE_CLOSED:
		// Connection closed.
		break
	}
}

// Called to update the state on sending a packet
func (conn *PLUSConn) updateStateSend(plusPacket *packet.PLUSPacket) {
	switch conn.state {
	case STATE_ZERO:
		conn.setState(STATE_UNIFLOW_SENT)
		break
	case STATE_UNIFLOW_RECV:
		// Up to this point we only sent stuff
		conn.setState(STATE_ASSOCIATED)
		break
	case STATE_UNIFLOW_SENT:
		break
	case STATE_STOP_SENT:
		break
	case STATE_STOP_RECV:
		// We received a stop packet and now are trying to send one?
		if plusPacket.SFlag() {
			conn.setState(STATE_CLOSED)
		}
		break
	case STATE_CLOSED:
		break
	}
}

// Returns true if this connection is closed.
func (conn *PLUSConn) IsClosed() bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()

	closed := false
	if conn.state == STATE_CLOSED {
		closed = true
	} else {
		closed = false
	}

	return closed
}

// Returns the CAT
func (conn *PLUSConn) CAT() uint64 {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()

	cat := conn.cat
	return cat
}

// Send a raw packet.
func (conn *PLUSConn) SendPacket(plusPacket *packet.PLUSPacket) error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	return conn.sendPacket(plusPacket)
}

// Send a packet. This function will send the bytes of the packet through
// the underlying packet conn to the connections' current remote address.
// Packet will be signed and encrypted.
func (conn *PLUSConn) sendPacket(plusPacket *packet.PLUSPacket) error {
	if conn.state == STATE_CLOSED {
		return fmt.Errorf("Connection is closed!")
	}

	_, err := conn.signAndEncrypt(plusPacket)

	if err != nil {
		return err
	}

	conn.logger.Print(fmt.Sprintf("sendPacket: Sending packet PSN := %d, PSE := %d", plusPacket.PSN(), plusPacket.PSE()))
	conn.logger.Print(plusPacket.Buffer())

	packetCAT := plusPacket.CAT()

	if packetCAT != conn.cat {
		// There's no sane sitution in which this can happen.
		panic(fmt.Sprintf("Expected CAT %d but tried sending packet with CAT %d!", conn.cat, packetCAT))
	}

	buffer := plusPacket.Buffer()
	buflen := len(buffer)

	remoteAddr := conn.remoteAddr

	conn.logger.Print(fmt.Sprintf("sendPacket: WriteTo %s", remoteAddr.String()))

	n, err := conn.packetConn.WriteTo(buffer, remoteAddr)

	if n != buflen {
		return fmt.Errorf("Expected to send %d bytes but sent were %d bytes!", n, buflen)
	}

	if err != nil {
		return err
	}

	conn.updateStateSend(plusPacket)

	return nil
}

// Returns the state of this connection
func (conn *PLUSConn) State() uint16 {
	conn.mutex.RLock()
	state := conn.state
	conn.mutex.RUnlock()
	return state
}

// Update remote address
func (conn *PLUSConn) updateRemoteAddr(remoteAddr net.Addr) {
	conn.remoteAddr = remoteAddr
}

// Called by the listener when a new packet is received. This function handles
// protocol stuff such as updating the PSE and then adds the packet to a channel
// that is read by the ReadFrom method of this connection.
func (conn *PLUSConn) onNewPacketReceived(plusPacket *packet.PLUSPacket, remoteAddr net.Addr) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	conn.logger.Print(fmt.Sprintf("Received packet PSN := %d, PSE := %d", plusPacket.PSN(), plusPacket.PSE()))
	conn.logger.Print(plusPacket.Buffer())

	if conn.state == STATE_CLOSED {
		conn.logger.Print("Connection is in STATE_CLOSED")
		return //don't accept packets if the connection is closed
	}

	// Decrypt and validate
	err := conn.validateAndDecrypt(plusPacket)
	if err != nil {
		if !conn.dropInvalidPackets {
			conn.inChannel <- newInPacket(plusPacket, err)
			conn.notifyObservers(plusPacket, err)
		}
		return
	}

	packetCAT := plusPacket.CAT()

	if packetCAT != conn.cat {
		// There's no sane sitution in which this can happen.
		panic(fmt.Sprintf("Expected CAT %d but received packet with CAT %d!", conn.cat, packetCAT))
	}

	conn.updateRemoteAddr(remoteAddr)

	// Update PSE
	conn.pse = plusPacket.PSN()

	// TODO: make this non-blocking. If we can't write to the channel
	//       immediately we should just drop the packet.
	conn.inChannel <- newInPacket(plusPacket, nil)

	conn.updateStateReceive(plusPacket)

	conn.notifyObservers(plusPacket, nil)
}

func (conn *PLUSConn) notifyObservers(plusPacket *packet.PLUSPacket, err error) {
	// Notify observers if any
	if conn.observer != nil {
		if plusPacket.XFlag() {
			conn.observer.OnExtendedPacketReceived(conn, plusPacket, err)
		} else {
			conn.observer.OnBasicPacketReceived(conn, plusPacket, err)
		}
	}
}

// Closes this connection.
func (conn *PLUSConn) Close() error {
	// TODO: Maybe we need to do some cleanup?
	// FIXME: This is obviously bullshit because all PLUSConn from the server share
	//        the same packetConn. Maybe switch to channels?
	conn.logger.Print("Close()")
	return conn.packetConn.Close()
}

// Returns the observer
func (conn *PLUSConn) Observer() PLUSObserver {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()

	return conn.observer
}

// Sets the observer
func (conn *PLUSConn) SetObserver(observer PLUSObserver) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	conn.observer = observer
}

// Returns the crypto context
func (conn *PLUSConn) CryptoContext() PLUSCryptoContext {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()

	return conn.cryptoContext
}

// Sets the crypto context
func (conn *PLUSConn) SetCryptoContext(cryptoContext PLUSCryptoContext) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	conn.cryptoContext = cryptoContext
}

// Returns the local address of this connection.
func (conn *PLUSConn) LocalAddr() net.Addr {
	return conn.packetConn.LocalAddr()
}

// Read bytes from the connection into the supplied buffer and return the
// number of bytes read, this connection's current remote address.
func (conn *PLUSConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// NOTE: This function should have as little logic as necessary.
	//       All the protocol stuff should be done elsewhere. This is just a dummy
	//       wrapper around the channel.

	// TODO: Handle client IP address changes

	plusPacket, err := conn.ReadPacket()

	if err != nil {
		return 0, nil, err
	}

	n := copy(b, plusPacket.Payload())
	return n, conn.RemoteAddr(), nil
}

// similar to ReadFrom but does not return an address
func (conn *PLUSConn) Read(b []byte) (int, error) {
	n, _, err := conn.ReadFrom(b)
	return n, err
}

// Read a raw packet (validated and payload decrypted)
func (conn *PLUSConn) ReadPacket() (*packet.PLUSPacket, error) {
	conn.mutex.RLock()
	ch := conn.inChannel
	conn.mutex.RUnlock()
	select {
	case ip := <-ch:

		if ip.err != nil {
			return nil, ip.err
		}

		return ip.packet, nil
	}
}

// Validate & Decrypt the packet
func (conn *PLUSConn) ValidateAndDecrypt(plusPacket *packet.PLUSPacket) error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	return conn.validateAndDecrypt(plusPacket)
}

// Sign & Encrypt the packet
func (conn *PLUSConn) SignAndEncrypt(plusPacket *packet.PLUSPacket) (int, error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	return conn.signAndEncrypt(plusPacket)
}

// Validate & Decrypt the packet
func (conn *PLUSConn) validateAndDecrypt(plusPacket *packet.PLUSPacket) error {
	if conn.cryptoContext != nil {
		payload, err := conn.cryptoContext.ValidateAndDecrypt(conn, plusPacket.Header(), plusPacket.Payload())

		if err != nil {
			return err
		}

		plusPacket.SetPayload(payload)
	}
	return nil
}

// Sign & Encrypt the packet.
func (conn *PLUSConn) signAndEncrypt(plusPacket *packet.PLUSPacket) (int, error) {
	if conn.cryptoContext != nil {
		payload, err := conn.cryptoContext.SignAndEncrypt(conn, plusPacket.Header(), plusPacket.Payload())

		if err != nil {
			return 0, err
		}

		plusPacket.SetPayload(payload)

		return len(payload), nil
	}
	return len(plusPacket.Payload()), nil
}

// Sends data in a PLUS packet with a basic header.
// This essentially creates the PLUS packet and then calls
// sendPacket.
func (conn *PLUSConn) sendData(b []byte) (int, error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	plusPacket := packet.NewBasicPLUSPacket(conn.defaultLFlag, conn.defaultLFlag, false,
		conn.cat, conn.psn, conn.pse, b)

	conn.psn++

	return len(b), conn.sendPacket(plusPacket)
}

// Sends data in a PLUS packet with a basic header with the specified flags set.
// This essentially creates the PLUS packet and then calls
// sendPacket.
func (conn *PLUSConn) sendDataWithFlags(b []byte, lFlag bool, rFlag bool, sFlag bool) (int, error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	plusPacket := packet.NewBasicPLUSPacket(lFlag, rFlag, sFlag,
		conn.cat, conn.psn, conn.pse, b)

	conn.psn++

	return len(b), conn.sendPacket(plusPacket)
}

// Write bytes. The addr argument will be ignored because PLUS handles
// the remote address.
func (conn *PLUSConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// NOTE: We're ignoring Addr here because PLUS takes care of IP address changes.
	//       Which means yeah... we override the address the overlaying layer wants stuff
	//       to send to. Also... all the protocol stuff should be done elsehwere.

	return conn.sendData(b)
}

// see WriteTo.
func (conn *PLUSConn) Write(b []byte) (int, error) {
	return conn.sendData(b)
}

// see WriteTo. This function allows to specify flags for the basic PLUS header of the packet
// this data is sent with.
func (conn *PLUSConn) WriteWithFlags(b []byte, lFlag bool, rFlag bool, sFlag bool) (int, error) {
	return conn.sendDataWithFlags(b, lFlag, rFlag, sFlag)
}

// TODO
func (*PLUSConn) SetDeadline(t time.Time) error {
	return nil
}

// TODO
func (*PLUSConn) SetReadDeadline(t time.Time) error {
	return nil
}

// TODO
func (*PLUSConn) SetWriteDeadline(t time.Time) error {
	return nil
}
