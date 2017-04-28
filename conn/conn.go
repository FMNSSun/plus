package conn

import "net"
import "time"
import "plus/packet"
import "fmt"
import "log"
import "os"
import "sync"

type PLUSListener struct {
  packetConn net.PacketConn
  connections map[uint64]*PLUSConn
  newConnections chan *PLUSConn
  serverMode bool
  logger *log.Logger
  mkPLUSInterface func(*PLUSConn) *PLUSInterface
}

// Implements the net.PacketConn interface but also
// allows raw access and allows to register an observer
// to be notified about state changes and receiving
// of packets.
type PLUSConn struct {
  inChannel chan *packet.PLUSPacket
  outChannel chan *packet.PLUSPacket
  packetConn net.PacketConn
  state uint16
  cat uint64
  defaultLFlag bool
  defaultRFlag bool
  pse uint32
  psn uint32
  remoteAddr net.Addr
  logger *log.Logger
  mutex *sync.RWMutex
  plusInterface *PLUSInterface
}


type PLUSInterface struct {
  SignAndEncrypt func(*PLUSConn, []byte, []byte) []byte
  ValidateAndDecrypt func(*PLUSConn, []byte, []byte) ([]byte, error)
  OnStateChanged func(*PLUSConn, uint16)
  OnBasicPacketReceived func(*PLUSConn, *packet.PLUSPacket)
  OnExtendedPacketReceived func(*PLUSConn, *packet.PLUSPacket)
}


const maxPacketSize int = 4096
const mUint32 uint64 = 4294967296

// ZERO State
const STATE_ZERO uint16 = 0
// Only received, nothing sent so far
const STATE_UNIFLOW_RECV uint16 = 1
// Only sent, nothing received so far.
const STATE_UNIFLOW_SENT uint16 = 2
// Unused
const STATE_ASSOCIATING uint16 = 3
// Received and sent packets
const STATE_ASSOCIATED uint16 = 4
// Sent a packet with the S flag set
const STATE_STOP_SENT uint16 = 5
// Received a packet with the S flag set
const STATE_STOP_RECV uint16 = 6
// Connection closed
const STATE_CLOSED uint16 = 7

// Return state as a human readable value.
func StateToString(state uint16) string {
  switch(state) {
  case STATE_ZERO: return "ZERO"
  case STATE_UNIFLOW_RECV: return "UNIFLOW_RECV"
  case STATE_UNIFLOW_SENT: return "UNIFLOW_SENT"
  case STATE_ASSOCIATING: return "ASSOCIATING"
  case STATE_ASSOCIATED: return "ASSOCIATED"
  case STATE_STOP_SENT: return "STOP_SENT"
  case STATE_STOP_RECV: return "STOP_RECV"
  case STATE_CLOSED: return "CLOSED"
  }
  return "N/A"
}

// Create a PLUS server listening on laddr
func ListenPLUSAware(laddr string, mkPLUSInterface func(*PLUSConn) *PLUSInterface) (*PLUSListener, error) {
  packetConn, err := net.ListenPacket("udp", laddr)
  
  if(err != nil) {
    return nil, err
  }

  var plusListener PLUSListener
  plusListener.logger = log.New(os.Stdout, "Listener (true): ", log.Lshortfile)
  plusListener.packetConn = packetConn
  plusListener.serverMode = true
  plusListener.connections = make(map[uint64]*PLUSConn)
  plusListener.newConnections = make(chan *PLUSConn)
  plusListener.mkPLUSInterface = mkPLUSInterface

  go plusListener.listen()

  return &plusListener, nil
}

// Create a PLUS server listening on laddr
func ListenPLUS(laddr string) (*PLUSListener, error) {
  return ListenPLUSAware(laddr, nil)
}

// Connect to a PLUS server. laddr is the local address and remoteAddr is the 
// remote address.
func DialPLUSAware(laddr string, remoteAddr net.Addr, mkPLUSInterface func(*PLUSConn) *PLUSInterface) (*PLUSConn, error) {
  packetConn, err := net.ListenPacket("udp", laddr)
  
  if(err != nil) {
    return nil, err
  }

  var plusListener PLUSListener
  plusListener.logger = log.New(os.Stdout, "Listener (false): ", log.Lshortfile)
  plusListener.packetConn = packetConn
  plusListener.serverMode = false
  plusListener.connections = make(map[uint64]*PLUSConn)
  plusListener.mkPLUSInterface = mkPLUSInterface

  go plusListener.listen()

  // FIXME: Make this random. 
  randomCAT := uint64(4) //totally random for now
  plusListener.addConnection(randomCAT)

  plusConnection, ok := plusListener.connections[randomCAT]

  if(!ok) {
    return nil, fmt.Errorf("Connection with CAT %d does not exist. BUG!", randomCAT)
  }

  plusConnection.updateRemoteAddr(remoteAddr)

  return plusConnection, nil
}

// Connect to a PLUS server. laddr is the local address and remoteAddr is the 
// remote address.
func DialPLUS(laddr string, remoteAddr net.Addr) (*PLUSConn, error) {
  return DialPLUSAware(laddr, remoteAddr, nil)
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
  if(conn.plusInterface != nil) {
    if(conn.plusInterface.OnStateChanged != nil) {
      conn.plusInterface.OnStateChanged(conn, conn.state)
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
    if(plusPacket.SFlag()) {
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
    if(plusPacket.SFlag()) {
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
  closed := false
  if(conn.state == STATE_CLOSED) {
    closed = true
  } else {
    closed = false
  }
  conn.mutex.RUnlock()
  return closed
}

// Returns the CAT
func (conn *PLUSConn) CAT() uint64 {
  conn.mutex.Lock()
  cat := conn.cat
  conn.mutex.Unlock()
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
func (conn *PLUSConn) sendPacket(plusPacket *packet.PLUSPacket) error {
  if(conn.state == STATE_CLOSED) {
    return fmt.Errorf("Connection is closed!")
  }

  conn.logger.Print(fmt.Sprintf("sendPacket: Sending packet PSN := %d, PSE := %d", plusPacket.PSN(), plusPacket.PSE()))
  conn.logger.Print(plusPacket.Buffer())
  
  packetCAT := plusPacket.CAT()

  if(packetCAT != conn.cat) {
    // There's no sane sitution in which this can happen. 
    panic(fmt.Sprintf("Expected CAT %d but tried sending packet with CAT %d!", conn.cat, packetCAT))
  }

  buffer := plusPacket.Buffer()
  buflen := len(buffer)

  remoteAddr := conn.remoteAddr

  conn.logger.Print(fmt.Sprintf("sendPacket: WriteTo %s", remoteAddr.String()))

  n, err := conn.packetConn.WriteTo(buffer, remoteAddr)

  if(n != buflen) {
    return fmt.Errorf("Expected to send %d bytes but sent were %d bytes!", n, buflen)
  }

  if(err != nil) {
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
func (conn *PLUSConn) onNewPacketReceived(plusPacket *packet.PLUSPacket, remoteAddr net.Addr)  {
  conn.mutex.Lock()

  conn.logger.Print(fmt.Sprintf("Received packet PSN := %d, PSE := %d", plusPacket.PSN(), plusPacket.PSE()))
  conn.logger.Print(plusPacket.Buffer())

  packetCAT := plusPacket.CAT()

  if(packetCAT != conn.cat) {
    // There's no sane sitution in which this can happen. 
    panic(fmt.Sprintf("Expected CAT %d but received packet with CAT %d!", conn.cat, packetCAT))
  }


  conn.updateRemoteAddr(remoteAddr)
  

  // Update PSE
  conn.pse = plusPacket.PSN()

  if(conn.state != STATE_CLOSED) {
    conn.inChannel <- plusPacket
  }

  conn.updateStateReceive(plusPacket)

  // Notify observers if any
  if(conn.plusInterface != nil) {
    if(plusPacket.XFlag()) {
       if(conn.plusInterface.OnExtendedPacketReceived != nil) {
         conn.plusInterface.OnExtendedPacketReceived(conn, plusPacket)
       }
    } else {
       if(conn.plusInterface.OnBasicPacketReceived != nil) {
         conn.plusInterface.OnBasicPacketReceived(conn, plusPacket)
       }
    }
  }

  conn.mutex.Unlock()
}

// This listens on the internal packet connection for new packets, tries to
// parse them as a PLUS packet and creates new connection if packets with
// new CAT arrive. 
func (listener *PLUSListener) listen() {
  listener.logger.Print(fmt.Sprintf("listen() on %s",listener.packetConn.LocalAddr().String()))

  buffer := make([]byte, maxPacketSize)
  for {
    listener.logger.Print("listen: ReadFrom")
    n, remoteAddr, err := listener.packetConn.ReadFrom(buffer)
    listener.logger.Print("Read.")

    if(err != nil) {
      // FIXME: What the f*ck do we do here?
      listener.logger.Printf("Reading from packetConn failed: %s", err.Error())
      return
    } else {
      plusPacket, err := packet.NewPLUSPacket(buffer[:n])

      if(err != nil) {
        // FIXME: What the f*ck do we do here?
        listener.logger.Print("Parsing packet failed.")
      } else {

        plusConnection, ok := listener.connections[plusPacket.CAT()]

        if(!ok) {
          if(listener.serverMode) {
            plusConnection = listener.addConnection(plusPacket.CAT())
            if(listener.mkPLUSInterface != nil) {
              plusConnection.SetObserver(listener.mkPLUSInterface(plusConnection))
            }
          } else {
            /* Bogus packet with a bogus cat. Skip */
            listener.logger.Print("Bogus packet in non-servermode received")
            continue
          }
        }

        listener.logger.Print("Invoking onNewPacketReceived")

        plusConnection.onNewPacketReceived(plusPacket, remoteAddr)
      }
    }
  }
}

// Add and create a new connection. This is called when a new packet with a new CAT
// is received. 
func (listener *PLUSListener) addConnection(cat uint64) (*PLUSConn)  {
  listener.logger.Print(fmt.Sprintf("addConnection: %d", cat))

  var plusConnection PLUSConn

  plusConnection.mutex = &sync.RWMutex{}
  plusConnection.mutex.Lock()
  defer plusConnection.mutex.Unlock()

  /* Server mode or client mode? */
  if(listener.serverMode) {
    plusConnection.state = STATE_UNIFLOW_RECV
    listener.logger.Print(fmt.Sprintf("addConnection: write to chan"))
    listener.newConnections <- &plusConnection
    listener.logger.Print(fmt.Sprintf("addConnection: wrote to chan"))
  } else {
    plusConnection.state = STATE_ZERO
  }

  plusConnection.inChannel = make(chan *packet.PLUSPacket)
  plusConnection.cat = cat
  plusConnection.defaultLFlag = false
  plusConnection.defaultRFlag = false
  plusConnection.packetConn = listener.packetConn
  plusConnection.pse = 0
  plusConnection.psn = 1
  plusConnection.logger = log.New(os.Stdout, fmt.Sprintf("Connection %d: ", cat), log.Lshortfile)

  listener.connections[cat] = &plusConnection

  return &plusConnection
}

// Wait for a new connection and return it. Blocks forever.
// A connection is considered a new connection if a packet
// with a new CAT in the PLUS header is received.
func (listener *PLUSListener) Accept() (net.PacketConn, error) {
  listener.logger.Print("Waiting for new connection...")
  conn := <- listener.newConnections
  listener.logger.Print("New connection \\o/")
  return conn, nil
}

// Closes this listener.
func (listener *PLUSListener) Close() error {
  // TODO: Close channels an all that stuff
  listener.logger.Print("Close()")
  return listener.packetConn.Close()
}

// Closes this connection.
func (conn *PLUSConn) Close() error {
  // TODO: Maybe we need to do some cleanup?
  // FIXME: This is obviously bullshit because all PLUSConn from the server share
  //        the same packetConn. Maybe switch to channels?
  conn.logger.Print("Close()")
  return conn.packetConn.Close()
}

func (conn *PLUSConn) SetObserver(observer *PLUSInterface) {
  conn.mutex.RLock()
  defer conn.mutex.RUnlock()

  conn.plusInterface = observer
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
  select {
    case plusPacket := <- conn.inChannel:
      n := copy(b, plusPacket.Payload())
      return n, conn.RemoteAddr(), nil
  }

  return 0, nil, nil
}

// similar to ReadFrom but does not return an address
func (conn *PLUSConn) Read(b []byte) (int, error) {
  n, _, err := conn.ReadFrom(b)
  return n, err
}

// Read a raw packet
func (conn *PLUSConn) ReadPacket() (*packet.PLUSPacket, error) {
  select {
    case plusPacket := <- conn.inChannel:

      return plusPacket, nil
  }
}

// Sends data in a PLUS packet with a basic header.
// This essentially creates the PLUS packet and then calls
// sendPacket.
func (conn *PLUSConn) sendData(b []byte) (int, error) {
  conn.mutex.Lock()
  defer conn.mutex.Unlock()

  plusPacket := packet.NewBasicPLUSPacket(conn.defaultLFlag, conn.defaultLFlag, false,
                   conn.cat, conn.psn, conn.pse, b)

  if(conn.plusInterface != nil) {
    if(conn.plusInterface.SignAndEncrypt != nil) {
      payload := conn.plusInterface.SignAndEncrypt(conn, plusPacket.Header(), b)
      plusPacket.SetPayload(payload)
    }
  }

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
