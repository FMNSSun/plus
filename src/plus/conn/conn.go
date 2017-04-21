package conn

import "net"
import "time"
import "plus/packet"
import "fmt"
import "log"
import "os"

type PLUSListener struct {
  packetConn net.PacketConn
  connections map[uint64]*PLUSConn
  newConnections chan *PLUSConn
  serverMode bool
  logger *log.Logger
}


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
  kMaxOutOfOrder uint32
  remoteAddr net.Addr
  logger *log.Logger
}

const maxPacketSize int = 4096
const mUint32 uint64 = 4294967296
const STATE_ZERO uint16 = 0
const STATE_UNIFLOW_RECV uint16 = 1
const STATE_UNIFLOW_SENT uint16 = 2
const STATE_ASSOCIATING uint16 = 3
const STATE_ASSOCIATED uint16 = 4
const STATE_STOP_SENT uint16 = 5
const STATE_STOP_RECV uint16 = 6
const STATE_CLOSED uint16 = 7

func ListenPLUS(laddr string) (*PLUSListener, error) {
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

  go plusListener.listen()

  return &plusListener, nil
}

func DialPLUS(laddr string, remoteAddr net.Addr) (*PLUSConn, error) {
  packetConn, err := net.ListenPacket("udp", laddr)
  
  if(err != nil) {
    return nil, err
  }

  var plusListener PLUSListener
  plusListener.logger = log.New(os.Stdout, "Listener (false): ", log.Lshortfile)
  plusListener.packetConn = packetConn
  plusListener.serverMode = false
  plusListener.connections = make(map[uint64]*PLUSConn)

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

func (conn *PLUSConn) RemoteAddr() net.Addr {
  return conn.remoteAddr
}

func (conn *PLUSConn) setState(newState uint16) {
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

func (conn *PLUSConn) sendPacket(plusPacket *packet.PLUSPacket, size int) (int, error) {

  conn.logger.Print(fmt.Sprintf("sendPacket: Sending packet PSN := %d, PSE := %d", plusPacket.PSN(), plusPacket.PSE()))
  conn.logger.Print(plusPacket.Buffer())
  
  packetCAT := plusPacket.CAT()

  if(packetCAT != conn.cat) {
    // There's no sane sitution in which this can happen. 
    panic(fmt.Sprintf("Expected CAT %d but tried sending packet with CAT %d!", conn.cat, packetCAT))
  }

  stop := false

  switch conn.state {
  case STATE_ZERO: 
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
      stop = true
    }
    break
  case STATE_CLOSED:
    conn.logger.Print("sendPacket: Send on closed connection!")
    return 0,  fmt.Errorf("Connection has been closed.")
  }

  buffer := plusPacket.Buffer()
  buflen := len(buffer)

  conn.logger.Print(fmt.Sprintf("sendPacket: WriteTo %s", conn.RemoteAddr().String()))
  n, err := conn.packetConn.WriteTo(buffer, conn.RemoteAddr())

  if(n != buflen) {
    return n, fmt.Errorf("Expected to send %d bytes but sent were %d bytes!", n, buflen)
  }

  if(stop) {
    conn.setState(STATE_CLOSED)
  }

  if(err != nil) {
    return 0, err
  }

  return size, nil
}

func (conn *PLUSConn) updateRemoteAddr(remoteAddr net.Addr) {
  conn.remoteAddr = remoteAddr
}

func (conn *PLUSConn) onNewPacketReceived(plusPacket *packet.PLUSPacket, remoteAddr net.Addr)  {

  conn.logger.Print(fmt.Sprintf("Received packet PSN := %d, PSE := %d", plusPacket.PSN(), plusPacket.PSE()))
  conn.logger.Print(plusPacket.Buffer())

  packetCAT := plusPacket.CAT()

  if(packetCAT != conn.cat) {
    // There's no sane sitution in which this can happen. 
    panic(fmt.Sprintf("Expected CAT %d but received packet with CAT %d!", conn.cat, packetCAT))
  }

  // Try to catch bogus packets where somebody sends bogus packets with random
  // PSNs. Obviously won't help much. The idea is that if we receive packet 5 then packet 3434344
  // and expected packet 6 then the packet 3434344 is probably a bogus one.
  distance := (mUint32 - uint64(conn.pse) + uint64(plusPacket.PSN())) % mUint32

  if(distance > uint64(conn.kMaxOutOfOrder)) {
    // drop the packet
    return
  }

  conn.updateRemoteAddr(remoteAddr)

  sendToChan := true

  switch conn.state {
  case STATE_ZERO: 
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
    // FIXME: Do we keep the packet?
    sendToChan = false
    break
  }

  if(sendToChan) {
    conn.inChannel <- plusPacket
  }
}

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

func (listener *PLUSListener) addConnection(cat uint64) (*PLUSConn)  {
  listener.logger.Print(fmt.Sprintf("addConnection: %d", cat))

  var plusConnection PLUSConn

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
  listener.connections[cat] = &plusConnection
  plusConnection.defaultLFlag = false
  plusConnection.defaultRFlag = false
  plusConnection.packetConn = listener.packetConn
  plusConnection.pse = 0
  plusConnection.psn = 1
  plusConnection.kMaxOutOfOrder = uint32(mUint32/2)

  plusConnection.logger = log.New(os.Stdout, fmt.Sprintf("Connection %d: ", cat), log.Lshortfile)

  return &plusConnection
}


func (listener *PLUSListener) Accept() (net.PacketConn, error) {
  listener.logger.Print("Waiting for new connection...")
  conn := <- listener.newConnections
  listener.logger.Print("New connection \\o/")
  return conn, nil
}

func (listener *PLUSListener) Close() error {
  // TODO: Close channels an all that stuff
  listener.logger.Print("Close()")
  return listener.packetConn.Close()
}

func (conn *PLUSConn) Close() error {
  // TODO: Maybe we need to do some cleanup?
  // FIXME: This is obviously bullshit because all PLUSConn from the server share
  //        the same packetConn. Maybe switch to channels?
  conn.logger.Print("Close()")
  return conn.packetConn.Close()
}

func (conn *PLUSConn) LocalAddr() net.Addr {
  return conn.packetConn.LocalAddr()
}

func (conn *PLUSConn) ReadFrom(b []byte) (int, net.Addr, error) {
  // NOTE: This function should have as little logic as necessary.
  //       All the protocol stuff should be done elsewhere. This is just a dummy
  //       wrapper around the channel.

  // TODO: Handle client IP address changes
  select {
    case plusPacket := <- conn.inChannel:

      n := copy(b, plusPacket.Payload())
      return n, nil, nil
  }

  return 0, nil, nil
}

func (conn *PLUSConn) WriteTo(b []byte, addr net.Addr) (int, error) {
  // NOTE: We're ignoring Addr here because PLUS takes care of IP address changes.
  //       Which means yeah... we override the address the overlaying layer wants stuff
  //       to send to. Also... all the protocol stuff should be done elsehwere.

  plusPacket := packet.NewBasicPLUSPacket(conn.defaultLFlag, conn.defaultLFlag, false,
                   conn.cat, conn.psn, conn.pse, b)

  return conn.sendPacket(plusPacket, len(b))
}

func (*PLUSConn) SetDeadline(t time.Time) error {
  return nil
}

func (*PLUSConn) SetReadDeadline(t time.Time) error {
  return nil
}

func (*PLUSConn) SetWriteDeadline(t time.Time) error {
  return nil
}
