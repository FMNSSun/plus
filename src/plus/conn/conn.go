package conn

import "net"
import "time"
import "plus/packet"

type PLUSListener struct {
  packetConn net.PacketConn
  plusConnections map[uint64]*PLUSConn
}

type PLUSConn struct {
  inChannel chan *packet.PLUSPacket
  state uint16
  cat uint64
}

const maxPacketSize int = 4096
const STATE_ZERO uint16 = 0

func ListenPLUS(laddr string) (*PLUSListener, error) {
  packetConn, err := net.ListenPacket("udp", laddr)
  
  if(err != nil) {
    return nil, err
  }

  var plusListener PLUSListener
  plusListener.packetConn = packetConn

  go plusListener.listen()

  return &plusListener, nil
}

func (listener *PLUSListener) listen() {
  buffer := make([]byte, maxPacketSize)
  for {
    _, _, err := listener.packetConn.ReadFrom(buffer)

    if(err != nil) {
      // FIXME: What the f*ck do we do here?
    } else {
      plusPacket, err := packet.NewPLUSPacket(buffer)

      if(err != nil) {
        // FIXME: What the f*ck do we do here?
      } else {

        plusConnection, ok := listener.plusConnections[plusPacket.CAT()]

        if(!ok) {
          plusConnection = listener.addConnection(plusPacket.CAT())
        }

        plusConnection.inChannel <- plusPacket
      }
    }
  }
}

func (listener *PLUSListener) addConnection(cat uint64) (*PLUSConn)  {
  var plusConnection PLUSConn
  plusConnection.state = STATE_ZERO
  plusConnection.inChannel = make(chan *packet.PLUSPacket)
  plusConnection.cat = cat
  listener.plusConnections[cat] = &plusConnection
  return &plusConnection
}

func (*PLUSListener) Accept() (net.PacketConn, error) {

  var plusConn PLUSConn

  return &plusConn, nil
}

func (*PLUSConn) Close() error {
  return nil
}

func (*PLUSConn) LocalAddr() net.Addr {
  return nil
}

func (conn *PLUSConn) ReadFrom(b []byte) (int, net.Addr, error) {
  // TODO: Handle client IP address changes
  select {
    case <- conn.inChannel:
      plusPacket := <- conn.inChannel
      n := copy(b, plusPacket.Payload())
      return n, nil, nil
  }

  return 0, nil, nil
}

func (*PLUSConn) WriteTo(b []byte, addr net.Addr) (int, error) {
  return 0, nil
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
