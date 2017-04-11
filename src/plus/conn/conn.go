package conn

import "net"
import "time"

type PLUSListener struct {
  packetConn net.PacketConn
}

type PLUSConn struct {
}

func ListenPLUS(laddr string) (*PLUSListener, error) {
  packetConn, err := net.ListenPacket("udp", laddr)
  
  if(err != nil) {
    return nil, err
  }

  var plusListener PLUSListener
  plusListener.packetConn = packetConn  

  return &plusListener, nil
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

func (*PLUSConn) ReadFrom(b []byte) (int, net.Addr, error) {
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
