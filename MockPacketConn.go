package PLUS

import "net"
import "time"

type MockPacketConn struct {
	DataToRead  []byte
	DataWritten []byte
	LocalAddr_  net.Addr
	RemoteAddr  net.Addr
}

func (c *MockPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n := copy(buffer, c.DataToRead)
	return n, c.RemoteAddr, nil
}

func (c *MockPacketConn) WriteTo(buffer []byte, remoteAddr net.Addr) (int, error) {
	c.DataWritten = make([]byte, len(buffer))
	n := copy(c.DataWritten, buffer)
	return n, nil
}

func (c *MockPacketConn) Close() error {
	return nil
}

func (c *MockPacketConn) LocalAddr() net.Addr {
	if c.LocalAddr_ != nil {
		return c.LocalAddr_
	}
	return &MockAddr{}
}

func (c *MockPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *MockPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *MockPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type MockAddr struct {
}

func (*MockAddr) Network() string {
	return ""
}

func (*MockAddr) String() string {
	return ""
}
