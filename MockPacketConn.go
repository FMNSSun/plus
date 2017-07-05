package PLUS

import "net"
import "time"
import "fmt"

type MockPacketConn struct {
	DataToRead  chan []byte
   DataWritten chan []byte
	LocalAddr_  net.Addr
	RemoteAddr  net.Addr
}

func NewMockPacketConn() *MockPacketConn {
	mpc := &MockPacketConn{}
	mpc.LocalAddr_ = &MockAddr{}
	mpc.RemoteAddr = &MockAddr{}
	mpc.DataToRead = make(chan []byte, 16)
	mpc.DataWritten = make(chan []byte, 16)
	return mpc
}

func (c *MockPacketConn) PutData(buffer []byte) (int, error) {
	fmt.Println("PUTDATA")
	data := make([]byte, len(buffer))
   n := copy(data, buffer)
	c.DataToRead <- data
	fmt.Println("PUTDATA:", data)
	return n, nil
}

func (c *MockPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	fmt.Println("READDATA")
	data := <- c.DataToRead
	fmt.Println("GOTDATA:", data)
	n := copy(buffer, data)
	return n, c.RemoteAddr, nil
}

func (c *MockPacketConn) WriteTo(buffer []byte, remoteAddr net.Addr) (int, error) {
	fmt.Println("WRITEDATA")
	data := make([]byte, len(buffer))
	n := copy(data, buffer)
	c.DataWritten <- data
	fmt.Println("WRITTENDATA:", data)
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
