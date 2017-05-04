package conn

// About:
//  Some general very basic dummy tests.

import "testing"
import "net"
import "os"
import "time"
import "bytes"
import "fmt"

func setupServer(t *testing.T) *PLUSListener {
	listener, err := ListenPLUS("127.0.0.1:15000")

	if err != nil {
		t.Errorf("Failed to ListenPLUS: %s", err.Error())
		return nil
	}

	return listener
}

func teardownServer(t *testing.T, listener *PLUSListener) {
	listener.Close()
	time.Sleep(1000 * time.Millisecond)
}

func setupClient(t *testing.T) *PLUSConn {
	adr, err := net.ResolveUDPAddr("udp", "127.0.0.1:15000")

	if err != nil {
		t.Errorf("Failed to resolve addr: %s", err.Error())
		return nil
	}

	connection, err_ := DialPLUS("127.0.0.1:15001", adr)

	if err_ != nil {
		t.Errorf("Failed to DialPLUS")
		return nil
	}

	return connection
}

func teardownClient(t *testing.T, conn *PLUSConn) {
	conn.Close()
	time.Sleep(1000 * time.Millisecond)
}

func TestCreateListener(t *testing.T) {
	t.Log("TestCreateListener")
	server := setupServer(t)
	defer teardownServer(t, server)
	os.Stdout.Sync()
}

func TestCreateClient(t *testing.T) {
	t.Log("TestCreateClient")
	client := setupClient(t)
	defer teardownClient(t, client)
	os.Stdout.Sync()
}

func pingPong(t *testing.T, connA net.PacketConn, connB net.PacketConn, payload []byte) {
	sendBuf := payload

	os.Stdout.Sync()

	fmt.Printf("Sending payload %x\n", sendBuf)

	n, err := connA.WriteTo(sendBuf, nil)

	if err != nil {
		t.Errorf("WriteTo failed: %s", err.Error())
		return
	}

	if n != len(sendBuf) {
		t.Errorf("Expected to write %d bytes but written were %d bytes", len(sendBuf), n)
		return
	}

	recvBuf := make([]byte, len(payload))

	fmt.Println("Wait for data (A -> B)")

	n, _, err = connB.ReadFrom(recvBuf)

	fmt.Printf("Received payload %x\n", recvBuf)

	if err != nil {
		t.Errorf("ReadFrom failed: %s", err.Error())
		return
	}

	if n != len(recvBuf) {
		t.Errorf("Expected to read %d bytes but written were %d bytes", len(recvBuf), n)
		return
	}

	if !bytes.Equal(sendBuf, recvBuf) {
		t.Errorf("Data went wrong!")
		fmt.Println(sendBuf)
		fmt.Println(recvBuf)
		return
	}

	n, err = connB.WriteTo(sendBuf, nil)

	if err != nil {
		t.Errorf("WriteTo failed: %s", err.Error())
		return
	}

	if n != len(sendBuf) {
		t.Errorf("Expected to write %d bytes but written were %d bytes", len(sendBuf), n)
		return
	}

	recvBuf = make([]byte, len(payload))

	fmt.Println("Wait for data (B -> A)")

	n, _, err = connA.ReadFrom(recvBuf)

	fmt.Printf("Received payload %x\n", recvBuf)

	if err != nil {
		t.Errorf("ReadFrom failed: %s", err.Error())
		return
	}

	if n != len(recvBuf) {
		t.Errorf("Expected to read %d bytes but written were %d bytes", len(recvBuf), n)
		return
	}

	if !bytes.Equal(sendBuf, recvBuf) {
		t.Errorf("Data went wrong!")
		fmt.Println(sendBuf)
		fmt.Println(recvBuf)
		return
	}

	fmt.Println("Round done")
}

func TestPingPong(t *testing.T) {
	fmt.Println("PingPong")

	os.Stdout.Sync()

	server := setupServer(t)
	client := setupClient(t)

	defer teardownServer(t, server)
	defer teardownClient(t, client)

	if server == nil || client == nil {
		t.Errorf("BUG")
		return
	}

	sendBuf := []byte{1, 2, 10, 20}

	os.Stdout.Sync()

	fmt.Printf("Sending payload %x\n", sendBuf)

	n, err := client.WriteTo(sendBuf, nil)

	if err != nil {
		t.Errorf("WriteTo failed: %s", err.Error())
		return
	}

	if n != len(sendBuf) {
		t.Errorf("Expected to write %d bytes but written were %d bytes", len(sendBuf), n)
		return
	}

	recvBuf := []byte{0, 0, 0, 0}

	serverConn, err := server.Accept()

	if serverConn == nil {
		t.Errorf("BUG")
		return
	}

	if err != nil {
		t.Errorf("Accept failed!")
		return
	}

	n, _, err = serverConn.ReadFrom(recvBuf)

	fmt.Printf("Received payload %x\n", recvBuf)

	if err != nil {
		t.Errorf("ReadFrom failed: %s", err.Error())
		return
	}

	if n != len(recvBuf) {
		t.Errorf("Expected to read %d bytes but written were %d bytes", len(recvBuf), n)
		return
	}

	if !bytes.Equal(sendBuf, recvBuf) {
		t.Errorf("Data went wrong!")
		fmt.Println(sendBuf)
		fmt.Println(recvBuf)
		return
	}

	pingPong(t, serverConn, client, []byte{99, 88, 00, 88, 13, 17, 255, 255, 0, 1})
}

func TestSendRecvDummyPacket(t *testing.T) {
	fmt.Println("SendRecvDummyPacket")

	os.Stdout.Sync()

	server := setupServer(t)
	client := setupClient(t)

	defer teardownServer(t, server)
	defer teardownClient(t, client)

	if server == nil || client == nil {
		t.Errorf("BUG")
		return
	}

	sendBuf := []byte{1, 2, 10, 20}

	os.Stdout.Sync()

	fmt.Printf("Sending payload %x\n", sendBuf)

	n, err := client.WriteTo(sendBuf, nil)

	if err != nil {
		t.Errorf("WriteTo failed: %s", err.Error())
		return
	}

	if n != len(sendBuf) {
		t.Errorf("Expected to write %d bytes but written were %d bytes", len(sendBuf), n)
		return
	}

	recvBuf := []byte{0, 10, 0, 10}

	serverConn, err := server.Accept()

	if serverConn == nil {
		t.Errorf("BUG")
		return
	}

	if err != nil {
		t.Errorf("Accept failed!")
		return
	}

	n, _, err = serverConn.ReadFrom(recvBuf)

	fmt.Printf("Received payload %x\n", recvBuf)

	if err != nil {
		t.Errorf("ReadFrom failed: %s", err.Error())
		return
	}

	if n != len(recvBuf) {
		t.Errorf("Expected to read %d bytes but read were %d bytes", len(recvBuf), n)
		return
	}

	if !bytes.Equal(sendBuf, recvBuf) {
		t.Errorf("Data went wrong!")
		fmt.Println(sendBuf)
		fmt.Println(recvBuf)
		return
	}
}
