package conn

import "testing"
import "net"
import "fmt"

// About:
//  Tests the invocation of the SignAndEncrypt and ValidateAndDecrypt
//  callbacks.


type dummyProtocol_CryptoContext struct {
	key byte
}

func (ctx *dummyProtocol_CryptoContext) EncryptAndProtect(header []byte, data []byte) ([]byte, error) {
	fmt.Println("SignAndEncrypt")
	encrypted := make([]byte, len(data))
	for i := range data {
		encrypted[i] = data[i] ^ ctx.key
	}
	return encrypted, nil
}

func (ctx *dummyProtocol_CryptoContext) DecryptAndValidate(header []byte, data []byte) ([]byte, error) {
	fmt.Println("ValidateAndDecrypt")
	decrypted := make([]byte, len(data))
	for i := range data {
		decrypted[i] = data[i] ^ ctx.key
	}
	return decrypted, nil
}

func dummyProtocol_initConn(conn *PLUSConn) error {
	ctx := dummyProtocol_CryptoContext{key: 0x3B}
	conn.SetCryptoContext(&ctx)
	return nil
}

func dummyProtocol_SetupServer(t *testing.T) *PLUSListener {
	listener, err := ListenPLUSAware("127.0.0.1:15000", true, dummyProtocol_initConn)

	if err != nil {
		t.Errorf("Failed to ListenPLUS: %s", err.Error())
		return nil
	}

	return listener
}

func dummyProtocol_SetupClient(t *testing.T) *PLUSConn {
	adr, err := net.ResolveUDPAddr("udp", "127.0.0.1:15000")

	if err != nil {
		t.Errorf("Failed to resolve addr: %s", err.Error())
		return nil
	}

	connection, err_ := DialPLUSAware("127.0.0.1:15001", adr, dummyProtocol_initConn)

	if err_ != nil {
		t.Errorf("Failed to DialPLUS")
		return nil
	}

	return connection
}

func TestDummyProtocol(t *testing.T) {

	t.Log("TestDummyProtocol")

	server := dummyProtocol_SetupServer(t)
	client := dummyProtocol_SetupClient(t)

	defer teardownServer(t, server)
	defer teardownClient(t, client)

	if server == nil || client == nil {
		t.Errorf("BUG")
		return
	}

	// This is necessary for the server to create a new connection.
	// The connection is created (and can be retrieved by Accept()) once
	// a packet is received.
	buf := []byte{}
	client.WriteTo(buf, nil)

	serverConn, err := server.Accept()

	if serverConn == nil {
		t.Errorf("BUG")
		return
	}

	if err != nil {
		t.Errorf("Accept failed!")
		return
	}

	serverConn.ReadFrom(buf)

	pingPong(t, serverConn, client, []byte{0xCA, 0xFE, 0xBA, 0xBE})
}

