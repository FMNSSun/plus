package conn

import "testing"
import "net"

// About:
//  Tests the invocation of the SignAndEncrypt and ValidateAndDecrypt
//  callbacks.

func dummyProtocol_SignAndEncrypt(conn *PLUSConn, header []byte, data []byte) ([]byte, error) {
  encrypted := make([]byte, len(data))
  for i := range data {
    encrypted[i] = data[i] ^ 0x3B
  }
  return encrypted, nil
}

func dummyProtocol_ValidateAndDecrypt(conn *PLUSConn, header []byte, data []byte) ([]byte, error) {
  decrypted := make([]byte, len(data))
  for i := range data {
    decrypted[i] = data[i] ^ 0x3B
  }
  return decrypted, nil
}

func dummyProtocol_SetupServer(t *testing.T) *PLUSListener {
  listener, err := ListenPLUSAware("127.0.0.1:15000", dummyProtocol_mkPLUSInterface)

  if(err != nil) {
    t.Errorf("Failed to ListenPLUS: %s", err.Error())
    return nil
  }

  return listener
}

func dummyProtocol_mkPLUSInterface(conn *PLUSConn) *PLUSInterface {
  var plusInterface PLUSInterface;
  plusInterface.SignAndEncrypt = dummyProtocol_SignAndEncrypt
  plusInterface.ValidateAndDecrypt = dummyProtocol_ValidateAndDecrypt
  return &plusInterface
}

func dummyProtocol_SetupClient(t *testing.T) *PLUSConn {
  adr, err := net.ResolveUDPAddr("udp", "127.0.0.1:15000")

  if(err != nil) {
    t.Errorf("Failed to resolve addr: %s", err.Error())
    return nil
  }

  connection, err_ := DialPLUSAware("127.0.0.1:15001", adr, dummyProtocol_mkPLUSInterface)

  if(err_ != nil) {
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

  if(server == nil || client == nil) {
    t.Errorf("BUG")
    return
  }

  // This is necessary for the server to create a new connection.
  // The connection is created (and can be retrieved by Accept()) once
  // a packet is received. 
  buf := []byte{}
  client.WriteTo(buf, nil)

  serverConn, err := server.Accept()

  if(serverConn == nil) {
    t.Errorf("BUG")
    return
  }

  if(err != nil) {
    t.Errorf("Accept failed!")
    return
  }

  serverConn.ReadFrom(buf)

  pingPong(t, serverConn, client, []byte{0xCA, 0xFE, 0xBA, 0xBE})
}
