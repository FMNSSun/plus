# How to integrate plus-lib

The plus-lib offers a multitude of ways to use it depending on your exact needs.
It also offers a connections implementing the net.Conn interface (with the exception
of the Set*Deadline functions) which allows transparent use of PLUS with the
exception that feedback handling can not be done using the net.Conn interface (because
the net.Conn interface provides no such functions). 

PLUS offers a high-level interface and a low-level interface and it even allows use of
both of them at the same time. In the high-level interface PLUS also handles connection
multiplexing automatically.

## High-Level Interface

### Server

To create a `ConnectionManager` we need to create a `net.PacketConn` first...

```go
packetConn, err := net.ListenPacket("udp", addr)
```

... then we create the `ConnectionManager` ...

```go
connectionManager := PLUS.NewConnectionManager(packetConn)
```

... and finally we put it into listen mode.

```go
go connectionManager.Listen()
```

In listen mode plus-lib will automatically read and process packets from the underlying packet
connection, will handle connection multiplexing, will handle encryption and decryption as well
as integrity protection and verification. Once the `ConnectionManager` is in listen mode we
can start to accept new connections:

```go
connection := connectionManager.Accept()
```

This wil return a new connection that we can use Read and Write functions on:

```go
// Read data from the connection
buffer := make([]byte, 8129)
n, err := connection.Read(buffer)
buffer = buffer[:n]

// Echo it back
_, err = connection.Write(buffer)
```

### Client

For the client we need to create a `ConnectionManager` as well but this time a `ConnectionManager` in
client mode:

```go
cat := PLUS.RandomCAT()
connectionManager, connection := PLUS.NewConnectionManagerClient(packetConn, cat, udpAddr)
```

You can set a cat manually however it is HIGHLY recommended to generate it using the `RandomCAT()` function
provided by the plus-lib.

Then we need to set it into listen mode too:

```go
go connectionManager.Listen()
```

And then we can use the connection's Write and Read functions:

```go
_, err = connection.Write(buffer)
```

## Encryption/Decryption

If a `CryptoContext` is configured plus-lib will perform encryption and decryption using the `CryptoContext`.
If you call `Write` or `Read` on the connection the data will be fed through the `CryptoContext`. If the connection
is NOT listen mode then `Read` can not be used. If not in listen mode the `DecryptAndValidate(packet)` function
may be used. 

### CryptoContext

You can set a `CryptoContext` for the connection to use. If none is set no encryption/decryption will be performed.
It's recommended to set the `CryptoContext` during the `InitConn` callback:

```go
type cryptoContext struct {
	key byte
}

func (c *cryptoContext) EncryptAndProtect(header []byte, payload []byte) ([]byte, error) {
	for i, v := range payload {
		payload[i] = v ^ c.key
	}

	return payload, nil
}

func (c *cryptoContext) DecryptAndValidate(header []byte, payload []byte) ([]byte, bool, error) {
	for i, v := range payload {
		payload[i] = v ^ c.key
	}

	return payload, true, nil
}

connectionManager.SetInitConn(func(conn *PLUS.Connection) error {
		conn.SetSFlag(true)
		conn.SetCryptoContext(&cryptoContext{key:0x3B})
		return nil
	})
```

Do not use this specific implementation of a `CryptoContext` in practice, this is just to showcase the interface
of the `CryptoContext`. 

The functions of the `CryptoContext` may write directly to the buffer they receive (act in-place) or they may
return a new buffer (not in-place). However, you need to exactly know what you're doing and know exactly who
holds references to which buffers. To avoid allocating too many buffers it's possible to pass a buffer
to the `Write` function that is large enough to also hold the encrypted and integrity protected data. 

## Low-Level interface

The plus-lib also offers raw functions such as the `ReadAndProcessPacket` which will read and process a packet
from the underlying packet connection. It's also possible to invoke `Read` and then feed this to the `ProcessPacket` function. `ReadAndProcessPacket` is merely a wrapper that does both. To send packets
one can use the `PrepareNextPacket` or the `PrepareNextPacketRaw` function which prepares a packet with
an empty payload then one can set the payload using the packet's `SetPayload` function and use the connection
managers `WritePacket` function. Since plus-lib makes use of packet and buffer pools they may be returned
to be re-used. This is strictly speaking optional because if you don't the garbage collector will delete them
and the pools will create new ones but to avoid too much strain on the gc they may be returned to plus-lib for reuse using the `ReturnPacketAndBuffer` (or the `ReturnPacket`, `ReturnBuffer`) function. If you're using the `ReadPacket` function you should call `ReturnPacketAndBuffer`, if you're using the `ReadPacketUsing` function you
can supply your own buffer in which case you should only call `ReturnPacket` but not `ReturnBuffer`. 
The `PrepareNextPacketRaw` allows you to supply your own buffer as well which needs to be at least large enough
to hold the PLUS header. This is the recommended way because it does not allocate a packet where as `PrepareNextPacket` allocates a new packet. 

Example usages for receiving:

```go
plusConnection, plusPacket, remoteAddr, feedbackData, err := plusConnManager.ReadAndProcessPacket()
payload := plusPacket.Payload()
// process payload and feedbackData
plusConnManager.ReturnPacketAndBuffer(plusPacket)
```

Please be aware that should you make use of feedbackData and payload after the `ReturnPacketAndBuffer` call
you're in trouble because they may have already been used. 

Example usages for sending:

```go
psn, headerLen, err := connectionManager.PrepareNextPacketRaw(buf)
payload := buf[headerLen:]
// write stuf into payload
packetConn.WriteTo(buf, addr) // write a raw []byte packet
```
