package conn

import "net"
import "plus/packet"
import "fmt"
import "log"
import "os"
import "sync"

// Utility type to feed back validation errors
// to ReadFrom
type inPacket struct {
	packet *packet.PLUSPacket
	err    error
}

func newInPacket(packet *packet.PLUSPacket, err error) inPacket {
	var ip inPacket
	ip.packet = packet
	ip.err = err
	return ip
}

type PLUSListener struct {
	packetConn     net.PacketConn
	connections    map[uint64]*PLUSConn
	newConnections chan *PLUSConn
	serverMode     bool
	logger         *log.Logger
	initConn       func(*PLUSConn) error
}

const maxPacketSize int = 4096

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
	switch state {
	case STATE_ZERO:
		return "ZERO"
	case STATE_UNIFLOW_RECV:
		return "UNIFLOW_RECV"
	case STATE_UNIFLOW_SENT:
		return "UNIFLOW_SENT"
	case STATE_ASSOCIATING:
		return "ASSOCIATING"
	case STATE_ASSOCIATED:
		return "ASSOCIATED"
	case STATE_STOP_SENT:
		return "STOP_SENT"
	case STATE_STOP_RECV:
		return "STOP_RECV"
	case STATE_CLOSED:
		return "CLOSED"
	}
	return "N/A"
}

// Create a PLUS server listening on laddr
func ListenPLUSAware(laddr string, initConn func(*PLUSConn) error) (*PLUSListener, error) {
	packetConn, err := net.ListenPacket("udp", laddr)

	if err != nil {
		return nil, err
	}

	return ListenPLUSWithPacketConn(packetConn, initConn)
}

func ListenPLUSWithPacketConn(packetConn net.PacketConn, initConn func(*PLUSConn) error) (*PLUSListener, error) {
	var plusListener PLUSListener
	plusListener.logger = log.New(os.Stdout, "Listener (true): ", log.Lshortfile)
	plusListener.packetConn = packetConn
	plusListener.serverMode = true
	plusListener.connections = make(map[uint64]*PLUSConn)
	plusListener.newConnections = make(chan *PLUSConn)
	plusListener.initConn = initConn

	go plusListener.listen()

	return &plusListener, nil
}

// Create a PLUS server listening on laddr
func ListenPLUS(laddr string) (*PLUSListener, error) {
	return ListenPLUSAware(laddr, nil)
}

// This listens on the internal packet connection for new packets, tries to
// parse them as a PLUS packet and creates new connection if packets with
// new CAT arrive.
func (listener *PLUSListener) listen() {
	listener.logger.Print(fmt.Sprintf("listen() on %s", listener.packetConn.LocalAddr().String()))

	// We can re-use this buffer because PLUSPacket copies the buffer
	buffer := make([]byte, maxPacketSize)
	for {
		listener.logger.Print("listen: ReadFrom")
		n, remoteAddr, err := listener.packetConn.ReadFrom(buffer)
		listener.logger.Print("Read.")

		if err != nil {
			// TODO: Close connections/signal close
			listener.logger.Printf("Reading from packetConn failed: %s", err.Error())
			return
		} else {
			plusPacket, err := packet.NewPLUSPacket(buffer[:n])

			if err != nil {
				// Drop packets that aren't PLUS packets
				listener.logger.Print("Parsing packet failed.")
			} else {

				plusConnection, ok := listener.connections[plusPacket.CAT()]

				if !ok {
					if listener.serverMode {
						plusConnection = listener.addConnection(plusPacket.CAT())
					} else {
						// Invalid CAT. Drop packet.
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
func (listener *PLUSListener) addConnection(cat uint64) *PLUSConn {
	listener.logger.Print(fmt.Sprintf("addConnection: %d", cat))

	var plusConnection PLUSConn

	plusConnection.mutex = &sync.RWMutex{}
	plusConnection.mutex.Lock()

	/* Server mode or client mode? */
	if listener.serverMode {
		plusConnection.state = STATE_UNIFLOW_RECV
		listener.logger.Print(fmt.Sprintf("addConnection: write to chan"))
		listener.newConnections <- &plusConnection
		listener.logger.Print(fmt.Sprintf("addConnection: wrote to chan"))
	} else {
		plusConnection.state = STATE_ZERO
	}

	plusConnection.inChannel = make(chan inPacket, 10)
	plusConnection.cat = cat
	plusConnection.defaultLFlag = false
	plusConnection.defaultRFlag = false
	plusConnection.packetConn = listener.packetConn
	plusConnection.pse = 0
	plusConnection.psn = 1
	plusConnection.logger = log.New(os.Stdout, fmt.Sprintf("Connection %d: ", cat), log.Lshortfile)
	plusConnection.dropInvalidPackets = true

	listener.connections[cat] = &plusConnection

	plusConnection.mutex.Unlock()

	if listener.initConn != nil {
		listener.initConn(&plusConnection)
	}

	return &plusConnection
}

// Wait for a new connection and return it. Blocks forever.
// A connection is considered a new connection if a packet
// with a new CAT in the PLUS header is received.
func (listener *PLUSListener) Accept() (net.PacketConn, error) {
	listener.logger.Print("Waiting for new connection...")
	conn := <-listener.newConnections
	listener.logger.Print("New connection \\o/")
	return conn, nil
}

// Closes this listener.
func (listener *PLUSListener) Close() error {
	// TODO: Close channels an all that stuff
	listener.logger.Print("Close()")
	return listener.packetConn.Close()
}
