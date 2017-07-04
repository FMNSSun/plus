package PLUS_test

import (
	. "plus"
	packet "plus/packet"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Plus", func() {
	Context("ConnectionManager", func() {
		It("Deals with new basic packets", func() {
			p := packet.NewBasicPLUSPacket(false, false, false, 1234, 11, 12, []byte{0x00})
			packetConn := NewMockPacketConn()
			packetConn.PutData(p.Buffer())
			manager := NewConnectionManager(packetConn)
			packet, addr, err := manager.ReadPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(packet).ToNot(Equal(nil))
			Expect(addr).ToNot(Equal(nil))

			conn, feedbackData, err := manager.ProcessPacket(p, addr)
			Expect(err).ToNot(HaveOccurred())
			Expect(conn).ToNot(Equal(nil))
			Expect(conn.CAT()).To(Equal(uint64(1234)))
			Expect(conn.PSE()).To(Equal(uint32(11)))

			var nilbuf []byte
			Expect(feedbackData).To(Equal(nilbuf))
		})

		It("Deals with new extended packets", func() {
			p, err := packet.NewExtendedPLUSPacket(false, false, false, 1234, 11, 12, 0x01, 0x00, []byte{0xCA,0xFE}, []byte{0xBA, 0xBE})

			Expect(err).ToNot(HaveOccurred())
			
			packetConn := NewMockPacketConn()
			packetConn.PutData(p.Buffer())
			manager := NewConnectionManager(packetConn)
			packet, addr, err := manager.ReadPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(packet).ToNot(Equal(nil))
			Expect(addr).ToNot(Equal(nil))

			conn, feedbackData, err := manager.ProcessPacket(p, addr)
			Expect(err).ToNot(HaveOccurred())
			Expect(conn).ToNot(Equal(nil))
			Expect(conn.CAT()).To(Equal(uint64(1234)))
			Expect(conn.PSE()).To(Equal(uint32(11)))

			Expect(feedbackData).To(Equal(p.Header()))
		})

		It("Deals with new extended packets with INTEGRITY_FULL", func() {
			p, err := packet.NewExtendedPLUSPacket(false, false, false, 1234, 11, 12, 0x01, 0x03, []byte{0xCA,0xFE}, []byte{0xBA, 0xBE})

			Expect(err).ToNot(HaveOccurred())
			
			packetConn := NewMockPacketConn()
			packetConn.PutData(p.Buffer())
			manager := NewConnectionManager(packetConn)
			packet, addr, err := manager.ReadPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(packet).ToNot(Equal(nil))
			Expect(addr).ToNot(Equal(nil))

			conn, feedbackData, err := manager.ProcessPacket(p, addr)
			Expect(err).ToNot(HaveOccurred())
			Expect(conn).ToNot(Equal(nil))
			Expect(conn.CAT()).To(Equal(uint64(1234)))
			Expect(conn.PSE()).To(Equal(uint32(11)))

			var nilbuf []byte
			Expect(feedbackData).To(Equal(nilbuf))
		})

		It("Deals with connections", func() {
			p := packet.NewBasicPLUSPacket(false, false, false, 1234, 11, 12, []byte{0x12, 0x21, 0x31, 0x13})
			packetConn := NewMockPacketConn()
			packetConn.PutData(p.Buffer())
			manager := NewConnectionManager(packetConn)
			go manager.Listen()
			conn := manager.Accept()
			buffer := make([]byte, 4096)
			n, err := conn.Read(buffer)

			Expect(err).ToNot(HaveOccurred())

			buffer = buffer[:n]
			
			Expect(buffer).To(Equal([]byte{0x12, 0x21, 0x31, 0x13}))

			p = packet.NewBasicPLUSPacket(false, false, false, 1234, 99, 88, []byte{0x33, 0x44, 0x55, 0x66})
			packetConn.PutData(p.Buffer())

			buffer = make([]byte, 4096)
			n, err = conn.Read(buffer)

			Expect(err).ToNot(HaveOccurred())
			
			buffer = buffer[:n]

			Expect(buffer).To(Equal([]byte{0x33, 0x44, 0x55, 0x66}))

			conn.Close()
			manager.Close()
		})
	})
})
