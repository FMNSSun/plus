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
			packetConn := &MockPacketConn { DataToRead : p.Buffer(), 
				DataWritten : nil, RemoteAddr: &MockAddr{} }
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
	})
})