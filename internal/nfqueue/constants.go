package nfqueue

type Packet struct {
	// Unique ID assigned by the kernel for this packet inside the NFQUEUE.
	//
	// Must send this back when you issue a verdict (ACCEPT/DROP).
	PacketID uint32

	// The actual packet data.
	//
	// Starts at Layer 3 (IP header), not Ethernet.
	Payload []byte

	// The IP version.
	//
	// Either 4 (IPv4) or 6 (IPv6).
	IPVersion uint32
}
