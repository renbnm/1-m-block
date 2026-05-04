#include "tcp.h"
#include <cstdio>

Tcp::Tcp(const std::string r) {
	unsigned int port;
	int res = sscanf(r.c_str(), "%u", &port);
	if (res != 1 || port > 65535) {
		fprintf(stderr, "Tcp::Tcp sscanf return %d r=%s\n", res, r.c_str());
		return;
	}
	port_ = static_cast<uint16_t>(port);
}

Tcp::operator std::string() const {
	char buf[32]; // enough size
	sprintf(buf, "%u", port_);
	return std::string(buf);
}

#ifdef GTEST
#include <gtest/gtest.h>

TEST(Tcp, ctorTest) {
	Tcp tcp1; // Tcp()

	Tcp tcp2(80); // Tcp(const uint16_t r)

	Tcp tcp3("80"); // Tcp(const std::string r);

	EXPECT_EQ(tcp2, tcp3);
}

TEST(Tcp, castingTest) {
	Tcp tcp("443");

	uint16_t ui = tcp; // operator uint16_t() const
	EXPECT_EQ(ui, 443);

	std::string s = std::string(tcp); // explicit operator std::string()

	EXPECT_EQ(s, "443");
}

TEST(TcpHdr, basicTest) {
	TcpHdr hdr{};

	hdr.sport_ = htons(12345);
	hdr.dport_ = htons(80);
	hdr.seq_ = htonl(100);
	hdr.ack_ = htonl(200);
	hdr.off_rsvd_ = (5 << 4); // header length = 5 * 4 = 20
	hdr.flags_ = TcpHdr::SYN | TcpHdr::ACK;
	hdr.win_ = htons(4096);
	hdr.sum_ = htons(0x1234);
	hdr.urp_ = htons(0);

	EXPECT_EQ(uint16_t(hdr.sport()), 12345);
	EXPECT_EQ(uint16_t(hdr.dport()), 80);
	EXPECT_EQ(hdr.seq(), 100u);
	EXPECT_EQ(hdr.ack(), 200u);
	EXPECT_EQ(hdr.off(), 5);
	EXPECT_EQ(hdr.len(), 20);
	EXPECT_TRUE(hdr.syn());
	EXPECT_TRUE(hdr.ackFlag());
	EXPECT_FALSE(hdr.fin());
}

#endif // GTEST