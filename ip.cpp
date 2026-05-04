#include "ip.h"
#include <cstdio>

Ip::Ip(const std::string r) {
	unsigned int a, b, c, d;
	int res = sscanf(r.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
	if (res != Size) {
		fprintf(stderr, "Ip::Ip sscanf return %d r=%s\n", res, r.c_str());
		return;
	}
	ip_ = (a << 24) | (b << 16) | (c << 8) | d;
}

Ip::operator std::string() const {
	char buf[32]; // enough size
	sprintf(buf, "%u.%u.%u.%u",
		(ip_ & 0xFF000000) >> 24,
		(ip_ & 0x00FF0000) >> 16,
		(ip_ & 0x0000FF00) >> 8,
		(ip_ & 0x000000FF));
	return std::string(buf);
}

#ifdef GTEST
#include <gtest/gtest.h>

TEST(Ip, ctorTest) {
	Ip ip1; // Ip()

	Ip ip2(0x7F000001); // Ip(const uint32_t r)

	Ip ip3("127.0.0.1"); // Ip(const std::string r);

	EXPECT_EQ(ip2, ip3);
}

TEST(Ip, castingTest) {
	Ip ip("127.0.0.1");

	uint32_t ui = ip; // operator uint32_t() const
	EXPECT_EQ(ui, 0x7F000001);

	std::string s = std::string(ip); // explicit operator std::string()

	EXPECT_EQ(s, "127.0.0.1");
}

TEST(IpHdr, basicTest) {
	IpHdr hdr{};

	hdr.v_hl_ = (4 << 4) | 5;
	hdr.tlen_ = htons(40);
	hdr.id_ = htons(1);
	hdr.off_ = htons(0);
	hdr.ttl_ = 64;
	hdr.p_ = IpHdr::TCP;
	hdr.sum_ = htons(0x1234);
	hdr.sip_ = htonl(0x7F000001);
	hdr.dip_ = htonl(0x08080808);

	EXPECT_EQ(hdr.version(), 4);
	EXPECT_EQ(hdr.hl(), 5);
	EXPECT_EQ(hdr.hlen(), 20);
	EXPECT_EQ(hdr.tlen(), 40);
	EXPECT_EQ(hdr.p(), IpHdr::TCP);
	EXPECT_EQ(std::string(hdr.sip()), "127.0.0.1");
	EXPECT_EQ(std::string(hdr.dip()), "8.8.8.8");
}

#endif // GTEST