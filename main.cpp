#include <arpa/inet.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_set>

#include "ip.h"
#include "tcp.h"

using namespace std;

static unordered_set<string> blocked_sites;
static volatile sig_atomic_t stop_program = 0;
static bool rule_installed = false;

static const uint16_t QUEUE_NUM = 0;
static const uint16_t HTTP_PORT = 80;

static string normalize_host(string host) {
	size_t start = 0;
	while (start < host.size() && isspace(static_cast<unsigned char>(host[start]))) start++;
	size_t end = host.size();
	while (end > start && isspace(static_cast<unsigned char>(host[end - 1]))) end--;
	host = host.substr(start, end - start);

	if (host.empty()) return "";

	size_t pos = host.find("://");
	if (pos != string::npos) host = host.substr(pos + 3);

	pos = host.find('/');
	if (pos != string::npos) host = host.substr(0, pos);

	pos = host.find('?');
	if (pos != string::npos) host = host.substr(0, pos);

	pos = host.find('#');
	if (pos != string::npos) host = host.substr(0, pos);

	for (char& c : host) {
		c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
	}

	if (!host.empty() && host.back() == '.') {
		host.pop_back();
	}

	if (!host.empty() && host.front() == '[') {
		size_t bracket_end = host.find(']');
		if (bracket_end != string::npos) {
			host = host.substr(0, bracket_end + 1);
		}
	} else {
		size_t colon = host.find(':');
		if (colon != string::npos) {
			host = host.substr(0, colon);
		}
	}

	start = 0;
	while (start < host.size() && isspace(static_cast<unsigned char>(host[start]))) start++;
	end = host.size();
	while (end > start && isspace(static_cast<unsigned char>(host[end - 1]))) end--;
	host = host.substr(start, end - start);

	return host;
}

static void cleanup_rule() {
	if (!rule_installed) return;
	system("iptables -D OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0 > /dev/null 2>&1");
	rule_installed = false;
}

static void signal_handler(int) {
	stop_program = 1;
}

static int callback(struct nfq_q_handle* qh, struct nfgenmsg*, struct nfq_data* nfa, void*) {
	uint32_t id = 0;
	struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
	if (ph != nullptr) {
		id = ntohl(ph->packet_id);
	}

	unsigned char* data = nullptr;
	int len = nfq_get_payload(nfa, &data);

	if (len < 0 || data == nullptr) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
	}

	if (len < IpHdr::MinSize) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
	}

	const IpHdr* ipHdr = reinterpret_cast<const IpHdr*>(data);

	if (ipHdr->version() != 4) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
	}

	if (ipHdr->p() != IpHdr::TCP) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
	}

	int ipHeaderLen = ipHdr->hlen();
	if (ipHeaderLen < IpHdr::MinSize) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
	}

	if (len < ipHeaderLen + TcpHdr::MinSize) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
	}

	const TcpHdr* tcpHdr = reinterpret_cast<const TcpHdr*>(data + ipHeaderLen);

	int tcpHeaderLen = tcpHdr->len();
	if (tcpHeaderLen < TcpHdr::MinSize) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
	}

	if (len < ipHeaderLen + tcpHeaderLen) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
	}

	if (uint16_t(tcpHdr->dport()) != HTTP_PORT) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
	}

	const char* payload = reinterpret_cast<const char*>(data + ipHeaderLen + tcpHeaderLen);
	int payload_len = len - ipHeaderLen - tcpHeaderLen;

	if (payload_len <= 0) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
	}

	string http_data(payload, payload_len);
	string host;

	auto ieq = [](char a, char b) {
		return tolower(static_cast<unsigned char>(a)) ==
		       tolower(static_cast<unsigned char>(b));
	};

	string key1 = "\r\nHost:";
	auto it = search(http_data.begin(), http_data.end(), key1.begin(), key1.end(), ieq);

	size_t start = string::npos;

	if (it != http_data.end()) {
		start = static_cast<size_t>(distance(http_data.begin(), it)) + key1.size();
	} else {
		string key2 = "Host:";
		auto it2 = search(http_data.begin(), http_data.end(), key2.begin(), key2.end(), ieq);

		if (it2 == http_data.end()) {
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
		}

		size_t pos = static_cast<size_t>(distance(http_data.begin(), it2));
		if (pos != 0 && http_data[pos - 1] != '\n') {
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
		}

		start = pos + key2.size();
	}

	while (start < http_data.size() && (http_data[start] == ' ' || http_data[start] == '\t')) {
		start++;
	}

	size_t end = start;
	while (end < http_data.size() && http_data[end] != '\r' && http_data[end] != '\n') {
		end++;
	}

	if (end <= start) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
	}

	host = normalize_host(http_data.substr(start, end - start));
	if (host.empty()) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
	}

	string current = host;
	while (true) {
		if (blocked_sites.find(current) != blocked_sites.end()) {
			cout << "[BLOCK] " << host << '\n';
			return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
		}

		size_t dot = current.find('.');
		if (dot == string::npos) break;
		current = current.substr(dot + 1);
	}

	if (host.rfind("www.", 0) == 0 && host.size() > 4) {
		current = host.substr(4);

		while (true) {
			if (blocked_sites.find(current) != blocked_sites.end()) {
				cout << "[BLOCK] " << host << '\n';
				return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
			}

			size_t dot = current.find('.');
			if (dot == string::npos) break;
			current = current.substr(dot + 1);
		}
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		cerr << "syntax : 1m-block <site list file>\n";
		cerr << "sample : 1m-block top-1m.csv\n";
		return 1;
	}

	if (geteuid() != 0) {
		cerr << "run with sudo\n";
		return 1;
	}

	ifstream file(argv[1]);
	if (!file.is_open()) {
		cerr << "failed to open file: " << argv[1] << '\n';
		return 1;
	}

	string line;
	size_t loaded_lines = 0;

	while (getline(file, line)) {
		size_t start = 0;
		while (start < line.size() && isspace(static_cast<unsigned char>(line[start]))) start++;
		size_t end = line.size();
		while (end > start && isspace(static_cast<unsigned char>(line[end - 1]))) end--;
		line = line.substr(start, end - start);

		if (line.empty()) continue;
		if (line[0] == '#') continue;

		string host = line;

		size_t comma = line.find(',');
		if (comma != string::npos) {
			host = line.substr(comma + 1);
		}

		host = normalize_host(host);
		if (host.empty()) continue;

		blocked_sites.insert(host);

		if (host.rfind("www.", 0) == 0 && host.size() > 4) {
			blocked_sites.insert(host.substr(4));
		}

		loaded_lines++;
	}

	cout << "[*] loaded lines: " << loaded_lines << '\n';
	cout << "[*] loaded hosts in set: " << blocked_sites.size() << '\n';

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	atexit(cleanup_rule);

	system("iptables -D OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0 > /dev/null 2>&1");
	int ret = system("iptables -I OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0 > /dev/null 2>&1");
	if (ret != 0) {
		cerr << "failed to install iptables rule\n";
		return 1;
	}
	rule_installed = true;

	struct nfq_handle* h = nfq_open();
	if (h == nullptr) {
		cerr << "nfq_open() failed\n";
		return 1;
	}

	nfq_unbind_pf(h, AF_INET);

	if (nfq_bind_pf(h, AF_INET) < 0) {
		cerr << "nfq_bind_pf() failed\n";
		nfq_close(h);
		return 1;
	}

	struct nfq_q_handle* qh = nfq_create_queue(h, QUEUE_NUM, &callback, nullptr);
	if (qh == nullptr) {
		cerr << "nfq_create_queue() failed\n";
		nfq_close(h);
		return 1;
	}

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		cerr << "nfq_set_mode() failed\n";
		nfq_destroy_queue(qh);
		nfq_close(h);
		return 1;
	}

	int fd = nfq_fd(h);
	alignas(8) char buf[65536];

	cout << "[*] queue started\n";
	cout << "[*] press Ctrl+C to stop\n";

	while (!stop_program) {
		int rv = recv(fd, buf, sizeof(buf), 0);
		if (rv >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}

		if (errno == EINTR) continue;
		if (errno == ENOBUFS) continue;

		perror("recv");
		break;
	}

	nfq_destroy_queue(qh);
	nfq_close(h);
	cleanup_rule();

	return 0;
}