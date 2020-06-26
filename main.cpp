#include <cctype>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include <cstdio>
#define BUF_SIZE 1500
#define TIMEVAL_LEN	((int)sizeof(struct timeval))
#define ICMP_LEN ICMP_MINLEN + TIMEVAL_LEN

using namespace std;

bool run = true;
int nsend = 0, nrecv = 0;

void printUsage(char* prog)
{
	cerr << "Usage: " << prog <<" [-c count] [-i wait] [-m ttl] [-s packetsize] [-t timeout] host" << endl;
}

void termHandler(int)
{
	run = false;
}

void getStatistics(char* dest, int nsent, int nrecv)  
{  
	cout << "--- " << dest << " ping statistics ---" << endl;
	cout << nsent << " packets transmitted, " << nrecv << " received, " << 1.0*(nsent-nrecv)/nsent*100 << "\% packet loss" <<endl; 
}

void tv_sub(struct timeval& out, struct timeval* in)
{
    if ((out.tv_usec -= in->tv_usec) < 0) {
		--out.tv_sec;
		out.tv_usec += 1000000;
	} 
	out.tv_sec -= in->tv_sec;
}

void parseOpts(int argc, char* argv[], int& count, int& datalen, int& ttl, float& timeout, float& wait)
{
	int c;
	while ((c = getopt(argc, argv, "c:i:m:s:t:")) != -1) {
		char* p;
		switch (c) {
			case 'c':
				count = strtol(optarg, &p, 10);
				if (*p || count < 1) {
					cerr << argv[0] << ": invalid count of packets to transmit: `" << optarg << '`' << endl;
					exit(EXIT_FAILURE);
				}
				break;
			case 'i':
				wait = strtof(optarg, &p);
				if (*p) {
					cerr << argv[0] << ": invalid timing interval: `" << optarg << '`' << endl;
					exit(EXIT_FAILURE);
				} else if (wait < 1) {
					cerr  << argv[0] << ": -i interval too short: Operation not permitted" << endl;
					exit(EXIT_FAILURE);
				}
				break;
			case 'm':
				ttl = strtol(optarg, &p, 10);
				if (*p || ttl < 1) {
					cerr << argv[0] << ": invalid TTL: `" << optarg << '`' << endl;
					exit(EXIT_FAILURE);
				}
				break;
			case 's':
				datalen = strtol(optarg, &p, 10);
				if (*p || datalen < 1) {
					cerr << argv[0] << ": invalid datalen: `" << optarg << '`' << endl;
					exit(EXIT_FAILURE);
				}
				else if (datalen + ICMP_LEN > BUF_SIZE) {
					cerr << "Packet size too large: " << datalen << " > " << BUF_SIZE - ICMP_LEN << endl;
					exit(EXIT_FAILURE);
				}
			case 't':
				timeout = strtof(optarg, &p);
				if (*p) {
					cerr << argv[0] << ": invalid timeout: `" << optarg << '`' << endl;
					exit(EXIT_FAILURE);
				}
				break;
			case '?':
				cerr << "illegal option -- " << (char)optopt << endl;
				printUsage(argv[0]);
			default:
				exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc) {
		printUsage(argv[0]);
		exit(EXIT_FAILURE);
	}
}

/* Implement RFC 1071 */
unsigned short checksum(unsigned short* buf, int buf_size)
{
	unsigned int sum = 0;
	while (buf_size > 1) {
		sum += *buf++;
		buf_size -= 2;
	}

	// Deal with last 8 bits 
	if (buf_size == 1) {
		sum += *(unsigned char*)buf;
	}

	sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
	return ~sum;
}

void pack_icmp(char* sendbuf, int seq, int packetsize)
{
	struct icmp* pkt = (struct icmp*)sendbuf;
	pkt->icmp_type = ICMP_ECHO;
	pkt->icmp_code = 0;
	pkt->icmp_cksum = 0;
	pkt->icmp_id = getpid();
	pkt->icmp_seq = seq;
	struct timeval now;
	gettimeofday(&now, NULL);
	memcpy(sendbuf + ICMP_MINLEN, &now, TIMEVAL_LEN);
	pkt->icmp_cksum = checksum((unsigned short*)sendbuf, packetsize + 8);
}

/*
 * unpack_icmp: Parse ICMP response
 * @param buf: The buffer storing the packet
 * @param len: The length of the packet
 * @param dest: Destination
 */
void unpack_icmp(char* buf, int len, char* dest, int& nrecv)
{
	/* Extract IP header */
	struct ip* iphdrptr = (struct ip*)buf;

	/* Extract ICMP header */
	int hlen = (iphdrptr->ip_hl << 2);
	if (len < hlen + ICMP_MINLEN) {
		cout << "Packet too short (" << len << " bytes) from " << dest << endl;
		return;
	}
	len -= hlen;

	struct icmp* pkt = (struct icmp*)(buf + hlen);
	cout << len << " bytes from " << dest << ": ";
	switch (pkt->icmp_type) {
		case ICMP_ECHOREPLY: {
			if (pkt->icmp_id == getpid()) {
				cout << "icmp_seq=" << pkt->icmp_seq << " ttl=" << unsigned(iphdrptr->ip_ttl);
				nrecv++;
				if (len - ICMP_MINLEN >= ICMP_LEN) {
					struct timeval tvrecv;
					gettimeofday(&tvrecv, NULL);
					struct timeval* tvsend = (struct timeval*)(buf + hlen + ICMP_MINLEN);
					tv_sub(tvrecv, tvsend);
					double rtt = ((double)tvrecv.tv_sec) * 1000 + ((double)tvrecv.tv_usec) / 1000;
					cout << " time=" << (float)rtt << "ms" << endl;
				} else {
					cout << endl;
				}
				break;
			}
		}
		case ICMP_UNREACH: {
			switch (pkt->icmp_code) {
				case ICMP_UNREACH_NET:
					cout << "Destination Net Unreachable" << endl;
					break;
				case ICMP_UNREACH_HOST:
					cout << "Destination host unreachable" << endl;
					break;
				case ICMP_UNREACH_PROTOCOL:
					cout << "Destination protocol unreachable" << endl;
					break;
				case ICMP_UNREACH_PORT:
					cout << "Destination Protocol Unreachable" << endl;
					break;
				case ICMP_UNREACH_SRCFAIL:
					cout << "Source Route Failed" << endl;
					break;
				case ICMP_UNREACH_FILTER_PROHIB:
					cout << "Communication prohibited by filter" << endl;
					break;
				default:
					cout << "Destination unreachable, code: " << pkt->icmp_code << endl;
					break;
			}
			break;
		}
		case ICMP_SOURCEQUENCH: {
			cout << "Source quench" << endl;
			break;
		}
		case ICMP_REDIRECT: {
			switch(pkt->icmp_code) {
				case ICMP_REDIRECT_NET:
					cout << "Redirect Network";
					break;
				case ICMP_REDIRECT_HOST:
					cout << "Redirect Host";
					break;
				case ICMP_REDIRECT_TOSNET:
					cout << "Redirect Type of Service and Network";
					break;
				case ICMP_REDIRECT_TOSHOST:
					cout << "Redirect Type of Service and Host";
					break;
				default:
					cout << "Redirect, code: " << unsigned(pkt->icmp_code);
					break;
			}
			cout << "(New addr: " << inet_ntoa(pkt->icmp_gwaddr) << ")" << endl;
			break;
		}
		case ICMP_TIMXCEED: {
			switch(pkt->icmp_code) {
				case ICMP_TIMXCEED_INTRANS:
					cout << "Time to live exceeded" << endl;
					break;
				case ICMP_TIMXCEED_REASS:
					cout << "Frag reassembly time exceeded" << endl;
					break;
				default:
					cout << "Time exceeded, Bad code: " << unsigned(pkt->icmp_code) << endl;
					break;
			}
			break;
		}
		default:
			cout << "ICMP type=" << unsigned(pkt->icmp_type) << endl;
			break;
	}
}


int main(int argc, char *argv[])
{
	int count = 0, ttl = 0, packetsize = 56;
	int sockfd;
	socklen_t fromlen;
	float wait = 1;	/* Default wait time for ping is one second */
	float timeout = 0;
	parseOpts(argc, argv, count, packetsize, ttl, timeout, wait);
	char* dest = argv[optind];
	char sendbuf[BUF_SIZE], recvbuf[BUF_SIZE];
	struct sockaddr_in sendto_addr, recvfrom_addr;
	struct hostent* host;
	struct sigaction term_action;
	struct itimerval timeout_alarm;
	timeout_alarm.it_interval.tv_sec = (time_t)timeout;
	timeout_alarm.it_interval.tv_usec = (time_t)((timeout - (int)timeout) * 100000);
	timeout_alarm.it_value.tv_sec = 0;
	timeout_alarm.it_value.tv_usec = 1;

	term_action.sa_handler = termHandler;

	memset(&sendto_addr, 0, sizeof(sendto_addr));
	// Determine if the dest is an IPv4 address, IPv6 address, or a hostname
	if (inet_pton(AF_INET, dest, &sendto_addr.sin_addr)) {
		/* IPv4 address */
		sendto_addr.sin_family = AF_INET;
	}
	else {
		if (!(host = gethostbyname(dest))) {
			cerr << argv[0] << ": Unknown host " << dest << endl;
			exit(EXIT_FAILURE);
		}

		sendto_addr.sin_family = host->h_addrtype;
		sendto_addr.sin_addr = *(struct in_addr*)host->h_addr_list[0];
	}

	/* Create a raw socket for ICMP */
	if ((sockfd = socket(sendto_addr.sin_family, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		cerr << "Failed to create a socket" << endl;
		exit(EXIT_FAILURE);
	}

	if (ttl > 0) {
		setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	}


	sigaction(SIGINT, &term_action, NULL);

	if (timeout > 0) {
		sigaction(SIGALRM, &term_action, NULL);
		alarm((unsigned int)timeout);
	}

	cout << "PING " << dest << " (" << inet_ntoa(sendto_addr.sin_addr) << "): " << packetsize << " data bytes" << endl;
	while (run) {
		memset(sendbuf, 0xff, sizeof(sendbuf));
		pack_icmp(sendbuf, nsend + 1, packetsize);

		/* Send ICMP echo */
		ssize_t recv_bytes;
		if ((recv_bytes = sendto(sockfd, sendbuf, packetsize + 8, 0, (struct sockaddr*)&sendto_addr, sizeof(sendto_addr))) == -1) {
			cerr << "Send to: No route to host" << endl;
			continue;
		}
		nsend++;

		fromlen = sizeof(recvfrom_addr);
		if ((recv_bytes = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr*)&recvfrom_addr, &fromlen)) < 0) {
			cerr << "Failed to receive ICMP response from " << dest << endl;
			continue;
		}

		unpack_icmp(recvbuf, recv_bytes, inet_ntoa(recvfrom_addr.sin_addr), nrecv);
		if (count > 0 && nrecv == count)
			run = false;

		sleep(wait);
	}

	getStatistics(dest, nsend, nrecv);
	close(sockfd);
	return EXIT_SUCCESS;
}
