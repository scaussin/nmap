//
// Created by Sylvain Caussinus on 30/10/2020.
//

#ifndef NMAP_MAIN_H
#define NMAP_MAIN_H

#include <iostream>
#include <pcap.h>
#include <string>
#include <iomanip>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <ifaddrs.h>
#include <string.h>
#include <map>
#include <thread>
#include <vector>


using namespace std;

#define INTERFACE "en0"

uint16_t	icmpChecksum(uint16_t *data, uint32_t len);
void        hexdumpBuf(char *buf, uint32_t len);
double      getDiffTimeval(const timeval &t1, const timeval &t2);
bool        isEchoReply(uint8_t *buf, ssize_t retRecv);
void        onSignalReceived(int sig);
void        printAddrInfo(addrinfo *pAddrInfo);
void        printSockaddr(sockaddr *sockAddr);
timeval     subTimeval(const timeval &t1, const timeval &t2);
std::string getIpStr(const sockaddr_in &addr);
bool        changeTTL(uint64_t sockFd, uint64_t socketTTL);
bool        sendRequestUDP(uint64_t sockFd, addrinfo *addrInfo);
std::string getDomainName(uint32_t IpAddr, std::string ipAddr);
bool        isTTLExceeded(uint8_t *buf, ssize_t retRecv);

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);
uint32_t nm_get_ip_interface(const char *interfaceName);
void makeChecksumTcp(uint32_t dstAddr, const char *interfaceName, tcphdr *tcpHeader);
void scanPort(bpf_u_int32 &ip, uint16_t leBonGrosPorcDeDestination, char *domainNameDest, uint32_t sockFdRawTcp, char *dev);

struct pseudoHdrIp {
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcpLength;
};

enum class resScan {
    NONE = 0,
    OPEN = 1,
    CLOSE = 2,
    FILTERED = 3,
};

ostream &operator<<(ostream& os, resScan &type)
{
    if (type == resScan::OPEN)
        os << "OPEN";
    else if (type == resScan::CLOSE)
        os << "CLOSE";
    else if (type == resScan::FILTERED)
        os << "FILTERED";
    else
        os << "NONE";
    return os;
}


map<uint16_t , resScan> mapResScan;

#endif //NMAP_MAIN_H
