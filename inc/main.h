//
// Created by Sylvain Caussinus on 30/10/2020.
//

#ifndef NMAP_MAIN_H
#define NMAP_MAIN_H

#include <thread>
#include <iostream>
#include <pcap.h>
#include <string>
#include <iomanip>
#include <unistd.h>
#include <sys/socket.h>


using std::cout;
using std::endl;

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

#endif //NMAP_MAIN_H
