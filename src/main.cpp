//
// Created by Sylvain Caussinus on 30/10/2020.
//

#include <netinet/tcp.h>
#include "main.h"

int main(int ac, char **av)
{
    if (ac != 3)
    {
        printf("usage: %s <address> <port>\n", av[0]);
        return 1;
    }

    /*char *domainNameDest = av[1];

    uint16_t leBonGrosPorc;
    try {
        leBonGrosPorc = std::stoi(av[2]);
    }
    catch (std::exception &e)
    {
        cout << e.what() << endl;
        return (1);
    }

    addrinfo hints = {0};
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = 0;
    hints.ai_protocol = IPPROTO_IP;

    //requete DNS pour resoudre le nom de domaine
    addrinfo *addrInfoLst;
    int ret = getaddrinfo(domainNameDest, nullptr, &hints, &addrInfoLst);
    if (ret)
    {
        cout << "ping: cannot resolve " << domainNameDest << ": Unknown host" << endl;
        return 1;
    }

    //recuperation de l'adresse en char[] pour l'affichage.
    std::string ipDest = getIpStr(*((sockaddr_in *) addrInfoLst->ai_addr));

    addrinfo *addrInfoLstFirst = addrInfoLst;

    if (!addrInfoLstFirst)
    {
        cout << "ERROR return getaddrinfo() empty" << endl;
        return 1;
    }

    cout << "Nmap scan report for " << domainNameDest << " (" << ipDest << ")" << endl;

*/
    //creation de la socket en IPv4 / UDP pour l'envoi des messages
    //int32_t sockFdRaw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    //int32_t sockFdRaw = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    int32_t sockFdRaw = socket(PF_NDRV , SOCK_RAW , IPPROTO_UDP) ;
    if (sockFdRaw == -1)
    {
        cout << "ERROR socket(). impossible to create the socket" << endl;
        return 1;
    }

    int yes = 1;
    setsockopt(sockFdRaw, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes));

    sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    //addr.sin_port = htons(0); //attribue un port disponible automatiquement
    addr.sin_port = htons(4300);
    addr.sin_addr.s_addr = htonl(INADDR_ANY); //attribue automatiquement l'ip locale

    //MacOs specificity - (uniquement pour send)
   /* int32_t retBind = bind(sockFdRaw, (sockaddr *) &addr, sizeof(addr));
    if (retBind == -1)
    {
        cout << "retBind error: " << retBind << endl;
    }*/

    sockaddr_in sin;
    socklen_t len = sizeof(sin);
    if (getsockname(sockFdRaw, (struct sockaddr *)&sin, &len) == -1)
        perror("getsockname");
    else
        printf("port number %d\n", ntohs(sin.sin_port));

    sockaddr_in addrDest = {0};
    addrDest.sin_family = AF_INET;
    addrDest.sin_port = htons(4200);
    inet_pton(AF_INET, "127.0.0.1", &addrDest.sin_addr.s_addr);

    tcphdr tcpHeader = {0};
    tcpHeader.th_sport = htons(4300);
    tcpHeader.th_dport = htons(4200);
    tcpHeader.th_off = sizeof(tcphdr) >> (uint32_t)2;
    tcpHeader.th_flags |= (uint32_t)TH_SYN;
    tcpHeader.th_win = htons(1024);
    cout << "checksum: " << icmpChecksum((uint16_t *)&tcpHeader, sizeof(tcpHeader));
    tcpHeader.th_sum = 0xAC8C; // icmpChecksum((uint16_t *)&tcpHeader, sizeof(tcpHeader) / 2);

    /*if (sendto(sockFdRaw, &tcpHeader, sizeof(tcpHeader), 0, (sockaddr *)&addrDest, sizeof(addrDest)) == -1)
    {
        cout << "Error sendto()" << endl;
        perror("perror sendto");
        return 1;
    }*/

    /*cout << "listen()..." << endl;
    int32_t retListent = listen(sockFdRaw, 5);
    if (retListent == -1)
    {
        cout << "listen error: " << retListent << endl;
    }*/

    char buf[2048] = {0};
    cout << "recv()..." << endl;
    //for recvfrom()
    sockaddr_in sockaddrInRecv = {0};
    socklen_t p;

    int32_t retRecv = recvfrom(sockFdRaw, buf, (__darwin_size_t)sizeof(buf), 0, (sockaddr *)&sockaddrInRecv, &p);
    if (retRecv == -1)
    {
        cout << "recv error: " << retRecv << endl;
        return 1;
    }
    cout << "retRecv: " << retRecv << endl;
    hexdumpBuf(buf, retRecv);

    retRecv = recvfrom(sockFdRaw, buf, (__darwin_size_t)sizeof(buf), 0, (sockaddr *)&sockaddrInRecv, &p);
    if (retRecv == -1)
    {
        cout << "recv error: " << retRecv << endl;
        return 1;
    }
    cout << "retRecv: " << retRecv << endl;
    hexdumpBuf(buf, retRecv);


    retRecv = recvfrom(sockFdRaw, buf, (__darwin_size_t)sizeof(buf), 0, (sockaddr *)&sockaddrInRecv, &p);
    if (retRecv == -1)
    {
        cout << "recv error: " << retRecv << endl;
        return 1;
    }
    cout << "retRecv: " << retRecv << endl;
    hexdumpBuf(buf, retRecv);


    /*cout << "recv()2..." << endl;
     retRecv = recv(sockFdRaw, buf, (__darwin_size_t)sizeof(buf), 0);
    if (retRecv == -1)
    {
        cout << "recv error: " << retRecv << endl;
        return 1;
    }
    cout << "retRecv: " << retRecv << endl;
    hexdumpBuf(buf, retRecv);*/


    /*cout << "sizeof(sockaddr)" << sizeof(sockaddr) << endl;
    cout << "sizeof(sockaddr*)" << sizeof(sockaddr*) << endl;*/

    /*sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t) 28001);
    addr.sin_addr.s_addr = INADDR_ANY;

    //MacOs specificity - (uniquement pour send)
    int retBind = bind(sockFdUDP, (sockaddr *) &addr, sizeof(addr));
    if (retBind == -1)
    {
        cout << "retBind error: " << retBind << endl;
    }

    //for recvfrom()
    sockaddr_in sockaddrInRecv = {0};
    fd_set fdRead;

    int32_t retSelect;
    //sockaddrInRecv.sin_family = AF_INET;
    //sockaddrInRecv.sin_port = 0;
    //sockaddrInRecv.sin_addr.s_addr = INADDR_ANY;
    char bufRecv[2048] = {0};

    bool loop = true;
    uint64_t socketTTL = 1;*/
    return (0);
}

uint16_t icmpChecksum(uint16_t *data, uint32_t len)
{
    uint32_t checksum;

    checksum = 0;
    while (len > 1)
    {
        checksum = checksum + *data++;
        len = len - sizeof(uint16_t);
    }
    if (len)
        checksum = checksum + *(uint8_t *) data;
    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum = checksum + (checksum >> 16);
    return (uint16_t) (~checksum);
}

std::string getIpStr(const sockaddr_in &addr)
{
    char tmp[100];
    inet_ntop(addr.sin_family, &(addr.sin_addr), tmp, 100);
    std::string s(tmp);
    return (s);
}


void hexdumpBuf(char *buf, uint32_t len)
{
    cout << endl;
    for (int i = 0; i < len; i++)
    {
        cout << std::setw(2) << std::setfill('0') << std::hex << (uint16_t) ((uint8_t) buf[i]) << " " << std::flush;

        if (i % 8 == 7 && i % 16 != 15)
        {
            cout << " " << std::flush;
        }
        else if (i % 16 == 15)
        {
            cout << endl << std::flush;
        }
    }
    cout << endl << std::dec << std::flush;
}