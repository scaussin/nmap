//
// Created by Sylvain Caussinus on 30/10/2020.
//

#include "main.h"

int main(int ac, char **av)
{
    if (ac != 3)
    {
        printf("usage: %s <address> <port>\n", av[0]);
        return 1;
    }

    char *domainNameDest = av[1];

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


    //creation de la socket en IPv4 / UDP pour l'envoi des messages
    int32_t sockFdRaw = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockFdRaw == -1)
    {
        cout << "ERROR socket(). impossible to create the socket" << endl;
        return 1;
    }

    //creation de la socket en IPv4 / ICMP pour la reception des messages de response
    int32_t sockFdICMP = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockFdICMP == -1)
    {
        cout << "ERROR socket(). impossible to create the socket" << endl;
        return 1;
    }

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

std::string getIpStr(const sockaddr_in &addr)
{
    char tmp[100];
    inet_ntop(addr.sin_family, &(addr.sin_addr), tmp, 100);
    std::string s(tmp);
    return (s);
}