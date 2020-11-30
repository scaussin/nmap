//
// Created by Sylvain Caussinus on 30/10/2020.
//

#include "main.h"


int main(int ac, char **av)
{
    if (ac != 4)
    {
        printf("usage: %s <address> <port> <+nPorts>\n", av[0]);
        return 1;
    }

    char *domainNameDest = av[1];


    uint16_t leBonGrosPorcDeDestination;
    uint16_t nPorts;
    try {
        leBonGrosPorcDeDestination = std::stoi(av[2]);
        nPorts = stoi(av[3]);
    }
    catch (std::exception &e)
    {
        cout << e.what() << endl;
        return (1);
    }

    /*addrinfo hints = {0};
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
    //creation de la raw socket en TCP pour l'envoi des SYN
    int32_t sockFdRawTcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockFdRawTcp == -1)
    {
        cout << "ERROR socket(). impossible to create the socket" << endl;
        return 1;
    }

    /*int yes = 1;
    setsockopt(sockFdRaw, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes));*/

    sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0); //attribue un port disponible automatiquement
    addr.sin_addr.s_addr = htonl(INADDR_ANY); //attribue automatiquement l'ip locale

    //MacOs specificity - (uniquement pour send)
    int32_t retBind = ::bind(sockFdRawTcp, (sockaddr *) &addr, sizeof(addr));
    if (retBind == -1)
    {
        cout << "retBind error: " << retBind << endl;
    }

    sockaddr_in sin = {0};
    socklen_t len = sizeof(sin);
    if (getsockname(sockFdRawTcp, (struct sockaddr *)&sin, &len) == -1)
        perror("getsockname");
    else
        printf("port number %d\n", sin.sin_port);


    /*sockaddr_in addrDest = {0};
    addrDest.sin_family = AF_INET;
    addrDest.sin_port = htons(leBonGrosPorcDeDestination);
    inet_pton(AF_INET, domainNameDest, &addrDest.sin_addr.s_addr);

    tcphdr tcpHeader = {0};
    tcpHeader.th_sport = htons(4242);
    tcpHeader.th_dport = htons(leBonGrosPorcDeDestination);
    tcpHeader.th_off = sizeof(tcphdr) >> (uint32_t)2;
    tcpHeader.th_flags |= (uint32_t)TH_SYN;
    tcpHeader.th_win = htons(1024);
    makeChecksumTcp((uint32_t)addrDest.sin_addr.s_addr, std::string(INTERFACE).c_str(), &tcpHeader);

    cout << "sendto: [SYN] " << domainNameDest << ":" << leBonGrosPorcDeDestination << endl;
    if (sendto(sockFdRawTcp, &tcpHeader, sizeof(tcpHeader), 0, (sockaddr *)&addrDest, sizeof(addrDest)) == -1)
    {
        cout << "Error sendto()" << endl;
        perror("perror sendto");
        return 1;
    }*/




    /* PCAP */

    char error_buffer[PCAP_ERRBUF_SIZE];

    char dev[] = INTERFACE;
    bpf_u_int32 subnet_mask, ip;

    //cout << __PRETTY_FUNCTION__ << endl;
    /* Open device for live capture */

    if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1) {
        printf("Could not get information for device: %s\n", dev);
        ip = 0;
        subnet_mask = 0;
    }

    vector<thread> threads;
    for ( ; nPorts > 0 ; --nPorts)
    {
        threads.emplace_back(scanPort, std::ref(ip), leBonGrosPorcDeDestination + nPorts, domainNameDest, sockFdRawTcp, dev);

    }

    for (auto& th : threads)
    {
        th.join();
    }

    return (0);
}

void scanPort(bpf_u_int32 &ip, uint16_t leBonGrosPorcDeDestination, char *domainNameDest, uint32_t sockFdRawTcp, char *dev)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int timeout_limit = 100; /* In milliseconds */

    sockaddr_in addrDest = {0};
    addrDest.sin_family = AF_INET;
    addrDest.sin_port = htons(leBonGrosPorcDeDestination);
    inet_pton(AF_INET, domainNameDest, &addrDest.sin_addr.s_addr);

    tcphdr tcpHeader = {0};
    tcpHeader.th_sport = htons(4242);
    tcpHeader.th_dport = htons(leBonGrosPorcDeDestination);
    tcpHeader.th_off = sizeof(tcphdr) >> (uint32_t)2;
    tcpHeader.th_flags |= (uint32_t)TH_SYN;
    tcpHeader.th_win = htons(1024);
    makeChecksumTcp((uint32_t)addrDest.sin_addr.s_addr, std::string(INTERFACE).c_str(), &tcpHeader);

    cout << "sendto: [SYN] " << domainNameDest << ":" << leBonGrosPorcDeDestination << endl;
    if (sendto(sockFdRawTcp, &tcpHeader, sizeof(tcpHeader), 0, (sockaddr *)&addrDest, sizeof(addrDest)) == -1)
    {
        cout << "Error sendto()" << endl;
        perror("perror sendto");
        return ;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, timeout_limit, error_buffer);
    if (handle == nullptr) {
        fprintf(stderr, "Could not open device lo0: %s\n", error_buffer);
        return ;
    }

    string filters = string("tcp && src port ") + to_string(leBonGrosPorcDeDestination) + string(" && dst port 4242");
    const char *filter_exp = filters.c_str();
    bpf_program filter = {0};
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return ;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return ;
    }

    pcap_dispatch(handle, 1, my_packet_handler, nullptr);
    pcap_close(handle);
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr* header, const u_char* packet)
{
    struct ether_header *eth_header;
    ip *iphdr = (ip *)(packet + sizeof(ether_header));
    eth_header = (struct ether_header *) packet;
    tcphdr *tcp = (tcphdr *)((uint8_t *)(iphdr) + iphdr->ip_hl * 4);

//    cout << "eth_header->ether_type: " << eth_header->ether_type << endl;
//    cout << "ntohs: " << ntohs(eth_header->ether_type) << endl;
//    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
//    {
//        cout << "[IP][" << (uint16_t)iphdr->ip_p <<  "]";
//    }

    if (tcp->th_flags == (TH_ACK | TH_SYN))
    {
        //open
    }
    if (tcp->th_flags == (TH_RST))
    {
        //close
    }

    hexdumpBuf((char *)packet, header->len);


    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        printf("IP\n");
    } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        printf("ARP\n");
    } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
        printf("Reverse ARP\n");
    }
}

//TODO envoyer data pour calculer tcpLength
void makeChecksumTcp(uint32_t dstAddr, const char *interfaceName , tcphdr *tcpHeader)
{
    pseudoHdrIp phi = {0};

    phi.dstAddr = dstAddr;
    phi.srcAddr = nm_get_ip_interface(interfaceName);
    phi.protocol = IPPROTO_TCP;
    phi.tcpLength = htons(sizeof(tcphdr));

    uint8_t buf[256];
    memcpy(buf, &phi, sizeof(phi));
    memcpy(buf + sizeof(phi), tcpHeader, sizeof(*tcpHeader));

    tcpHeader->th_sum = icmpChecksum((uint16_t *)buf, sizeof(phi) + sizeof(*tcpHeader));
}

uint32_t nm_get_ip_interface(const char *interfaceName)
{
    ifaddrs *ifap;
    ifaddrs *ifa;

    if (getifaddrs(&ifap) < 0)
    {
        cout << "[ERROR] getifaddrs" << endl;
        return 0;
    }
    ifa = ifap;
    while (ifa->ifa_next != nullptr)
    {
        if (ifa->ifa_addr->sa_family == AF_INET && strcmp(interfaceName, ifa->ifa_name) == 0)
        {
            uint32_t res = ((sockaddr_in *)(ifa->ifa_addr))->sin_addr.s_addr;
            freeifaddrs(ifap);
            return (res);
        }
        ifa = ifa->ifa_next;
    }
    freeifaddrs(ifap);
    return (0);
}



void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
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