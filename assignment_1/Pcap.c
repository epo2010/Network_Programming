#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>


// 2계층 이더넷 구조체 선언 : 총 바이트는 14바이트
struct Ethernet {
    uint8_t dst_MAC[6]; 
    uint8_t src_MAC[6];
    uint16_t type;
} __attribute__ ((__packed__)); //#pragma pack 1과 비슷한 역할


// 3계층 IP 구조체 선언
struct IP {
    uint8_t IHL:4; // 원래는 Ver, IHL 순서이지만, NBO에 의해 순서를 바꿔 선언
    uint8_t Ver:4;
    uint8_t Service;
    uint16_t IP_total_length;
    uint16_t Identification;
    uint16_t Flags_FragOffset;
    uint8_t TTL;
    uint8_t Protocol;
    uint16_t Header_checksum;
    uint8_t src_IP[4];
    uint8_t dst_IP[4];
} __attribute__ ((__packed__));


// 4계층 TCP 구조체 선언
struct TCP {
    uint16_t src_Port;
    uint16_t dst_Port;
    uint32_t Seq_Num;
    uint32_t Ack_Num;
    uint8_t Reserved:4; // 원래는 H_len, Reserved 순서이지만, NBO에 의해 순서를 바꿔 선언
    uint8_t H_len:4;
    uint8_t Flags;
    uint16_t Window;
    uint16_t Checksum;
    uint16_t Urgent_Pointer;
} __attribute__ ((__packed__));

struct TCP_Payload {
    uint8_t payload[16];
}__attribute__ ((__packed__));

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

// 인수의 개수가 제대로 받아지면 True를 반환하는 함수
bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1]; // dev_가 argv[1]의 위치를 가리킴
    return true;
}

int main(int argc, char* argv[]) {
    // 인수 개수 검사
    if (!parse(&param, argc, argv))
        return -1;

    // PCAP_ERRBUF_SIZE : pcap 라이브러리에서 발생하는 오류 메시지를 저장하는 버퍼의 최대 크기
    // errbuf는 오류 메세지를 담을 문자열
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

    // 아무 패킷이 캡쳐되지 않았을 때 오류 메시지 출력
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

// 구조체 객체 생성
    struct Ethernet *ethernet;
    struct IP *ip;
    struct TCP *tcp;
    struct TCP_Payload *tcp_payload;


    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

// [이더넷 패킷] 패킷의 맨 앞 위치부터 구조체 크기 만큼 데이터를 할당
        ethernet = (struct Ethernet *)packet;
// [ip 패킷] 이더넷 헤더 뒤 위치부터 데이터 할당 
        ip = (struct IP *)(packet + sizeof(struct Ethernet));
// [tcp 패킷] ip 헤더 뒤 위치부터 데이터 할당
        tcp = (struct TCP *)(packet + (sizeof(struct Ethernet)) + (ip->IHL * 4));
// [tcp 페이로드] tcp헤더 뒤 위치부터 할당
        tcp_payload = (struct TCP_Payload *)(packet + (sizeof(struct Ethernet) + (ip->IHL * 4) + (tcp->H_len * 4)));


// 캡처한 패킷이 tcp 패킷인지 확인
        if (ip->Protocol == 0x06 && ethernet->type == 0x0008) {

// 출발지 MAC 주소 출력
            printf("Src MAC : ");
            for (int i = 0; i < 6; i++) {
                printf("%02X", ethernet->src_MAC[i]);
                if (i <= 4)
                    printf(" : ");
                else
                    printf("\n");
            }

// 목적지 MAC 주소 출력
            printf("Dst MAC : ");
            for (int i = 0; i < 6; i++) {
                printf("%02X", ethernet->dst_MAC[i]);
                if (i <= 4)
                    printf(" : ");
                else
                    printf("\n");
            }

// 출발지 IP 주소 출력
            printf("Src IP : ");
            for (int i = 0; i < 4; i++) {
                printf("%d", ip->src_IP[i]);
                if (i <= 2)
                    printf(".");
                else
                    printf("\n");
            }

// 목적지 IP 주소 출력
            printf("Dst IP : ");
            for (int i = 0; i < 4; i++) {
                printf("%d", ip->dst_IP[i]);
                if (i <= 2)
                    printf(".");
                else
                    printf("\n");
            }

// 출발지 포트 출력
            printf("Src Port : %d\n", ntohs(tcp->src_Port));

// 목적지 포트 출력
            printf("Dst Port : %d\n", ntohs(tcp->dst_Port));

// 데이터 길이 출력
            printf("Total Byte : %u\n", header->caplen);

// TCP 페이로드 출력
            int check_remain = header->caplen - (sizeof(struct Ethernet) + (ip->IHL * 4) + (tcp->H_len * 4));

            if (check_remain != 0 ) {
                printf("TCP Payload : ");

                for (int i = 0; i < check_remain; i++) {
                    if (i == 16) break;

                    printf("%02X", tcp_payload->payload[i]);
                    printf(" ");
                }
                printf("\n");
            }
            printf("\n");
        }
    }
    pcap_close(pcap);
}