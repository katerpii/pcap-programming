#ifndef PCAPTEST_H
#define PCAPTEST_H

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN      0x6
#endif

#ifndef IP_PROTOCOL_OFFSET
#define IP_PROTOCOL_OFFSET  0x48
#endif


#ifndef ETHER_TYPE_OFFSET
#define ETHER_TYPE_OFFSET  0xc
#endif


#include <inttypes.h>

// typedef struct in_addr {
//     uint32_t addr;
// };

typedef struct {
    uint8_t dhost[ETHER_ADDR_LEN];
    uint8_t shost[ETHER_ADDR_LEN];
    uint16_t ether_type; 
} ethernet_hdr;

typedef struct {
    uint8_t ip_hl:4, ip_v:4;
    uint8_t ip_tos;
    uint16_t ip_len;         
    uint16_t ip_id;          
    uint16_t ip_off;
    uint8_t ip_ttl;        
    uint8_t ip_p;           
    uint16_t ip_sum;  
    uint32_t ip_src;
    uint32_t ip_dst;
} ipv4_hdr;

typedef struct {
    uint16_t sport;       
    uint16_t dport;       
    uint32_t seq;          
    uint32_t ack;
    uint8_t th_x2:4, th_off:4;
    uint8_t  flags;             
} tcp_hdr;

typedef struct {
    uint8_t dst_mac[ETHER_ADDR_LEN];
    uint8_t src_mac[ETHER_ADDR_LEN];

    uint32_t ip_src;
    uint32_t ip_dst;

    uint16_t src_port;
    uint16_t dst_port;

    unsigned char payload[21];
} pkt_record;

#endif