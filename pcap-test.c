#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "pcap-test.h"


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

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

bool is_tcp(unsigned char* packet) {
	return (ntohs(*(uint16_t*)(packet + ETHER_TYPE_OFFSET)) == 0x0800)
		&& (*(uint8_t*)(packet + sizeof(ethernet_hdr) + IP_PROTOCOL_OFFSET) == 0x6);
}

void print_addr(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport){
	printf("IPv4 src: %hhu.%hhu.%hhu.%hhu:%hu\n" \
		   "IPv4 dst: %hhu.%hhu.%hhu.%hhu:%hu\n" \
			, (uint8_t)(src >> 24), (uint8_t)(src >> 16)
		    , (uint8_t)(src >> 8), (uint8_t)src
			, sport
			, (uint8_t)(dst >> 24), (uint8_t)(dst >> 16)
		    , (uint8_t)(dst >> 8), (uint8_t)dst
			, dport
		);
}

void print_mac(uint8_t* src, uint8_t* dst){
	printf("MAC src: %02x:%02x:%02x:%02x:%02x:%02x\n" \
		   "MAC dst: %02x:%02x:%02x:%02x:%02x:%02x\n" \
		   , src[0], src[1], src[2]
		   , src[3], src[4], src[5]
		   , dst[0], dst[1], dst[2]
		   , dst[3], dst[4], dst[5]
	);
}


void print_packet_info(unsigned char* packet, uint32_t caplen){
	pkt_record res = {0};
	
	ethernet_hdr *eth = (ethernet_hdr*)packet;
	memcpy(res.dst_mac, eth->dhost, ETHER_ADDR_LEN);
	memcpy(res.src_mac, eth->shost, ETHER_ADDR_LEN);

	ipv4_hdr *ip4 = (ipv4_hdr*)(packet + sizeof(ethernet_hdr));
	uint8_t ip_hdr_len = (ip4->ip_hl & 0xf) * 4;

	res.ip_src = ntohl(ip4->ip_src);
	res.ip_dst = ntohl(ip4->ip_dst);

	tcp_hdr *tcp = (tcp_hdr*)(packet + sizeof(ethernet_hdr) + ip_hdr_len);
	uint8_t data_offset = (tcp->th_off & 0xf) * 4;
	uint32_t hdr_len = sizeof(ethernet_hdr) + ip_hdr_len + data_offset;
	
	res.src_port = ntohs(tcp->sport);
	res.dst_port = ntohs(tcp->dport);
	
	if (caplen > hdr_len){
		uint32_t data_len = caplen - hdr_len;
		if (data_len > sizeof(res.payload)){
			data_len = sizeof(res.payload);
		}
		memcpy(res.payload, packet + hdr_len, data_len);
		res.payload[data_len] = '\0';

	}
	
	print_mac(res.src_mac, res.dst_mac);
	print_addr(res.ip_src, res.ip_dst, res.src_port, res.dst_port);
	
	printf("Data: ");
	fwrite(res.payload, 1, strlen(res.payload), stdout);
	printf("\n\n");

}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const unsigned char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		if (!is_tcp(packet)) {
			continue;
		}
		printf("%u bytes captured\n", header->caplen);
		print_packet_info(packet, header->caplen);
	}

	pcap_close(pcap);
}
