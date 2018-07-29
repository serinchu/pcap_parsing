
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdint.h>

#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define MAX_DATA_LEN 16

void usage()
{
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

typedef struct _ether_hdr
{
	uint8_t dmac[MAC_ADDR_LEN];
	uint8_t smac[MAC_ADDR_LEN];
	uint16_t type;
} ether_hdr;

typedef struct _ip_hdr
{
	uint8_t ver_hdlen;
	uint8_t tos;			//type of service
	uint16_t tpl;			//total packet length
	uint16_t id;
	uint16_t flag_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t sip[IP_ADDR_LEN];
	uint8_t dip[IP_ADDR_LEN];	
} ip_hdr;

typedef struct _tcp_hdr
{
	uint16_t sport;
	uint16_t dport;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t hdr_len;		//only upper 4 bits
} tcp_hdr;

/*
int is_ipv4(uint16_t type) {
	return (((type>>8)|(type<<8)) == ETHERTYPE_IP) ? 1 : 0;
}
*/

void print_mac(uint8_t *mac_addr)
{
			printf("%.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
			 mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]);
}

int main(int argc, char *argv[]) {
	
	char track[] = "개발";
	char name[] = "이세린";
	printf("[bob7][%s]pcap_test[%s]\n", track, name);	

	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	char ip_buf[16] = {0};

	uint16_t ip_hdr_len = 0;
	uint16_t tcp_hdr_len = 0;

	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while (true) {
		
		struct pcap_pkthdr* header = NULL;
		const u_char* packet = NULL;
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) 					//none be captured
			continue;
		if (res == -1 || res == -2)
		 	break;

		ether_hdr *eth_h = (ether_hdr *)packet;
		
		printf("--------------------ETHERNET HEADER-------------------\n");
		printf("| destination MAC = ");
		print_mac(eth_h->dmac);
		printf("|      source MAC = ");
		print_mac(eth_h->smac);
		printf("------------------------------------------------------\n");

		if((ntohs)(eth_h->type) == ETHERTYPE_IP) {	//IPv4 protocol	

			ip_hdr *ip_h = (ip_hdr *)((uint8_t*)packet + sizeof(ether_hdr));

			printf("--------------------------IPv4------------------------\n");
			printf("|      source IP = %s\n",inet_ntop(AF_INET,&(ip_h->sip),ip_buf,sizeof(ip_buf)));
			printf("| destination IP = %s\n",inet_ntop(AF_INET,&(ip_h->dip),ip_buf,sizeof(ip_buf)));
			printf("------------------------------------------------------\n");


			//ipv4 header length is variable => ip_h header length....*4
			if(ip_h->protocol == IPPROTO_TCP) {
				ip_hdr_len = ((ip_h->ver_hdlen) & 0x0F) << 2;				//20~
				tcp_hdr *tcp_h = (tcp_hdr *)((uint8_t *)ip_h +  ip_hdr_len );

				printf("---------------------------TCP------------------------\n");
				printf("|      source port = %d\n",(ntohs)(tcp_h->sport));
				printf("| destination port = %d\n",(ntohs)(tcp_h->dport));
				printf("------------------------------------------------------\n");
				
				tcp_hdr_len = ((tcp_h->hdr_len) >> 4) << 2;					//20~60
				uint8_t *data = (uint8_t *)((uint8_t *)tcp_h + tcp_hdr_len);
				uint16_t data_len = ntohs(ip_h->tpl) - ip_hdr_len - tcp_hdr_len;

				if(data_len > 0) {
					uint16_t print_data_len = 0;
					printf("| DATA = ");
					if(data_len < MAX_DATA_LEN)
						print_data_len = data_len;
					print_data_len = MAX_DATA_LEN;
					for(int i = 0; (i < print_data_len) ; i++)
						printf("%.2X ", data[i]);
					printf(" |\n");
				}
			}
		}
		printf("\n");
	}

	pcap_close(handle);
	return 0;
}