
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

/*always 14 bytes*/
typedef struct _ether_hdr
{
	uint8_t dmac[MAC_ADDR_LEN];
	uint8_t smac[MAC_ADDR_LEN];
	uint16_t type;
} ether_hdr;

typedef struct _ip_hdr
{
	uint8_t ver_hdrlen;		//upper 4bit : version & lower 4bit : header length
	uint8_t tos;			//type of service
	uint16_t tpl;			//total packet length
	uint16_t id;
	uint16_t flag_offset;
	uint8_t ttl;
	uint8_t protocol;		//
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
			 mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
}

int main(int argc, char *argv[]) {

	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	char ip_buf[16] = {0};

	uint16_t ip_hdr_len = 0;
	uint16_t tcp_hdr_len = 0;

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while (1) 
	{
		//여기서는 pcap_pkthdr *header가 필요 없을거라 생각했는데, 없으면 segmentation fault가 뜨더라
		//
		struct pcap_pkthdr* header = NULL;
		const u_char* packet = NULL;
		/*
		pcap_next		=>	return a u_char pointer to the data in that packet
		pcap_next_ex	=>	return a intager (  1 = no error
											    0 = timeout
											   -1 = error
											   -2 = EOF     )
		*/
//		int res = pcap_next_ex(handle, &header, &packet);
		int res = pcap_next_ex(handle, (void *)NULL , &packet);
		if (res == 0) 					//none be captured ( timeout )
			continue;
		if (res == -1 || res == -2)		//pcap_next_ex error
		 	break;

		ether_hdr *eth_h = (ether_hdr *)packet;
		
		printf("--------------------ETHERNET HEADER-------------------\n");
		printf("| destination MAC = ");
		print_mac(eth_h->dmac);
		printf("|      source MAC = ");
		print_mac(eth_h->smac);
		printf("------------------------------------------------------\n");

		//ip start
		if(ntohs(eth_h->type) == ETHERTYPE_IP) 
		{	
			ip_hdr *ip_h = (ip_hdr *)((uint8_t *)packet + sizeof(ether_hdr));	//because ehternet header size is always 14 

			printf("--------------------------IPv4------------------------\n");
			printf("|      source IP = %s\n",inet_ntop(AF_INET,&(ip_h->sip),ip_buf,sizeof(ip_buf)));
			printf("| destination IP = %s\n",inet_ntop(AF_INET,&(ip_h->dip),ip_buf,sizeof(ip_buf)));
			printf("------------------------------------------------------\n");


			//tcp start
			if(ip_h->protocol == IPPROTO_TCP) 
			{
				//ipv4 header length is variable => ( ip_h header length....*4 )
				ip_hdr_len = ((ip_h->ver_hdrlen) & 0x0F) << 2;				//range : 20~60(4*(2^4-1)) 4bit 니까!
				tcp_hdr *tcp_h = (tcp_hdr *)((uint8_t *)ip_h +  ip_hdr_len );

				printf("---------------------------TCP------------------------\n");
				printf("|      source port = %d\n",ntohs(tcp_h->sport));
				printf("| destination port = %d\n",ntohs(tcp_h->dport));
				printf("------------------------------------------------------\n");
				
				tcp_hdr_len = ((tcp_h->hdr_len) >> 4) << 2;					//range : 20~60(4*(2^4-1))
				uint8_t *data = (uint8_t *)((uint8_t *)tcp_h + tcp_hdr_len);
				uint16_t data_len = ntohs(ip_h->tpl) - ip_hdr_len - tcp_hdr_len;

				if(data_len > 0)
				{
					uint16_t print_data_len = 0;
					printf("| DATA = ");
					if(data_len < MAX_DATA_LEN)
						print_data_len = data_len;
					else 
						print_data_len = MAX_DATA_LEN;
					for(int i = 0; i < print_data_len ; i++)
						printf("%.2X ", data[i]);
					printf(" |\n");
				}
			}
			//tcp end
		}
		//ip end
		printf("\n");
	}
	//while end

	pcap_close(handle);
	return 0;
}

