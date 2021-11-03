//
//  ssdp.c
//  功能：送出SSDP Discover封包並等待回覆。
//  Created by 聲華 陳 on 2016/03/06.
//

#define __FAVOR_BSD
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <libnet.h>

void usage(const char *cmd);
u_int32_t ip_aton(const char *ip_address);
char *ip_ntoa(u_int32_t i);
int datalink_length(int dlt);
pcap_t *open_pcap_handle(char *device, int timeout, char *filter_expression);
libnet_t *open_libnet_handle(char *device);

int main(int argc, const char * argv[]) 
{

	int c;
	char *device = NULL;
	pcap_t *pcap_handle = NULL;
	libnet_t *libnet_handle = NULL;
	int timeout = 200; //0.2s
	libnet_ptag_t tag;
	u_int32_t src_ip = 0;
	u_int32_t dst_ip = ip_aton("239.255.255.250");
	u_int16_t sport;
	int send_length = 0, recv_length = 0;
	struct pcap_pkthdr *header = NULL;
	const u_char *content = NULL;
	int dlt;
	int dlt_length;
	char ssdp[] =
	"M-SEARCH * HTTP/1.1\r\n"
	"HOST: 239.255.255.250:1900\r\n"
	"MAN: \"ssdp:discover\"\r\n"
	"MX: 2\r\n"
	"ST: ssdp:all\r\n"
	"\r\n";
	int ssdp_length = strlen(ssdp);

	//parse argument
	opterr = 0; //don't show default error message
	while((c = getopt(argc, (char * const *)argv, "i:s:d:t:")) != EOF) {
		switch (c) {
			case 'i':
				device = optarg;
				break;

			case 's':
				src_ip = ip_aton(optarg);
				break;

			case 'd':
				dst_ip = ip_aton(optarg);
				break;

			case 't':
				timeout = atoi(optarg);
				if(timeout == 0) {
					fprintf(stderr, "Invalid timeout value: %s\n", optarg);
					exit(1);
				}//end if
				break;

			case '?':
			case 'h':
			default:
				usage(argv[0]);
				break;
		}//end switch
	}//end while

	if(!device) {
		usage(argv[0]);
	}//end if


	//init pcap
	pcap_handle = open_pcap_handle(device, timeout, "udp src port 1900");
	if(!pcap_handle) {
		goto BYE;
	}//end if

	//get data-link length
	dlt = pcap_datalink(pcap_handle);
	dlt_length = datalink_length(dlt);
	if(dlt_length == -1) {
		fprintf(stderr, "No support datalink type: %s(%s)\n",
				pcap_datalink_val_to_name(dlt), pcap_datalink_val_to_description(dlt));
		goto BYE;
	}//end if

	//init libnet
	libnet_handle = open_libnet_handle(device);
	if(!libnet_handle) {
		goto BYE;
	}//end if

	//if source ip address is 0, assign current ip address
	if(src_ip == 0) {
		src_ip = libnet_get_ipaddr4(libnet_handle);
		if(src_ip == -1) {
			fprintf(stderr, "libnet_get_ipaddr4: %s\n", libnet_geterror(libnet_handle));
			goto BYE;
		}//end if fail
	}//end if

	//init seed
	libnet_seed_prand(libnet_handle);
	sport = libnet_get_prand(LIBNET_PRu16) % (65535-49152+1)+(49152);

	//build udp with ssdp
	tag = libnet_build_udp(sport,
						   //source port
						   1900,
						   //destination port
						   LIBNET_UDP_H + ssdp_length,
						   //length
						   0,
						   //checksum
						   (u_char *)ssdp,
						   ssdp_length,
						   libnet_handle,
						   LIBNET_PTAG_INITIALIZER);

	if(tag == -1) {
		fprintf(stderr, "libnet_build_udp: %s\n", libnet_geterror(libnet_handle));
		goto BYE;
	}//end if

	//build ip
	tag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + ssdp_length,
							//total length, 28 + payload length
							0,
							//type of service
							libnet_get_prand(LIBNET_PRu16),
							//id, rand
							0,
							//fragment offset
							64,
							//time to live
							IPPROTO_UDP,
							//procotol, 17
							0,
							//checksum, auto calculate
							src_ip,
							//source ip address
							dst_ip,
							//destination ip address
							NULL,
							0,
							libnet_handle,
							LIBNET_PTAG_INITIALIZER);

	if(tag == -1) {
		fprintf(stderr, "libnet_autobuild_ipv4: %s\n", libnet_geterror(libnet_handle));
		goto BYE;
	}//end if

	//send ssdp
	send_length = libnet_write(libnet_handle);
	if(send_length == -1) {
		fprintf(stderr, "libnet_write: %s\n", libnet_geterror(libnet_handle));
		goto BYE;
	}//end if


	//now listen response
	while(pcap_next_ex(pcap_handle, &header, &content) == 1) {
		struct ip *ip = (struct ip *)(content + dlt_length);
		char *src_ip = ip_ntoa(ip->ip_src.s_addr);
		struct udphdr *udp = (struct udphdr *)(content + dlt_length + (ip->ip_hl << 2));
		int ssdp_length = ntohs(udp->uh_ulen) - LIBNET_UDP_H;
		//int ssdp_length = header->caplen - dlt_length - (ip->ip_hl << 2) - LIBNET_UDP_H;
		char *ssdp_data = (char *)(content + dlt_length + (ip->ip_hl << 2) + LIBNET_UDP_H);
		char buffer[65535] = {};

		//check if is not udp
		if(ip->ip_p != IPPROTO_UDP) {
			continue;
		}//end if

		//copy ssdp data
		memcpy(buffer, ssdp_data, ssdp_length);
		buffer[ssdp_length] = '\0';

		//print result
		printf("Source IP Address: %s\n", src_ip);
		printf("SSDP Response:\n%s", buffer);

		//add receive length
		recv_length += header->caplen - dlt_length;
	}//end while read packet


	//stats
	printf("\nSent: %d bytes, Received: %d bytes\n"
		   "Increased: %.2f times\n",
		   send_length, recv_length, recv_length/(float)send_length);


	//free
	if(pcap_handle) {
		pcap_close(pcap_handle);
	}//end if
	if(libnet_handle) {
		libnet_destroy(libnet_handle);
	}//end if

	return 0;

BYE:
	//free
	if(pcap_handle) {
		pcap_close(pcap_handle);
	}//end if
	if(libnet_handle) {
		libnet_destroy(libnet_handle);
	}//end if

	return 1;
}

void usage(const char *cmd) {
	printf("Usage: %s <-i Interface> [-s Source IP Address] [-d Destination IP Address] [-t Timeout ms]\n", cmd);
	exit(1);
}//end usage

u_int32_t ip_aton(const char *ip_address) {
	u_int32_t ip_integer;
	if(1 != inet_pton(AF_INET, ip_address, &ip_integer)) {
		fprintf(stderr, "Invalid IP address: %s\n", ip_address);
		exit(1);
	}//end if
	return ip_integer;
}//end if

char *ip_ntoa(u_int32_t i) {
#define FUNCTION_BUFFER 256
	static char str[FUNCTION_BUFFER][INET_ADDRSTRLEN];
	static int which = -1;

	which = (which + 1 == FUNCTION_BUFFER ? 0 : which + 1);

	memset(str[which], 0, sizeof(str[which]));

	inet_ntop(AF_INET, &i, str[which], sizeof(str[which]));

	return str[which];
}//end ip_ntoa

int datalink_length(int dlt) {
	switch (dlt) {
		case DLT_EN10MB: return 14;
#ifdef DLT_IPNET
		case DLT_IPNET: return 24;
#endif
#ifdef DLT_PPI
		case DLT_PPI: return 8;
#endif
#ifdef DLT_NULL
		case DLT_NULL: return 4;
#endif
#ifdef DLT_LOOP
		case DLT_LOOP: return 4;
#endif
#ifdef DLT_RAW
		case DLT_RAW: return 0;
#endif
#ifdef DLT_IPV4
		case DLT_IPV4: return 0;
#endif
#ifdef DLT_IPV6
		case DLT_IPV6: return 0;
#endif
#ifdef DLT_FDDI
		case DLT_FDDI: return 13;
#endif
		default: return -1;
	}//end switch
}//end datalink_length

pcap_t *open_pcap_handle(char *device, int timeout, char *filter_expression) {
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net, mask;
	struct bpf_program fcode;

	handle = pcap_open_live(device, 65535, 1, timeout, errbuf);
	if(!handle) {
		fprintf(stderr, "pcap_open_live: %s\n", errbuf);
		return NULL;
	}//end if

	if(-1 == pcap_lookupnet(device, &net, &mask, errbuf)) {
		fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
		pcap_close(handle);
		return NULL;
	}//end if

	if(-1 == pcap_compile(handle, &fcode, filter_expression, 1, mask)) {
		fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return NULL;
	}//end if

	//set filter
	if(-1 == pcap_setfilter(handle, &fcode)) {
		fprintf(stderr, "pcap_pcap_setfilter: %s\n", pcap_geterr(handle));
		pcap_freecode(&fcode);
		pcap_close(handle);
		return NULL;
	}//end if

	//free code
	pcap_freecode(&fcode);

	return handle;
}//end open_pcap_handle

libnet_t *open_libnet_handle(char *device) {
	libnet_t *handle = NULL;
	char errbuf[LIBNET_ERRBUF_SIZE];

	handle = libnet_init(LIBNET_RAW4, device, errbuf);
	if(!handle) {
		fprintf(stderr, "libnet_init: %s\n", errbuf);
		return NULL;
	}//end if

	return handle;
}//end open_libnet_handle
