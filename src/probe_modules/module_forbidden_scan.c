// probe module for performing TCP forbidden payload scans

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"
#include "module_tcp_synscan.h"

#ifndef HOST
#define HOST "example.com"
#endif
//#define TCP_FLAGS TH_PUSH | TH_ACK
#define TCP_FLAGS TH_PUSH | TH_ACK
// #define PAYLOAD "GET / HTTP/1.1\r\nHost: " HOST "\r\n\r\n"
// #define PAYLOAD_LEN strlen(PAYLOAD) 
#define TOTAL_LEN sizeof(struct ip) + sizeof(struct tcphdr)
//#define TOTAL_LEN_PAYLOAD sizeof(struct ip) + sizeof(struct tcphdr) + PAYLOAD_LEN
#define ETHER_LEN sizeof(struct ether_header)
#define IP_LEN sizeof(struct ip)

probe_module_t module_tcp_forbiddenscan;
static uint32_t num_ports;

static unsigned int tlsPayloadLength;
static unsigned char *tlsPayload;
static unsigned int totalPayloadLength;

static void initialize_https_payload(){
	unsigned char tlsHeader[] = {0x16, 0x03, 0x01};
	unsigned char tlsLength[2];
	unsigned char clientHello[] = {0x01};
	unsigned char clientHelloLength[3];
	unsigned char everythingBeforeSNI[] = {
        0x03, 0x03, 0x0a, 0x2e, 0x88, 0xd5, 0x0c, 0xd0, 0x09, 0xc0, 0x68, 0xbc, 0x65, 0x70, 0x01, 0x43,
        0x58, 0xb0, 0xaf, 0x11, 0x00, 0x7f, 0xf5, 0x16, 0x61, 0x26, 0x19, 0x6b, 0xd1, 0x3d, 0xfb, 0xa8,
        0x31, 0xe5, 0x20, 0xf0, 0xef, 0xa6, 0xc0, 0x36, 0x71, 0xe0, 0x11, 0x21, 0x66, 0x0e, 0xdb, 0x3b,
        0x92, 0x1c, 0x19, 0xa7, 0x97, 0x85, 0x08, 0xe1, 0x45, 0xde, 0x09, 0xa3, 0x10, 0x27, 0x9e, 0xcd,
        0xc3, 0x53, 0x7c, 0x00, 0x3e, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c, 0xc0, 0x30, 0x00,
        0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0,
        0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0,
        0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00,
        0x2f, 0x00, 0xff, 0x01, 0x00, 0x00, 0xa9
    };
	unsigned char extensionType[] = {0x00, 0x00};
	unsigned char serverNameExtensionLength[2];
	unsigned char serverNameListLength[2];
	unsigned char serverNameType[] = {0x00};
	unsigned char serverNameLength[2];
	unsigned char *serverName = (unsigned char *) HOST;
	unsigned char everythingAfterSNI[] = {
		0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d,
		0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x00, 0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00,
        0x00, 0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x30, 0x00, 0x2e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 
		0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 
		0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x03, 0x03, 0x02, 0x03, 0x03, 0x01, 0x02, 0x01, 0x03, 0x02, 
		0x02, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x00, 0x2b, 0x00, 0x09, 0x08, 0x03, 0x04, 0x03, 
		0x03, 0x03, 0x02, 0x03, 0x01, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 
		0x24, 0x00, 0x1d, 0x00, 0x20, 0x05, 0xc2, 0x14, 0x4a, 0x82, 0xa7, 0xfd, 0xad, 0x65, 0x41, 0x18, 
		0x39, 0x0c, 0xbb, 0x1d, 0xf9, 0x66, 0x00, 0xcb, 0x87, 0x1f, 0xf6, 0x23, 0x72, 0x94, 0xa8, 0x1d, 
		0x4a, 0x34, 0x7c, 0x39, 0x65
	};
	unsigned int hostNameLength = strlen(HOST);
    unsigned int payloadLength = 292 + hostNameLength + 5;
    unsigned int clientHelloLengthValue = 288 + hostNameLength + 5;
	tlsLength[0] = (payloadLength >> 8) & 0xFF;
    tlsLength[1] = payloadLength & 0xFF;
    clientHelloLength[0] = (clientHelloLengthValue >> 16) & 0xFF;
    clientHelloLength[1] = (clientHelloLengthValue >> 8) & 0xFF;
    clientHelloLength[2] = clientHelloLengthValue & 0xFF;
    
    serverNameExtensionLength[0] = (hostNameLength + 5) >> 8 & 0xFF;
    serverNameExtensionLength[1] = (hostNameLength + 5) & 0xFF;
    serverNameListLength[0] = (hostNameLength + 3) >> 8 & 0xFF;
    serverNameListLength[1] = (hostNameLength + 3) & 0xFF;
    serverNameLength[0] = hostNameLength >> 8 & 0xFF;
    serverNameLength[1] = hostNameLength & 0xFF;

	unsigned char* sni = (unsigned char *) malloc(9 + hostNameLength);
    memcpy(sni, extensionType, 2);
    memcpy(sni + 2, serverNameExtensionLength, 2);
    memcpy(sni + 4, serverNameListLength, 2);
    memcpy(sni + 6, serverNameType, 1);
    memcpy(sni + 7, serverNameLength, 2);
    memcpy(sni + 9, serverName, hostNameLength);
    
    int sniLength = 9 + hostNameLength;
    tlsPayloadLength = sizeof(tlsHeader) + sizeof(tlsLength) + sizeof(clientHello) +
        sizeof(clientHelloLength) + sizeof(everythingBeforeSNI) + sniLength + sizeof(everythingAfterSNI);

	tlsPayload = (unsigned char *) malloc(tlsPayloadLength);
    memcpy(tlsPayload, tlsHeader, sizeof(tlsHeader));
    memcpy(tlsPayload + sizeof(tlsHeader), tlsLength, sizeof(tlsLength));
    memcpy(tlsPayload + sizeof(tlsHeader) + sizeof(tlsLength), clientHello, sizeof(clientHello));
    memcpy(tlsPayload + sizeof(tlsHeader) + sizeof(tlsLength) + sizeof(clientHello),
           clientHelloLength, sizeof(clientHelloLength));
    memcpy(tlsPayload + sizeof(tlsHeader) + sizeof(tlsLength) + sizeof(clientHello) +
           sizeof(clientHelloLength), everythingBeforeSNI, sizeof(everythingBeforeSNI));
    memcpy(tlsPayload + sizeof(tlsHeader) + sizeof(tlsLength) + sizeof(clientHello) +
           sizeof(clientHelloLength) + sizeof(everythingBeforeSNI), sni, sniLength);
    memcpy(tlsPayload + sizeof(tlsHeader) + sizeof(tlsLength) + sizeof(clientHello) +
           sizeof(clientHelloLength) + sizeof(everythingBeforeSNI) + sniLength,
           everythingAfterSNI, sizeof(everythingAfterSNI));

	
	totalPayloadLength = sizeof(struct ip) + sizeof(struct tcphdr) + tlsPayloadLength;

	// free(sni);
    // free(tls_payload);
}

static int forbiddenscan_global_initialize(struct state_conf *state)
{
	initialize_https_payload();
    printf("Starting module. Packet out size: %d\n", totalPayloadLength + TOTAL_LEN);
	num_ports = state->source_port_last - state->source_port_first + 1;
	return EXIT_SUCCESS;
}

static int forbiddenscan_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
        port_h_t dst_port,
        __attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
	make_ip_header(ip_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);

	make_tcp_header(tcp_header, dst_port, TH_SYN);
	return EXIT_SUCCESS;
}

static int forbiddenscan_init_perthread2(void *buf, macaddr_t *src, macaddr_t *gw,
				     port_h_t dst_port,
				     __attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + tlsPayloadLength);
	make_ip_header(ip_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);

	make_tcp_header(tcp_header, dst_port, TCP_FLAGS);
	char *payload = (char *)(&tcp_header[1]);
	memcpy(payload, tlsPayload, tlsPayloadLength);
	return EXIT_SUCCESS;
}

static int forbiddenscan_make_packet(void *buf, UNUSED size_t *buf_len,
        ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint8_t ttl,
        uint32_t *validation, int probe_num,
        UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
    // Subtract one for the SYN packet
	uint32_t tcp_seq = ntohl(htonl(validation[0]) - 1);
	uint32_t tcp_ack = 0;
	    //validation[2]; // get_src_port() below uses validation 1 internally.

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = ttl;

	tcp_header->th_sport =
	    htons(get_src_port(num_ports, probe_num, validation));
	tcp_header->th_seq = tcp_seq;
	tcp_header->th_ack = tcp_ack;
	tcp_header->th_sum = 0;
	tcp_header->th_sum =
	    tcp_checksum(sizeof(struct tcphdr), ip_header->ip_src.s_addr,
			 ip_header->ip_dst.s_addr, tcp_header);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	return EXIT_SUCCESS;
}
static int forbiddenscan_make_packet2(void *buf, UNUSED size_t *buf_len,
				  ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint8_t ttl,
				  uint32_t *validation, int probe_num,
				  UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
	uint32_t tcp_seq = validation[0];
	uint32_t tcp_ack =
	    validation[2]; // get_src_port() below uses validation 1 internally.

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = ttl;

	tcp_header->th_sport =
	    htons(get_src_port(num_ports, probe_num, validation));
	tcp_header->th_seq = tcp_seq;
	tcp_header->th_ack = tcp_ack;
	tcp_header->th_sum = 0;
	tcp_header->th_sum =
	    tcp_checksum(sizeof(struct tcphdr) + tlsPayloadLength, ip_header->ip_src.s_addr,
			 ip_header->ip_dst.s_addr, tcp_header);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	return EXIT_SUCCESS;
}

static int forbiddenscan_validate_packet(const struct ip *ip_hdr, uint32_t len,
        __attribute__((unused)) uint32_t *src_ip,
        uint32_t *validation)
{
	if (ip_hdr->ip_p != IPPROTO_TCP) {
		return 0;
	}
	if ((4 * ip_hdr->ip_hl + sizeof(struct tcphdr)) + 1 > len) {
		// buffer not large enough to contain expected tcp header 
		return 0;
	}

	struct tcphdr *tcp = (struct tcphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
	uint16_t sport = tcp->th_sport;
	uint16_t dport = tcp->th_dport;

    // validate source port
	if (ntohs(sport) != zconf.target_port) {
		return 0;
	}

	// validate destination port
	if (!check_dst_port(ntohs(dport), num_ports, validation)) {
		return 0;
	}
    
    if ((htonl(tcp->th_ack) != htonl(validation[0]) + tlsPayloadLength) &&  
        (htonl(tcp->th_ack) != htonl(validation[0])) &&
        (htonl(tcp->th_seq) != htonl(validation[2]))) {
        return 0;
    }

	return 1;
}

static void forbiddenscan_process_packet(const u_char *packet,
        uint32_t len,
        fieldset_t *fs,
        __attribute__((unused))
        uint32_t *validation)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	struct tcphdr *tcp =
	    (struct tcphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
	char *payload = (char *)(&tcp[1]);
    int mylen = ntohs(ip_hdr->ip_len);
    int payloadlen = mylen - IP_LEN - (tcp->th_off * 4);
    mylen += ETHER_LEN;


	fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp->th_sport));
	fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp->th_dport));
	fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp->th_seq));
	fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp->th_ack));
	fs_add_uint64(fs, "window", (uint64_t)ntohs(tcp->th_win));
    fs_add_uint64(fs, "payloadlen", (uint64_t)payloadlen);
	fs_add_uint64(fs, "len", (uint64_t)mylen);
	fs_add_uint64(fs, "flags", (uint64_t)tcp->th_flags);
	fs_add_uint64(fs, "ipid", (uint64_t)ntohs(ip_hdr->ip_id));
    // Attempt to track why an IP responded - did it acknolwedge our payload or not? 
    // If it acknowledges our payload, than it is probably responding to our payload
    // otherwise, it may just be sending us SYN/ACKs or responses
    if (htonl(tcp->th_ack) == htonl(validation[0]) + tlsPayloadLength) {
	    fs_add_uint64(fs, "validation_type", 0);
    } else if ((htonl(tcp->th_ack) == htonl(validation[0])) ||
               (htonl(tcp->th_seq) == htonl(validation[2]))) {
	    fs_add_uint64(fs, "validation_type", 1);
    } else {
	    fs_add_uint64(fs, "validation_type", 2);
    }

	fs_add_string(fs, "classification", "", 0);
	//fs_add_string(fs, "classification", (char *)payload, 0);
	fs_add_bool(fs, "success", 1);
}

static fielddef_t myfields[] = {
    {.name = "sport", .type = "int", .desc = "TCP source port"},
    {.name = "dport", .type = "int", .desc = "TCP destination port"},
    {.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
    {.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
    {.name = "window", .type = "int", .desc = "TCP window"},
    {.name = "payloadlen", .type = "int", .desc = "Payload Length"},
    {.name = "len", .type = "int", .desc = "Packet size"},
    {.name = "flags", .type = "int", .desc = "Packet flags"},
    {.name = "ipid", .type = "int", .desc = "IP Identification"},
    {.name = "validation_type", .type = "int", .desc = "Type of Validation"},
    {.name = "classification",
        .type = "string",
        .desc = "packet classification"},
    {.name = "success",
        .type = "bool",
        .desc = "is response considered success"}};

probe_module_t module_forbidden_scan = {
    .name = "forbidden_scan",
    .packet_length = TOTAL_LEN + ETHER_LEN,
    .packet2_length = TOTAL_LEN + 302 + strlen(HOST) + ETHER_LEN,
    .pcap_filter = "tcp", 
    .pcap_snaplen = 96,
    .port_args = 1,
    .global_initialize = &forbiddenscan_global_initialize,
    .thread_initialize = &forbiddenscan_init_perthread,
    .thread_initialize2 = &forbiddenscan_init_perthread2,
    .make_packet = &forbiddenscan_make_packet,
    .make_packet2 = &forbiddenscan_make_packet2,
    .print_packet = &synscan_print_packet,
    .process_packet = &forbiddenscan_process_packet,
    .validate_packet = &forbiddenscan_validate_packet,
    .close = NULL,
    .helptext = "Probe module that sends a TCP PSH/ACK packet to a specific "
        "port. Possible classifications are: synack and rst. A "
        "RST packet is considered a failure and a packet with data"
        "is considered a success.",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = myfields,
    .numfields = 12};
