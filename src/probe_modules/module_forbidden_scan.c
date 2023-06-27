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
#define TCP_FLAGS TH_PUSH | TH_ACK
//#define TCP_FLAGS TH_SYN
#define PAYLOAD "GET / HTTP/1.1\r\nHost: " HOST "\r\n\r\n"
#define PAYLOAD_LEN strlen(PAYLOAD) 

#define ETHER_LEN sizeof(struct ether_header)
#define IP_LEN sizeof(struct ip)
#define TOTAL_LEN sizeof(struct ip) + sizeof(struct tcphdr) + PAYLOAD_LEN

probe_module_t module_tcp_forbiddenscan;
static uint32_t num_ports;

static int forbiddenscan_global_initialize(struct state_conf *state)
{
    printf("Starting module. Packet out size: %d\n", TOTAL_LEN);
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
    uint16_t len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + PAYLOAD_LEN);
    make_ip_header(ip_header, IPPROTO_TCP, len);
    struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);

    make_tcp_header(tcp_header, dst_port, TCP_FLAGS);
    char *payload = (char *)(&tcp_header[1]);
    memcpy(payload, PAYLOAD, PAYLOAD_LEN);
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
    uint32_t tcp_seq = ntohl(htonl(validation[0]) - 1);
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
        tcp_checksum(sizeof(struct tcphdr) + PAYLOAD_LEN, ip_header->ip_src.s_addr,
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
    if ((4 * ip_hdr->ip_hl + sizeof(struct tcphdr)) > len) {
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

    if ((htonl(tcp->th_ack) != htonl(validation[0]) + PAYLOAD_LEN) &&  
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

    fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp->th_sport));
    fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp->th_dport));
    fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp->th_seq));
    fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp->th_ack));
    fs_add_uint64(fs, "window", (uint64_t)ntohs(tcp->th_win));
    fs_add_uint64(fs, "payloadlen", (uint64_t)payloadlen);
    fs_add_uint64(fs, "len", (uint64_t)mylen);
    fs_add_uint64(fs, "flags", (uint64_t)tcp->th_flags);
    fs_add_uint64(fs, "ipid", (uint64_t)ntohs(ip_hdr->ip_id));
    if (htonl(tcp->th_ack) == htonl(validation[0]) + PAYLOAD_LEN) {
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
    .pcap_filter = "tcp", 
    .pcap_snaplen = 96,
    .port_args = 1,
    .global_initialize = &forbiddenscan_global_initialize,
    .thread_initialize = &forbiddenscan_init_perthread,
    .make_packet = &forbiddenscan_make_packet,
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