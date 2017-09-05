#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <signal.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "checksum.h"

struct nfq_handle *h;
struct nfq_q_handle *qh;
unsigned char key;
uint16_t queue_id = 1;
int csum_flag = 1;

void transform(char *buffer, uint32_t len, unsigned char key) {
    unsigned j;
    for ( j = 0;j < len; j++ ) {
        buffer[j] ^= key;
    }
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *data) {
    uint32_t id = 0;
    uint32_t size = 0;
    struct nfqnl_msg_packet_hdr *ph = NULL;
    unsigned char *full_packet = NULL;
    struct iphdr *iph = NULL;
    uint32_t modified = 0;

    ph = nfq_get_msg_packet_hdr(nfa);
    if ( ph == NULL ) {
        fprintf(stderr, "nfq_get_msg_packet_hdr failed.\n");
        return -1;
    }
    id = ntohl(ph->packet_id);
    size = nfq_get_payload(nfa, &full_packet);
    iph = (struct iphdr *)full_packet;
    uint32_t tot_len = ntohs(iph->tot_len);
    uint32_t iph_len = (iph->ihl << 2);
    if ( iph->protocol == IPPROTO_TCP ) {
        struct tcphdr *tcph = (struct tcphdr *)((char *)iph + iph_len);
        uint32_t tcph_len = (tcph->doff << 2);
        char *payload = (char *)tcph + tcph_len;
        uint32_t payload_len = tot_len - iph_len - tcph_len;
        transform(payload, payload_len, key);
        if ( csum_flag ) {
            tcph->check = 0;
            tcph->check = ipv4_udptcp_cksum(iph, tcph);
        }
        modified = 1;
    }
    else if ( iph->protocol == IPPROTO_UDP ) {
        struct udphdr *udph = (struct udphdr *)((char *)iph + iph_len);
        char *payload = (char *)udph + sizeof(struct udphdr);
        uint32_t payload_len = tot_len - iph_len - sizeof(struct udphdr);
        transform(payload, payload_len, key);
        if ( csum_flag ) {
            udph->check = 0;
            udph->check = ipv4_udptcp_cksum(iph, udph);
        }
        modified = 1;
    }
    if ( modified ) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, size, full_packet);
    }
    else {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
}

void graceful_exit(int number) {
    fprintf(stderr, "Signal caught, destroying queue ...\n");
    nfq_destroy_queue(qh);
    fprintf(stderr, "Closing handle\n");
    nfq_close(h);
    exit(0);
}

void display_usage(const char *name) {
    fprintf(stderr, "Usage: %s -k keybyte -q id [--nocsum]\n", name);
}

void parse_args(int argc, char **argv) {
    static struct option long_options[] = {
        {"nocsum", no_argument, &csum_flag, 0},
        {"key",  required_argument, 0, 'k'},
        {"queueid",    required_argument, 0, 'q'},
        {"help",    no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    int option_index = 0;
    int c;

    if ( argc == 1 ) {
        display_usage(argv[0]);
        exit(1);
    }
    while ( (c = getopt_long(argc, argv, "hk:q:", long_options, &option_index)) != -1 ) {
        switch (c) {
            case 'k':
                key = (unsigned char)strtoul(optarg, NULL, 16);
                break;
            case 'q':
                queue_id = (uint16_t)atoi(optarg);
                break;
            case 'h':
                display_usage(argv[0]);
                exit(0);
            case '?':
                display_usage(argv[0]);
                exit(1);
        }
    }
}

int main(int argc, char **argv) {
    int fd;
    int rv;
    char buf[64*1024];

    parse_args(argc, argv);
    fprintf(stderr, "queue_id=%d, keybyte=0x%x\n", queue_id, key);

    signal(SIGINT, graceful_exit);
    signal(SIGTERM, graceful_exit);

    assert((h = nfq_open()) != NULL);
    assert(nfq_unbind_pf(h, AF_INET) == 0);
    assert(nfq_bind_pf(h, AF_INET) == 0);
    assert((qh = nfq_create_queue(h, queue_id, &cb, NULL)) != NULL);
    assert(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) == 0);
    fd = nfq_fd(h);

    int opt = 1;
    assert(setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int)) == 0);

    fprintf(stderr, "init finished, wait for processing\n");
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }
    // never reach
    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
