#include <linux/module.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/nfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

uint32_t our_addr;


uint32_t
process_packet(struct nfq_data *data, uint32_t **verdict) {
	// For the sake of testing getting this to work in docker containers
	// this is just going to print packet header info if it's a packet
	// addressed to this machine

	size_t payloadLen = 0;
	unsigned char *payload = NULL;
	struct iphdr *ipv4hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	struct icmphdr *icmphdr;
	uint32_t id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;

	payloadLen = nfq_get_payload(data, &payload);
	ipv4hdr = (struct iphdr *)payload;
	ph = nfq_get_msg_packet_hdr(data);
	id = ntohl(ph->packet_id);

	src_ip = ipv4hdr->saddr;
	dst_ip = ipv4hdr->daddr;
	printf("oa: %u, dst: %u\n", our_addr, dst_ip);
	char buff[500];
	nfq_ip_snprintf(buff, 500, ipv4hdr);
	if (dst_ip == our_addr) {
		printf("here\n");
		if (ipv4hdr->protocol == IPPROTO_TCP) {
			tcphdr = (struct tcphdr *)((char *)payload + sizeof(*ipv4hdr));
			src_port = ntohs(tcphdr->source);
			dst_port = ntohs(tcphdr->dest);
			printf("<src: %u:%hu, dest: %u:%hu, total size: %lu>\n", src_ip, src_port, dst_ip, dst_port, payloadLen);
		} else if (ipv4hdr->protocol == IPPROTO_UDP) {
			udphdr = (struct udphdr *)((char *)payload + sizeof(*ipv4hdr));
			src_port = ntohs(udphdr->source);
			dst_port = ntohs(udphdr->dest);
			printf("<src: %u:%hu, dest: %u:%hu, total size: %lu>\n", src_ip, src_port, dst_ip, dst_port, payloadLen);
		} else if (ipv4hdr->protocol == IPPROTO_ICMP) {
			printf("ICMP\n");
			icmphdr = (struct icmphdr *)((char *)payload + sizeof(*ipv4hdr));
			printf("<type: %hhu, code: %hhu>\n", icmphdr->type, icmphdr->code);
		}
	}
	**verdict = NF_ACCEPT;
	return id;

}

static int 
cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	printf("cb called\n");
	uint32_t verdict;
	uint32_t *verdict_p = &verdict;
	uint32_t id = process_packet(nfa, &verdict_p);
	verdict = *verdict_p;
	return nfq_set_verdict(qh, id, verdict, 0, NULL);
}


int
main(int argc, char **argv) {
	char *dev_name = "enp0s5";
	char buf[0xffff];
	int fd;
	/* get this machine's ip address from ioctl */
	struct ifaddrs *addrs;
	struct ifaddrs *cur_addr;
	getifaddrs(&addrs);
	cur_addr = addrs;
	while(cur_addr) {
		if ((cur_addr->ifa_addr && cur_addr->ifa_addr->sa_family == AF_INET)
		   	&& strncmp(dev_name, cur_addr->ifa_name, 15) == 0)	{
			our_addr = (uint32_t)((struct sockaddr_in *)cur_addr->ifa_addr)->sin_addr.s_addr;
			break;
		} else if (cur_addr->ifa_next == NULL) {
			printf("Couldn't find a device with the name: %s\n", dev_name);
			return -1;
		}
		cur_addr = cur_addr->ifa_next;
	}
	/* Create and initialize handle for netfilter_queue */
	struct nfq_handle *h = nfq_open();
	if (!h) {
		printf("Failed getting h\n");
		return -1;
	}
	if (nfq_bind_pf(h, AF_INET) < 0) {
		printf("Failed to bind\n");
		return -1;
	}
	struct nfq_q_handle *qh;
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh) {
		printf("Failed to make queue\n");
		return -1;
	}
	if ((nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xfff)) == -1) {
		printf("Failed to tune queue\n");
		return -1;
	}
	fd = nfq_fd(h);
	for(;;) {
		int rv;

		printf("pre recv\n");
		rv = recv(fd, buf, sizeof(buf), 0);
		printf("recv\n");
		if (rv < 0) {
			printf("failed to receive a thing\n");
			return -1;
		}
		nfq_handle_packet(h, buf, rv);
	}
	
	return 0;
}
