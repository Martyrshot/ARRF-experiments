#include <resource_record.h>
#include <dns_message.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <arpa/inet.h>

char *port = "53";


int
get_socket(void) {
	struct addrinfo hints, *res;
	int fd;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	getaddrinfo(NULL, port, &hints, &res);

	fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd < 0) {
		printf("Getting fd failed.\n");
		perror("Socket fd:");
		close(fd);
		return -1;
	}
	if (bind(fd, res->ai_addr, res->ai_addrlen) == -1) {
		printf("bind failed.\n");
		perror("Bind fd:");
		close(fd);
		return -1;
	}
	return fd;
}
int
main(int argc, char **argv) {
	// Wait for request.
	int fd = get_socket();
	if (fd < 0) {
		printf("Failed to get a socket\n");
		return -1;
	}
	unsigned char msg_bytes[10000];
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);
	memset(&from, 0, sizeof(from));
	printf("Waiting for a message\n");
	size_t recvd_bytes = recvfrom(fd, msg_bytes, 10000, 0, (struct sockaddr *)&from, &from_len);
	if (recvd_bytes <= 0) {
		printf("Recvd_bytes: %lu\n", recvd_bytes);
		close(fd);
		return -1;
	}
	printf("Recvd_bytes: %lu\n", recvd_bytes);
	// TODO Sanity check max udp size is huge.
	
	// Otherwise, we don't really care about the query for
	// this test.
	

	// Response with large RR
	ResourceRecord *rr;
	size_t rdlen = 2048;
	unsigned char rdata[rdlen];
	for (int i = 0; i < rdlen; i++) {
		rdata[i] = i;
	}
	create_rr(&rr, "www.google.com.", 2, 1, 1234, rdlen, rdata);
	unsigned char *b;
	size_t bl;
	rr_to_bytes(rr, &b, &bl);
	PackedRR **answers = malloc(sizeof(PackedRR *) * 1);
	create_packedrr(rr, answers);
	DNSMessage *respmsg;
	create_dnsmessage(&respmsg, 4321, 1 << 15, 0, 1, 0, 0, NULL, answers, NULL, NULL);
	unsigned char *resp_bytes;
	size_t resp_byte_len;
	if(dnsmessage_to_bytes(respmsg, &resp_bytes, &resp_byte_len) != 0) {
		printf("Failed to make bytes\n");
		close(fd);
		return -1;
	}
	printf("Sent bytes: %lu\n", resp_byte_len);
	// Send
	struct sockaddr_in *sin = (struct sockaddr_in *)&from;
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(sin->sin_addr), ip, INET_ADDRSTRLEN);
	printf("sending to ip: %s\n", ip);
	fflush(stdout);
	printf("Sending...");
	if (sendto(fd, resp_bytes, resp_byte_len, 0, (struct sockaddr *)&from, from_len) <= 0) {
		printf("from_len: %d\n", from_len);
		printf("resp_byte_len: %lu\n", resp_byte_len);
		perror("Send: ");
		close(fd);
		return -1;
	}
	printf("Done\n");
	while(true);
	return 0;
}
